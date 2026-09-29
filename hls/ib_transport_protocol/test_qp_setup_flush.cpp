/************************************************
Copyright (c) 2019, Systems Group, ETH Zurich.
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software
without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
************************************************/

// Unit test for a QP set up again (a full context write on s_axis_qp_interface) while its previous
// session left requests nobody will acknowledge. The new session must not be held behind them: the
// retransmitter must drop them, with no completion, and the transport timer must stop resending
// them. Drives the whole ib_transport_protocol; the test plays the remote node, reading the requests
// the stack sends and answering them with packets of its choosing, and the memory.
//
// Build and run from the repository root, with the Vitis HLS headers:
//   mkdir -p build && sed -e 's/${DATA_WIDTH}/64/' -e 's/${ROCE_STACK_MAX_QPS}/256/' \
//       -e 's/${PMTU_BYTES}/4096/' hls/rocev2/rocev2_config.hpp.in > build/rocev2_config.hpp
//   g++ -std=c++14 -I$XILINX_HLS/include -Ihls -Ihls/ib_transport_protocol -Ibuild \
//       hls/ib_transport_protocol/test_qp_setup_flush.cpp -o build/test_qp_setup_flush \
//       && build/test_qp_setup_flush

// The stack, and the opcode helpers it uses
#include "ib_transport_protocol.cpp"
#include "ib_utils.cpp"

#include <cstdio>
#include <vector>

namespace
{

const int W = 512;

stream<ipUdpMeta> rx_meta("rx_meta");
stream<net_axis<W> > rx_data("rx_data");
stream<ipUdpMeta> tx_meta("tx_meta");
stream<net_axis<W> > tx_data("tx_data");
stream<txMeta> sq("sq");
stream<ackMeta> completions("completions");
stream<memCmd> mem_wr_cmd("mem_wr_cmd");
stream<memCmd> mem_rd_cmd("mem_rd_cmd");
stream<net_axis<W> > mem_wr_data("mem_wr_data");
stream<net_axis<W> > mem_rd_data("mem_rd_data");
stream<qpContext> qp_ctx("qp_ctx");
stream<ifConnReq> qp_conn("qp_conn");
#ifdef DBG_IBV
// Never read: psnPkg has no default constructor
stream<psnPkg> dbg0("dbg0");
stream<psnPkg> dbg1("dbg1");
stream<psnPkg> dbg2("dbg2");
#endif
ap_uint<32> reg_drops, reg_retrans, reg_rx, reg_tx;

const ap_uint<128> PEER_IP = 0xfe8000000000000092e2baff0b01d4d3;

// What the stack sent, what it completed, and where it wrote READ data
struct Sent
{
    ibOpCode op;
    uint32_t qpn;
    uint32_t psn;
};
std::vector<Sent> sent;
std::vector<ackMeta> done;
std::vector<memCmd> written;

bool tx_in_packet = false;
int failures = 0;

void check(bool ok, const char* what)
{
    std::printf("%s %s\n", ok ? "ok:  " : "FAIL:", what);
    failures += ok ? 0 : 1;
}

// tkeep of a word holding `bytes` bytes
ap_uint<W / 8> keep_of(uint32_t bytes)
{
    ap_uint<W / 8> keep = 0;
    for (uint32_t i = 0; i < bytes; ++i)
        keep[i] = 1;
    return keep;
}

void step(int cycles)
{
    for (int i = 0; i < cycles; ++i)
    {
        ib_transport_protocol<W, 0>(rx_meta, rx_data, tx_meta, tx_data, sq, completions,
                                    mem_wr_cmd, mem_rd_cmd, mem_wr_data, mem_rd_data, qp_ctx, qp_conn,
#ifdef DBG_IBV
                                    dbg0, dbg1, dbg2,
#endif
                                    reg_drops, reg_retrans, reg_rx, reg_tx);

        // The remote node: note each packet's opcode and PSN from its BTH
        while (!tx_meta.empty())
            tx_meta.read();
        while (!tx_data.empty())
        {
            net_axis<W> word = tx_data.read();
            if (!tx_in_packet)
            {
                BaseTransportHeader<W> bth;
                bth.parseWord(word.data);
                sent.push_back(Sent{bth.getOpCode(), bth.getDstQP().to_uint(), bth.getPsn().to_uint()});
            }
            tx_in_packet = !word.last;
        }

        // The memory: payload for every read, and note where READ data is written
        while (!mem_rd_cmd.empty())
        {
            memCmd cmd = mem_rd_cmd.read();
            uint32_t len = cmd.len.to_uint();
            for (uint32_t offs = 0; offs < len; offs += W / 8)
            {
                net_axis<W> word;
                word.data = 0;
                const uint32_t bytes = len - offs < W / 8 ? len - offs : W / 8;
                word.keep = keep_of(bytes);
                word.last = offs + W / 8 >= len;
                mem_rd_data.write(word);
            }
        }
        while (!mem_wr_cmd.empty())
            written.push_back(mem_wr_cmd.read());
        while (!mem_wr_data.empty())
            mem_wr_data.read();
        while (!completions.empty())
            done.push_back(completions.read());
    }
}

// A packet from the remote node to local QP `qpn`: BTH, an AETH (syndrome ACK) for acknowledgements and
// READ responses, `payload` bytes, and the ICRC's 4 bytes
void receive(ibOpCode op, uint32_t qpn, uint32_t psn, uint32_t payload)
{
    BaseTransportHeader<W> bth;
    bth.setOpCode(op);
    bth.setPartitionKey(0xffff);
    bth.setDstQP(qpn);
    bth.setPsn(psn);
    AckExHeader<W> aeth;
    aeth.setSyndrome(0);
    aeth.setMsn(0);

    ap_uint<W> header = 0;
    bth.consumeWord(header);
    ap_uint<W> ack = 0;
    aeth.consumeWord(ack);
    header(BTH_SIZE + AETH_SIZE - 1, BTH_SIZE) = ack(AETH_SIZE - 1, 0);

    const uint32_t len = (BTH_SIZE + AETH_SIZE) / 8 + payload + 4;
    rx_meta.write(ipUdpMeta(PEER_IP, RDMA_DEFAULT_PORT, RDMA_DEFAULT_PORT, 8 + len));
    for (uint32_t offs = 0; offs < len; offs += W / 8)
    {
        net_axis<W> word;
        word.data = offs == 0 ? header : ap_uint<W>(0);
        const uint32_t bytes = len - offs < W / 8 ? len - offs : W / 8;
        word.keep = keep_of(bytes);
        word.last = offs + W / 8 >= len;
        rx_data.write(word);
    }
    step(600);
}

// Local address of a request whose completion is to go to stream `dest` of the vFPGA
ap_uint<64> laddr(uint64_t base, uint32_t dest)
{
    return (ap_uint<64>(dest) << 48) | base;
}

std::vector<ackMeta> completions_of(uint32_t qpn)
{
    std::vector<ackMeta> out;
    for (const ackMeta& c : done)
        if (c.qpn == qpn)
            out.push_back(c);
    return out;
}

// PSNs of the packets a local QP sent (their BTH carries the remote node's QP number)
std::vector<uint32_t> psns_sent(uint32_t qpn, ibOpCode op)
{
    std::vector<uint32_t> out;
    for (const Sent& s : sent)
        if (s.qpn == 0x10 + qpn && s.op == op)
            out.push_back(s.psn);
    return out;
}

// Sets up (or up again) local QP `qpn`, whose requests start at PSN `send_psn`: qpContext's
// remote_psn is the PSN the remote node expects next
void setup(uint32_t qpn, uint32_t send_psn)
{
    qp_ctx.write(qpContext(READY_SEND, qpn, send_psn, 0x100 * qpn, 0, 0));
    qp_conn.write(ifConnReq(qpn, 0x10 + qpn, PEER_IP, RDMA_DEFAULT_PORT));
    step(100);
}

void write(uint32_t qpn, uint64_t base)
{
    sq.write(txMeta(RC_RDMA_WRITE_ONLY, qpn, 1, 1, 0, laddr(base, 1), 0x80000, 64, 0));
    step(600);
}

// Longer than the transport timer takes to expire in C simulation
const int kTimerPeriod = (int(TIME_64ms.to_uint()) + 2) * MAX_QPS + 200;

} // namespace

int main()
{
    // A first session on QP 1 sends three WRITEs, which the remote node never acknowledges
    setup(1, 0x1000);
    for (uint32_t i = 0; i < 3; ++i)
        write(1, 0x10000 + i * 0x1000);
    check(psns_sent(1, RC_RDMA_WRITE_ONLY).size() == 3, "the first session on QP 1 sends three WRITEs");

    // QP 1 is set up again, for a session whose PSNs lie before the first session's
    setup(1, 0x800);
    const size_t sent_before = sent.size();
    step(kTimerPeriod);
    {
        std::printf("       sent after QP 1 was set up again:");
        for (size_t i = sent_before; i < sent.size(); ++i)
            std::printf(" psn 0x%x", sent[i].psn);
        std::printf("%s\n", sent.size() == sent_before ? " nothing" : "");
        check(sent.size() == sent_before, "nothing of the first session is sent again");
    }

    // The new session's WRITE is acknowledged, and completes
    write(1, 0x20000);
    {
        const std::vector<uint32_t> psns = psns_sent(1, RC_RDMA_WRITE_ONLY);
        const bool sent_new = !psns.empty() && psns.back() == 0x800;
        check(sent_new, "the new session's WRITE goes out with its own PSN, 0x800");
        if (sent_new)
            receive(RC_ACK, 1, 0x800, 0);
        const std::vector<ackMeta> c = completions_of(1);
        std::printf("       %zu completion(s) on QP 1\n", c.size());
        check(c.size() == 1, "its ACK completes it, and nothing else");
    }

    // A QP set up again with nothing outstanding keeps working
    setup(2, 0x2000);
    setup(2, 0x3000);
    write(2, 0x40000);
    {
        const std::vector<uint32_t> psns = psns_sent(2, RC_RDMA_WRITE_ONLY);
        if (!psns.empty())
            receive(RC_ACK, 2, psns.back(), 0);
        check(completions_of(2).size() == 1, "QP 2, set up twice with nothing outstanding, completes its WRITE");
    }

    if (failures)
        std::printf("%d FAILURE(S)\n", failures);
    else
        std::printf("ALL PASSED\n");
    return failures ? 1 : 0;
}
