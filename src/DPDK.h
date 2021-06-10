#pragma once

extern "C" {
#include <stdint.h>
#include <sys/time.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>


#define RX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 1

static const struct rte_eth_conf port_conf_default = {
        .rxmode = {
                .max_rx_pkt_len = RTE_ETHER_MAX_LEN,
        },
};
}

#include "zeek/iosource/PktSrc.h"

namespace zeek::iosource {

    class DPDK : public PktSrc {
    public:
        /**
         * Constructor.
         *
         * path: Name of the interface to open
         *
         * is_live: Must be true
         */
        DPDK(const std::string &path, bool is_live);

        /**
         * Destructor.
         */
        virtual ~DPDK();

        static PktSrc *PortInit(const std::string &iface_name, bool is_live);

    protected:
        // PktSrc interface.
        void Open() override;

        void Close() override;

        bool ExtractNextPacket(zeek::Packet *pkt) override;

        void DoneWithPacket() override;

        bool PrecompileFilter(int index, const std::string &filter) override;

        bool SetFilter(int index) override;

        void Statistics(PktSrc::Stats *stats) override;

    private:
        inline int port_init(uint16_t port);

        Properties props;

        // DPDK-related things
        struct rte_mbuf *bufs[1];
        struct rte_mempool *mbuf_pool;
    };

} // namespace zeek::iosource
