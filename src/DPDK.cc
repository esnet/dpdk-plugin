#include "DPDK.h"

namespace zeek::iosource {

    DPDK::~DPDK() {
        rte_eal_cleanup();
    }

    DPDK::DPDK(const std::string &iface_name, bool is_live) {
        props.path = iface_name;
        pkt = new zeek::Packet();
    }

/*
 * Initializes a given port. Called one or more times by DPDK::Open
 */
    inline int
    DPDK::port_init(uint16_t port) {
        struct rte_eth_conf port_conf = port_conf_default;
        const uint16_t rx_rings = 1;
        uint16_t nb_rxd = RX_RING_SIZE;
        // TODO: Can this be 0?
        uint16_t nb_txd = RX_RING_SIZE;

        int retval;
        uint16_t q;
        struct rte_eth_dev_info dev_info;

        if (!rte_eth_dev_is_valid_port(port))
            return -1;

        retval = rte_eth_dev_info_get(port, &dev_info);
        if (retval != 0) {
            printf("Error during getting device (port %u) info: %s\n",
                   port, strerror(-retval));
            return retval;
        }

        /* Configure the Ethernet device. */
        retval = rte_eth_dev_configure(port, rx_rings, 0, &port_conf);
        if (retval != 0)
            return retval;

        retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
        if (retval != 0)
            return retval;

        /* Allocate and set up 1 RX queue per Ethernet port. */
        for (q = 0; q < rx_rings; q++) {
            retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
                                            rte_eth_dev_socket_id(port), NULL, mbuf_pool);
            if (retval < 0)
                return retval;
        }

        /* Start the Ethernet port. */
        retval = rte_eth_dev_start(port);
        if (retval < 0)
            return retval;

        /* Enable RX in promiscuous mode for the Ethernet device. */
        retval = rte_eth_promiscuous_enable(port);
        if (retval != 0)
            return retval;

        return 0;
    }

    /*
     * Called a single time by Zeek. This setups the top layer, with the abstraction layer, etc.
     */

    void DPDK::Open() {

        // rte_eal_init needs argc and argv, so build that for now
        // TODO: Don't hardcode the interface
        std::vector<std::string> arguments = {"-c", "1", "-l", "1", "--vdev=eth_pcap0,iface=ens3f0"};

        std::vector<char *> argv;
        for (const auto &arg : arguments)
            argv.push_back((char *) arg.data());
        argv.push_back(nullptr);

        /* Initialize the Environment Abstraction Layer (EAL). */
        int ret = rte_eal_init(argv.size() - 1, argv.data());

        // TODO: Send messages to reporter logs too
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

        int nb_ports = rte_eth_dev_count_avail();
        if (nb_ports == 0)
            rte_exit(EXIT_FAILURE, "Error: no ports found\n");

        /* Creates a new mempool in memory to hold the mbufs. */
        mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
                                            MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
                                            rte_socket_id());
        if (mbuf_pool == NULL)
            rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

        uint16_t portid;

        /* Initialize all ports. */
        RTE_ETH_FOREACH_DEV(portid)if (port_init(portid) != 0)
                rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n",
                         portid);

        RTE_ETH_FOREACH_DEV(portid)if (rte_eth_dev_socket_id(portid) > 0 &&
                                       rte_eth_dev_socket_id(portid) !=
                                       (int) rte_socket_id())
                printf("WARNING, port %u is on remote NUMA node to "
                       "polling thread.\n\tPerformance will "
                       "not be optimal.\n", portid);


        Opened(props);

        return;
    }


    void DPDK::Close() {
        rte_eal_cleanup();
    }

    void DPDK::Process() {
        // Don't return any packets if processing is suspended (except for the
        // very first packet which we need to set up times).
        if ( run_state::is_processing_suspended() && run_state::detail::first_timestamp )
            return;

        if ( run_state::pseudo_realtime )
            run_state::detail::current_wallclock = util::current_time(true);

        const uint16_t nb_rx = rte_eth_rx_burst(0, 0, bufs, BURST_SIZE);

        if ( nb_rx == 0 )
            return;

        if ( unlikely ( ! run_state::detail::first_timestamp ) )
            run_state::detail::first_timestamp = util::current_time(true);

        struct timeval tv;
        gettimeofday(&tv, nullptr);

        uint16_t i;
        for (i = 0; i < nb_rx; i++)
        {
            pkt->Init(1, &tv, bufs[i]->pkt_len, bufs[i]->pkt_len, rte_pktmbuf_mtod(bufs[i], const unsigned char*));
            run_state::detail::dispatch_packet(pkt, this);
            rte_pktmbuf_free(bufs[i]);
        }
    }

    void DPDK::Statistics(PktSrc::Stats *stats) {
        return;
    }

    iosource::PktSrc *DPDK::PortInit(const std::string &iface_name, bool is_live) {
        return new DPDK(iface_name, is_live);
    }


} // namespace zeek::iosource

