#include "DPDK.h"

namespace zeek::iosource {

    DPDK::~DPDK() {
        rte_eal_cleanup();
    }

    // -i dpdk::eth0 will pass iface_name="eth0"
    DPDK::DPDK(const std::string &iface_name, bool is_live) {
        props.path = iface_name;
        pkt = new zeek::Packet();

        // TODO: Determine port_num and queue_num
        my_port_num = 0;
        my_queue_num = 0;//rte_lcore_index(rte_lcore_id());
    }

/*
 * Initializes a given port. Called one or more times by DPDK::Open
 */
    inline int
    DPDK::port_init(uint16_t port) {
        struct rte_eth_conf port_conf = {
                .rxmode = {
                        .mq_mode    = ETH_MQ_RX_RSS,
                        .split_hdr_size = 0,
                        //.offloads = DEV_RX_OFFLOAD_CHECKSUM,
                },
                /*.rx_adv_conf = {
                        .rss_conf = {
                                .rss_key = NULL,
                                .rss_hf = ETH_RSS_IP,
                        },
                },*/
        };
        // TODO: number of workers
        const uint16_t rx_rings = zeek::BifConst::DPDK::num_workers;
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

        // Set number of queues
        retval = rte_eth_dev_configure(port, 1, 0, &port_conf);
        if (retval != 0)
            return retval;

        // Set size of queues
        retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, nullptr);
        if (retval != 0)
            return retval;

        // TODO: Figure out which queue we have, as worker #n
        retval = rte_eth_rx_queue_setup(port, my_queue_num, nb_rxd,
                                        rte_eth_dev_socket_id(port), NULL, mbuf_pool);
        if (retval < 0)
            return retval;

        /* Start the Ethernet port. */
        retval = rte_eth_dev_start(port);
        if (retval < 0)
            return retval;

        /* Enable RX in promiscuous mode for the Ethernet device. */
        retval = rte_eth_promiscuous_enable(port);
        if (retval != 0)
            return retval;

        // TODO: Disable offloading, configure the RSS hash, etc.

        return 0;
    }

    /*
     * Called a single time by Zeek. This setups the top layer, with the abstraction layer, etc.
     */

    void DPDK::Open() {

        // rte_eal_init needs argc and argv, so build that for now
        // TODO: Don't hardcode the interface
        std::vector<std::string> arguments = {"--proc-type=auto",
                                              "--vdev=eth_pcap0,iface=" + props.path};
        // TODO: Causing a double free, "--file-prefix=zeek"};

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

        /* Initialize all ports. */
        if (port_init(my_port_num) != 0)
            rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", my_port_num);

        struct rte_eth_dev_info dev_info;


        /* Set MTU */
        // TODO: BIF
        uint16_t mtu = 9000;
        ret = rte_eth_dev_set_mtu(my_port_num, mtu);
        if(ret != 0)
            rte_exit(EXIT_FAILURE, "Cannot set MTU %" PRIu16 ", retval=%d\n", mtu, ret);

        // TODO: reporter.log?
        if (rte_eth_dev_socket_id(my_port_num) > 0 &&
            rte_eth_dev_socket_id(my_port_num) !=
            (int) rte_socket_id())
            printf("WARNING, port %u is on remote NUMA node to "
                   "polling thread.\n\tPerformance will "
                   "not be optimal.\n", my_port_num);


        // Tells Zeek that we successfully opened the interface
        Opened(props);

        return;
    }


    void DPDK::Close() {
        Closed();
        rte_eal_cleanup();
    }

    void DPDK::Process() {
        // Don't return any packets if processing is suspended (except for the
        // very first packet which we need to set up times).
        if ( run_state::is_processing_suspended() && run_state::detail::first_timestamp )
            return;

        if ( run_state::pseudo_realtime )
            run_state::detail::current_wallclock = util::current_time(true);

        const uint16_t nb_rx = rte_eth_rx_burst(my_port_num, my_queue_num, bufs, BURST_SIZE);

        if ( nb_rx == 0 )
            return;

        if ( unlikely ( ! run_state::detail::first_timestamp ) )
            run_state::detail::first_timestamp = util::current_time(true);

        // TODO: Don't do this?
        struct timeval tv;
        gettimeofday(&tv, nullptr);

        uint16_t i;
        for (i = 0; i < nb_rx; i++)
        {
            // TODO: How to get caplen?
            pkt->Init(DLT_EN10MB, &tv, bufs[i]->pkt_len, bufs[i]->pkt_len, rte_pktmbuf_mtod(bufs[i], const unsigned char*));
            run_state::detail::dispatch_packet(pkt, this);
            rte_pktmbuf_free(bufs[i]);
        }
    }

    void DPDK::Statistics(PktSrc::Stats *stats) {
        struct rte_eth_stats eth_stats;
        if ( rte_eth_stats_get(my_port_num, &eth_stats) == 0) {
            stats->bytes_received = eth_stats.ibytes;
            stats->dropped = eth_stats.imissed;
            stats->received = eth_stats.ipackets;
        }

        return;
    }

    iosource::PktSrc *DPDK::PortInit(const std::string &iface_name, bool is_live) {
        return new DPDK(iface_name, is_live);
    }


} // namespace zeek::iosource

