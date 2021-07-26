#include "DPDK.h"

namespace zeek::iosource
	{

DPDK::~DPDK()
	{
	rte_eal_cleanup();
	}

DPDK::DPDK(const std::string& iface_name, bool is_live)
	{
	props.path = iface_name;
	pkt = new zeek::Packet();

	// TODO: Determine port_num
	my_port_num = 0;

	char* cluster_node = getenv("CLUSTER_NODE");
	// Not running in a cluster, so single-queue
	if (!cluster_node)
		{
		my_queue_num = 0;
		return;
		}

	static auto cluster_node_table = zeek::id::find_val("Cluster::nodes")->AsTable();

	/* Fields in a record of type Cluster::Node
	[0] = node_type:    NodeType;
	[1] = ip:           addr;
	[2] = zone_id:      string      &default="";
	[3] = p:            port        &default=0/unknown;
	[4] = interface:    string      &optional;
	[5] = manager:      string      &optional;
	[6] = time_machine: string      &optional;
	[7] = id: string                &optional;
	*/

	static auto my_entry = cluster_node_table->Lookup(cluster_node)->GetVal()->AsRecordVal();
	static auto my_ip = my_entry->GetField(1)->AsAddr();
	// TODO: Technically this could be unset
	static auto my_iface = my_entry->GetField(4)->AsString();

	my_queue_num = 0;
	total_queues = 0;
	
	for ( const auto& iter : *cluster_node_table )
		{
		auto k = iter.GetKey();
		auto v = iter.GetValue<zeek::TableEntryVal*>()->GetVal()->AsRecordVal();

		auto interface_field = v->GetField(4);
		if ( ! interface_field )
			continue;

		auto interface_val = interface_field->AsString();
		auto ip_val = v->GetField(1)->AsAddr();

		if ( ( ip_val == my_ip ) && ( *interface_val == *my_iface ) )
			{
			// We have a cluster member whose IP and interface matches ours.
			total_queues++;
			// If they come before us, we bump up our queue number.
			if ( strcmp(k, cluster_node) < 0 )
				my_queue_num++;
			}
		}

	printf("Found %d queues\n", total_queues);
	
	// printf("Monitoring queue number: %d/%d\n", my_queue_num, total_queues);
	}

/*
 * Initializes a given port. Called one or more times by DPDK::Open
 */
inline int DPDK::port_init(uint16_t port)
	{
	static uint8_t rss_key[40] = {
			0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
			0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
			0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
			0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
			0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
	};

	struct rte_eth_conf port_conf = {
		.rxmode =
			{
				.mq_mode = ETH_MQ_RX_RSS,
				.max_rx_pkt_len = JUMBO_FRAME_MAX_SIZE,
				.split_hdr_size = 0,
				.offloads = DEV_RX_OFFLOAD_CHECKSUM,
			},
		.rx_adv_conf =
			{
				.rss_conf =
					{
						.rss_key = rss_key,
						.rss_key_len = 40,
						.rss_hf = ETH_RSS_NONFRAG_IPV4_TCP | ETH_RSS_NONFRAG_IPV6_TCP | \
								  ETH_RSS_NONFRAG_IPV4_UDP | ETH_RSS_NONFRAG_IPV6_UDP | \
								  ETH_RSS_NONFRAG_IPV4_OTHER | ETH_RSS_NONFRAG_IPV6_OTHER | \
								  ETH_RSS_FRAG_IPV4 | ETH_RSS_FRAG_IPV6,
					},
			},
	};

	struct rte_eth_dev_info dev_info;
	struct rte_eth_rxconf rxq_conf;

	const uint16_t rx_rings = total_queues;
	// uint16_t nb_rxd = RX_RING_SIZE;

	int retval;
	uint16_t q;
	uint64_t rss_hf_tmp;

	if ( rte_eal_process_type() == RTE_PROC_SECONDARY )
		{
		reporter->Info("Monitoring DPDK port %u, queue %u/%u\n", port, my_queue_num, total_queues);
		return 0;
		}

	if ( ! rte_eth_dev_is_valid_port(port) )
		return -1;

	retval = rte_eth_dev_info_get(port, &dev_info);
	if ( retval != 0 )
		{
		reporter->FatalError("Error during getting device (port %u) info: %s\n", port,
		                     strerror(-retval));
		return retval;
		}

	char dev_name[RTE_DEV_NAME_MAX_LEN];
	retval = rte_eth_dev_get_name_by_port(port, dev_name);
	if ( retval != 0 )
		{
		reporter->Warning("Error getting device name (port %u): %s\n", port, strerror(-retval));
		}
	else
		{
		reporter->Info("Configuring port %u @ %s\n", port, dev_name);
		}

	if ( dev_info.driver_name == "net_pcap" )
		{
		reporter->Info(
			"The port is using the generic 'net_pcap' driver, skipping it."
			"Please configure a Poll-Mode Driver (PMD) if you would like to use this port.\n");
		return 0;
		}

	port_conf.rxmode.max_rx_pkt_len =
		RTE_MIN(dev_info.max_rx_pktlen, port_conf.rxmode.max_rx_pkt_len);

	rss_hf_tmp = port_conf.rx_adv_conf.rss_conf.rss_hf;
	port_conf.rx_adv_conf.rss_conf.rss_hf &= dev_info.flow_type_rss_offloads;
	if ( port_conf.rx_adv_conf.rss_conf.rss_hf != rss_hf_tmp )
		{
		printf("Port %u modified RSS hash function based on hardware support,"
		       "requested:%#" PRIx64 " configured:%#" PRIx64 "\n",
		       port, rss_hf_tmp, port_conf.rx_adv_conf.rss_conf.rss_hf);
		}

	// Set number of queues
	retval = rte_eth_dev_configure(port, rx_rings, 0, &port_conf);
	if ( retval != 0 )
		{
		reporter->FatalError("Error during running eth_dev_configure (port %u) info: %s\n", port,
		                     strerror(-retval));
		return retval;
		}

	// Set MTU to the maximum
	retval = rte_eth_dev_set_mtu(port, port_conf.rxmode.max_rx_pkt_len - MTU_OVERHEAD);
	if ( retval != 0 )
		reporter->Warning("Error during running eth_dev_set_mtu (port %u, mtu %lu) info: %s\n", port,
		                  port_conf.rxmode.max_rx_pkt_len - MTU_OVERHEAD, strerror(-retval));

	// Adjust number of queues as required by the NIC
	uint16_t rx_descriptors = RX_RING_SIZE;
	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &rx_descriptors, nullptr);
	if ( retval != 0 )
		{
		reporter->FatalError("Error setting the number of queues (port %u): %s\n", port,
		                     strerror(-retval));
		return retval;
		}

	rxq_conf = dev_info.default_rxconf;
	rxq_conf.offloads = port_conf.rxmode.offloads;
	for ( q = 0; q < rx_rings; q++ )
		{
	  printf("Configuring queue %d\n", q);
		retval = rte_eth_rx_queue_setup(port, q, rx_descriptors, rte_eth_dev_socket_id(port), &rxq_conf,
		                                mbuf_pool);
		if ( retval < 0 )
			return retval;
		}

	retval = rte_eth_rx_queue_setup(port, my_queue_num, rx_descriptors, rte_socket_id(), NULL, mbuf_pool);
	if ( retval < 0 )
		return retval;

	/* Start the Ethernet port. */
	retval = rte_eth_dev_start(port);
	if ( retval < 0 )
		return retval;

	printf("------------------------------ Initializing %d\n", port);

	/* Enable RX in promiscuous mode for the Ethernet device. */
	retval = rte_eth_promiscuous_enable(port);
	if ( retval != 0 )
		return retval;

	reporter->Info("Monitoring DPDK port %u, queue %u\n", port, my_queue_num);

	// TODO: Disable offloading, configure the RSS hash, etc.

	return 0;
	}

/*
 * Called a single time by Zeek. This setups the top layer, with the abstraction layer, etc.
 */

void DPDK::Open()
	{

	// rte_eal_init needs argc and argv, so build that for now
	std::vector<std::string> arguments = {"zeek", "--proc-type=auto"};

	std::vector<char*> argv;
	for ( const auto& arg : arguments )
		argv.push_back((char*)arg.data());
	argv.push_back(nullptr);

	/* Initialize the Environment Abstraction Layer (EAL). */
	int ret = rte_eal_init(argv.size() - 1, argv.data());

	if ( ret < 0 )
		reporter->FatalError("Error with EAL initialization\n");

	int nb_ports = rte_eth_dev_count_avail();
	if ( nb_ports == 0 )
		reporter->FatalError("Error: no ports found\n");

	if ( rte_eal_process_type() == RTE_PROC_PRIMARY )
		{
		/* Creates a new mempool in memory to hold the mbufs. */
		mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports, MBUF_CACHE_SIZE, 0,
		                                    16384, rte_socket_id());
		if ( mbuf_pool == NULL )
			reporter->FatalError("Cannot create mbuf pool\n");
		}
	else
		{
		mbuf_pool = rte_mempool_lookup("MBUF_POOL");
		}

	bool found = false;
	// uint16_t port_id;

	ret = port_init(my_port_num);
	found |= ret == 0;

	if ( ret && rte_eth_dev_socket_id(my_queue_num) > 0 &&
	     rte_eth_dev_socket_id(my_queue_num) != (int)rte_socket_id() )
		reporter->Warning("port %u is on remote NUMA node to "
		                  "polling thread.\n\tPerformance will "
		                  "not be optimal.\n",
		                  my_queue_num);

	if ( ! found )
		{
		reporter->FatalError("Could not find any ports.\n");
		return;
		}

	unsigned active_procs;
	RTE_LCORE_FOREACH(active_procs) {};
	printf("%d active processes detected\n", active_procs);


	// Tells Zeek that we successfully opened the interface
	Opened(props);

	return;
	}

void DPDK::Close()
	{
	Closed();
	rte_eal_cleanup();
	}

void DPDK::Process()
	{
	// Don't return any packets if processing is suspended (except for the
	// very first packet which we need to set up times).
	if ( run_state::is_processing_suspended() && run_state::detail::first_timestamp )
		return;

	if ( run_state::pseudo_realtime )
		run_state::detail::current_wallclock = util::current_time(true);

	const uint16_t nb_rx = rte_eth_rx_burst(my_port_num, my_queue_num, bufs, BURST_SIZE);

	if ( nb_rx == 0 )
		return;

	if ( unlikely(! run_state::detail::first_timestamp) )
		run_state::detail::first_timestamp = util::current_time(true);

	// TODO: Don't do this?
	struct timeval tv;
	gettimeofday(&tv, nullptr);

	uint16_t i;
	for ( i = 0; i < nb_rx; i++ )
		{
		// TODO: How to get caplen?
		pkt->Init(DLT_EN10MB, &tv, bufs[i]->pkt_len, bufs[i]->pkt_len,
		          rte_pktmbuf_mtod(bufs[i], const unsigned char*));
		run_state::detail::dispatch_packet(pkt, this);
		rte_pktmbuf_free(bufs[i]);
		}
	}

void DPDK::Statistics(PktSrc::Stats* stats)
	{
	struct rte_eth_stats eth_stats;
	if ( rte_eth_stats_get(my_port_num, &eth_stats) == 0 )
		{
		stats->bytes_received = eth_stats.ibytes;
		stats->dropped = eth_stats.imissed;
		stats->received = eth_stats.ipackets;
		}

	return;
	}

iosource::PktSrc* DPDK::PortInit(const std::string& iface_name, bool is_live)
	{
	return new DPDK(iface_name, is_live);
	}

	} // namespace zeek::iosource
