#include "DPDK.h"

namespace zeek::iosource
	{

DPDK::~DPDK()
	{
	// rte_eal_cleanup();
	}

DPDK::DPDK(const std::string& iface_name, bool is_live)
	{
	props.path = iface_name;
	props.is_live = true;

	missed_pkts = 0;

	pkt = new zeek::Packet();
	pkt->link_type = DLT_EN10MB;
	pkt->l2_checksummed = true;
	pkt->l3_checksummed = true;

	queue_stats.bytes_received = queue_stats.dropped = queue_stats.received = queue_stats.link = 0;
	no_pkts = partial_pkts = full_pkts = 0.0;
	for ( uint16_t i = 0; i < BURST_SIZE; i++ )
		pkt_histo[i] = 0.0;

	// TODO: Determine port_num
	my_port_num = 0;
	my_queue_num = 0;
	total_queues = 1;

	pkt_loop = true;

	retry_us = 100 * 1000;

	char* cluster_node = getenv("CLUSTER_NODE");
	// Not running in a cluster, so single-queue
	if ( ! cluster_node )
		{
		printf("Found %d queues\n", total_queues);
		return;
		}

	static const zeek::PDict<zeek::TableEntryVal>* cluster_node_table =
		zeek::id::find_val("Cluster::nodes")->AsTable();

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

	static const zeek::RecordVal* my_entry =
		cluster_node_table->Lookup(cluster_node)->GetVal()->AsRecordVal();
	static const zeek::IPAddr my_ip = my_entry->GetField(1)->AsAddr();
	// TODO: Technically this could be unset
	static const zeek::String* my_iface = my_entry->GetField(4)->AsString();

// PDict iterator was replaced by standard-library compatible iterators at v4.1.0
#if ZEEK_VERSION_NUMBER < 40100
	const char* k = nullptr;
	int i = 0;
	while ( auto* entry = cluster_node_table->NthEntry(i++, k) )
		{
		auto v = entry->GetVal()->AsRecordVal();
#else
	for ( const auto& iter : *cluster_node_table )
		{
		auto k = iter.GetKey();
		auto v = iter.GetValue<zeek::TableEntryVal*>()->GetVal()->AsRecordVal();
#endif
		auto interface_field = v->GetField(4);
		if ( ! interface_field )
			continue;

		auto interface_val = interface_field->AsString();
		auto ip_val = v->GetField(1)->AsAddr();

		if ( (ip_val == my_ip) && (*interface_val == *my_iface) )
			{
			// We have a cluster member whose IP and interface matches ours.
			total_queues++;
			// If they come before us, we bump up our queue number.
			if ( strcmp(k, cluster_node) < 0 )
				my_queue_num++;
			}
		}
	}

/*
 * Initializes a given port. Called one or more times by DPDK::Open
 */
inline int DPDK::port_init(uint16_t port)
	{
	static uint8_t rss_key[52] = {
		0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
		0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
		0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,

		0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A};

	struct rte_eth_conf port_conf = {
		.rxmode =
			{
				.mq_mode = ETH_MQ_RX_RSS,
				.max_rx_pkt_len = JUMBO_FRAME_MAX_SIZE,
				.split_hdr_size = 0,
				//.offloads = DEV_RX_OFFLOAD_RSS_HASH,
			},
		.rx_adv_conf =
			{
				.rss_conf =
					{
						.rss_key = rss_key,
						.rss_key_len = 52,
						.rss_hf = ETH_RSS_NONFRAG_IPV4_TCP | ETH_RSS_NONFRAG_IPV6_TCP |
	                              ETH_RSS_NONFRAG_IPV4_UDP | ETH_RSS_NONFRAG_IPV6_UDP |
	                              ETH_RSS_NONFRAG_IPV4_OTHER | ETH_RSS_NONFRAG_IPV6_OTHER |
	                              ETH_RSS_FRAG_IPV4 | ETH_RSS_FRAG_IPV6,
					},
			},
	};

	struct rte_eth_dev_info dev_info;
	struct rte_eth_rxconf rxq_conf;

	const uint16_t rx_rings = total_queues;

	int retval;
	uint16_t q;
	uint64_t rss_hf_tmp;

	if ( rte_eal_process_type() == RTE_PROC_SECONDARY )
		{
		reporter->Info("Configuring DPDK port %u, queue %u/%u", port, my_queue_num, total_queues);
		return 0;
		}

	retval = rte_eth_dev_info_get(port, &dev_info);
	if ( retval != 0 )
		{
		reporter->FatalError("Error: Could not get device (port %u) info: %s. Proceeding to the next port.\n", port, strerror(-retval));
		return retval;
		}

	printf("Debug Jumbo max=%u, dev_info=%u, min=%u\n", JUMBO_FRAME_MAX_SIZE,
	       dev_info.max_rx_pktlen, RTE_MIN(dev_info.max_rx_pktlen, JUMBO_FRAME_MAX_SIZE));

	char dev_name[RTE_DEV_NAME_MAX_LEN];
	retval = rte_eth_dev_get_name_by_port(port, dev_name);
	if ( retval != 0 )
		{
		reporter->Warning("Warning: Could not get device name (port %u): %s\n", port, strerror(-retval));
		}

	if ( dev_info.driver_name == "net_pcap" )
		{
		reporter->Info(
			"The port is using the generic 'net_pcap' driver, proceeding to the next port."
			"Please configure a Poll-Mode Driver (PMD) if you would like to use this port.\n");
		return 0;
		}

	// If the driver mis-reports this, leave it as JUMBO_FRAME_MAX so as to not set it to 0.
	if ( dev_info.max_rx_pktlen > 1024 )
		{
		port_conf.rxmode.max_rx_pkt_len = RTE_MIN(dev_info.max_rx_pktlen, JUMBO_FRAME_MAX_SIZE);
		}

	rss_hf_tmp = port_conf.rx_adv_conf.rss_conf.rss_hf;
	port_conf.rx_adv_conf.rss_conf.rss_hf &= dev_info.flow_type_rss_offloads;
	if ( port_conf.rx_adv_conf.rss_conf.rss_hf != rss_hf_tmp )
		{
		reporter->Info("Port %u modified RSS hash function based on hardware support,"
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
		reporter->Warning("Error during running eth_dev_set_mtu (port %u, mtu %lu) info: %s\n",
		                  port, port_conf.rxmode.max_rx_pkt_len - MTU_OVERHEAD, strerror(-retval));

	// Adjust number of queues as required by the NIC
	uint16_t rx_descriptors = RX_RING_SIZE;
	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &rx_descriptors, nullptr);
	if ( retval != 0 )
		{
		reporter->Warning("Error: setting the number of queues (port %u): %s. Proceeding to the next port.\n", port,
		                  strerror(-retval));
		return retval;
		}

	printf("Attempting to configure %d descriptors, allowed to configure %d\n", RX_RING_SIZE,
	       rx_descriptors);

	rxq_conf = dev_info.default_rxconf;
	rxq_conf.offloads = port_conf.rxmode.offloads;
	for ( q = 0; q < rx_rings; q++ )
		{
		retval = rte_eth_rx_queue_setup(port, q, rx_descriptors, rte_eth_dev_socket_id(port),
		                                &rxq_conf, mbuf_pool);
		if ( retval != 0 )
			{
			reporter->Warning("Error: setting the number of queue descriptors (port %u): %s. Proceeding to the next port.\n", port,
			                  strerror(-retval));
			return retval;
			}
		}

	retval = rte_eth_rx_queue_setup(port, my_queue_num, rx_descriptors, SOCKET_ID_ANY, &rxq_conf,
	                                mbuf_pool);
	if ( retval != 0 )
		{
		reporter->Warning("Error: setting the number of queue descriptors (port %u, queue %u): %s. Proceeding to the next port.\n",
		                  port, my_queue_num, strerror(-retval));
		return retval;
		}

	/* Start the Ethernet port. */
	retval = rte_eth_dev_start(port);
	if ( retval != 0 )
		{
		reporter->Warning("Error: starting port %u: %s. Proceeding to the next port.\n", port, strerror(-retval));
		return retval;
		}

	/* Enable RX in promiscuous mode for the Ethernet device. */
	retval = rte_eth_promiscuous_enable(port);
	if ( retval != 0 )
		{
		reporter->Warning("Warning: Failed to set %u to promiscuous mode: %s\n", port,
		                  strerror(-retval));
		}

	reporter->Info("Monitoring DPDK port %u, queue %u, core %u\n", port, my_queue_num, rte_lcore_id());

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
		mbuf_pool =
			rte_pktmbuf_pool_create("ZEEK_MBUF_POOL", NUM_MBUFS, MBUF_CACHE_SIZE, 0,
		                            JUMBO_FRAME_MAX_SIZE + RTE_PKTMBUF_HEADROOM, rte_socket_id());
		if ( mbuf_pool == NULL )
			reporter->FatalError("Cannot create mbuf pool\n");
		}
	else
		{
		mbuf_pool = rte_mempool_lookup("ZEEK_MBUF_POOL");
		}

	bool found = false;

	ret = port_init(my_port_num);
	found |= ret == 0;

	char* ring_name[100];
	snprintf(ring_name, 100, "queued_pkts_%d_%d", my_port_num, my_queue_num);

	recv_ring = rte_ring_create(ring_name, rte_align32pow2(NUM_MBUFS), rte_socket_id(),
	                            RING_F_SP_ENQ | RING_F_SC_DEQ);
	if ( recv_ring == nullptr )
		{
		rte_exit(EXIT_FAILURE, "Cannot create receive ring: %s\n", rte_strerror(rte_errno));
		return;
		}

	if ( ret && rte_eth_dev_socket_id(my_port_num) > 0 &&
	     rte_eth_dev_socket_id(my_port_num) != (int)rte_socket_id() )
		reporter->Warning("port %u is on remote NUMA node to "
		                  "polling thread.\n\tPerformance will "
		                  "not be optimal.\n",
		                  my_port_num);

	if ( ! found )
		{
		reporter->FatalError("Could not find any ports.\n");
		return;
		}

	struct worker_thread_args* worker_args = new worker_thread_args;
	worker_args->port_id = my_port_num;
	worker_args->queue_id = my_queue_num;
	worker_args->ring = recv_ring;

	rte_eal_remote_launch(GrabPackets, (void*)worker_args, rte_lcore_id() + 1);

	// Tells Zeek that we successfully opened the interface
	Opened(props);
	return;
	}

void DPDK::Close()
	{
	pkt_loop = false;
	Closed();
	rte_eal_cleanup();
	}

void DPDK::Process()
	{
	// Don't return any packets if processing is suspended (except for the
	// very first packet which we need to set up times).
	if ( run_state::is_processing_suspended() && run_state::detail::first_timestamp )
		{
		pkt_loop = false;
		return;
		}
	else
		pkt_loop = true;

	if ( run_state::pseudo_realtime )
		run_state::detail::current_wallclock = util::current_time(true);

	if ( unlikely(! run_state::detail::first_timestamp) )
		{
		run_state::detail::first_timestamp = util::current_time(true);
		// Start tracking stats now
		rte_eth_stats_reset(my_port_num);
		queue_drops = 0;
		}

	uint loop_size = 10000;
	struct rte_mbuf* burst_buffer[BURST_SIZE] = {NULL};
	zeek::Packet* pkt;
	while( loop_size && rte_ring_dequeue(recv_ring, (void **)&pkt) == 0 )
		{
		loop_size--;
		queue_stats.bytes_received += pkt->len;
		queue_stats.received++;
		run_state::detail::dispatch_packet(pkt, this);
		}
	}

void DPDK::Statistics(PktSrc::Stats* stats)
	{
	struct rte_eth_stats eth_stats;

	stats->bytes_received = queue_stats.bytes_received;
	stats->received = queue_stats.received;
	if ( my_queue_num == 0 && rte_eth_stats_get(my_port_num, &eth_stats) == 0 )
		{
		stats->dropped = eth_stats.imissed + queue_drops;
		}

	return;
	}

iosource::PktSrc* DPDK::PortInit(const std::string& iface_name, bool is_live)
	{
	return new DPDK(iface_name, is_live);
	}

static int GrabPackets(void* args_ptr)
	{
	struct worker_thread_args* args = (struct worker_thread_args*)args_ptr;

	int port_id = args->port_id;
	int queue_id = args->queue_id;
	struct rte_ring* ring = args->ring;

	zeek::Packet* pkt[BURST_SIZE];

	struct rte_mbuf* burst_buffer[BURST_SIZE];
	uint16_t pkts_queued = 0;
	//queue_drops = 0;

	while ( !run_state::detail::first_timestamp ) {
		rte_delay_us_sleep(1000);
	}

	while ( pkt_loop )
		{
		const uint16_t nb_rx_pkts = rte_eth_rx_burst(port_id, queue_id, burst_buffer, BURST_SIZE);

		// No packets, sleep for 1 ms and try one more time
		if ( nb_rx_pkts == 0 )
			{
			rte_delay_us_sleep(1000);
			continue;
			}

		struct timeval tv;
		gettimeofday(&tv, nullptr);
		double time = tv.tv_sec + double(tv.tv_usec) / 1e6;

		uint16_t i;
		for ( i = 0; i < nb_rx_pkts; i++ )
			{
			pkt[i] = new zeek::Packet(
				DLT_EN10MB, &tv, burst_buffer[i]->pkt_len, burst_buffer[i]->pkt_len,
				rte_pktmbuf_mtod(burst_buffer[i], const unsigned char*), true);
			pkt[i]->l2_checksummed = true;
			pkt[i]->l3_checksummed = true;
			rte_pktmbuf_free(burst_buffer[i]);
			}
		uint free_space = 0;
		pkts_queued = rte_ring_enqueue_burst(ring, (void* const*)pkt, nb_rx_pkts, &free_space);
		if ( unlikely(pkts_queued < nb_rx_pkts) )
			{
			queue_drops += nb_rx_pkts - pkts_queued;
			if ( pkts_queued == 0 )
				rte_ring_reset(ring);
			}
		}

	return 0;
	}

	} // namespace zeek::iosource
