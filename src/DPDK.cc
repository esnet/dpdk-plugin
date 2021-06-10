#include "DPDK.h"

namespace zeek::iosource {

DPDK::~DPDK()
	{
	  Close();
	}

DPDK::DPDK(const std::string& iface_name, bool is_live)
	{
	props.path = iface_name;
	}

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
inline int
DPDK::port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rx_rings = 1;
	uint16_t nb_rxd = RX_RING_SIZE;
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

	/* Display the port MAC address. */
	struct rte_ether_addr addr;
	retval = rte_eth_macaddr_get(port, &addr);
	if (retval != 0)
		return retval;

	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			port,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);

	/* Enable RX in promiscuous mode for the Ethernet device. */
	retval = rte_eth_promiscuous_enable(port);
	if (retval != 0)
		return retval;

	return 0;
}


void DPDK::Open()
{

  std::vector<std::string> arguments = {"-c", "1", "-l", "1", "--vdev=eth_pcap0,iface=ens3f0"};

  std::vector<char*> argv;
  for (const auto& arg : arguments)
       argv.push_back((char*)arg.data());
   argv.push_back(nullptr);
  
  /* Initialize the Environment Abstraction Layer (EAL). */
  int ret = rte_eal_init(argv.size() - 1, argv.data());
  if (ret < 0)
	rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

  int nb_ports = rte_eth_dev_count_avail();
  if (nb_ports == 0)
	rte_exit(EXIT_FAILURE, "Error: no ports found\n");

	/* Creates a new mempool in memory to hold the mbufs. */
	struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");


        uint16_t portid;

	/* Initialize all ports. */
	RTE_ETH_FOREACH_DEV(portid)
		if (port_init(portid, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",
					portid);

	RTE_ETH_FOREACH_DEV(portid)
		if (rte_eth_dev_socket_id(portid) > 0 &&
				rte_eth_dev_socket_id(portid) !=
						(int)rte_socket_id())
			printf("WARNING, port %u is on remote NUMA node to "
					"polling thread.\n\tPerformance will "
					"not be optimal.\n", portid);

	printf("\nCore %u receiving packets. [Ctrl+C to quit]\n",
			rte_lcore_id());

        Opened(props);
	return;
}
  
  
void DPDK::Close()
{
  printf("Close called\n");
}
  
  
  bool DPDK::ExtractNextPacket(zeek::Packet* pkt)
{
   const uint16_t nb_rx = rte_eth_rx_burst(0, 0, bufs, 1);
   struct timeval tv;
   if (nb_rx > 0)
   {
       gettimeofday(&tv, nullptr);

       printf("NEW packet length=%d\n", bufs[0]->pkt_len);
       pkt->Init(1, &tv, bufs[0]->pkt_len, bufs[0]->pkt_len, rte_pktmbuf_mtod(bufs[0], const unsigned char*));
}
  return true;
}
  
  
void DPDK::DoneWithPacket()
{
     printf("DEL packet length=%d\n", bufs[0]->pkt_len);
     rte_pktmbuf_free_bulk(bufs, 1);
}
  
bool DPDK::PrecompileFilter(int index, const std::string& filter)
{
  printf("PCF called\n");
  return true;
}


bool DPDK::SetFilter(int index)
{
  printf("SF called\n");
  return true;

}
  void DPDK::Statistics(PktSrc::Stats* stats) {
  return;
  }
iosource::PktSrc* DPDK::PortInit(const std::string& iface_name, bool is_live)
	{
	return new DPDK(iface_name, is_live);
	}


} // namespace zeek::iosource

