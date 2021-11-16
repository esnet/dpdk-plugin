#pragma once

#include <inttypes.h>
#include <net/if.h>
#include <stdint.h>
#include <sys/time.h>

#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_latencystats.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#include <zeek/Desc.h>
#include <zeek/ID.h>
#include <zeek/RunState.h>

// Should be 2**n - 1
//#define NUM_MBUFS 32767
#define NUM_MBUFS 32767
// NUM_BUFS % MBUF_CACHE_SIZE should be 0
#define MBUF_CACHE_SIZE RTE_MEMPOOL_CACHE_MAX_SIZE

#define CACHE_SIZE 1024*1024*1024
#define BURST_SIZE 2048
#define RX_RING_SIZE 4096

/*
 * The overhead from max frame size to MTU.
 * We have to consider the max possible overhead.
 */
#define MTU_OVERHEAD (RTE_ETHER_HDR_LEN + RTE_ETHER_CRC_LEN + 2 * sizeof(struct rte_vlan_hdr))

/* allow max jumbo frame 9726 */
#define JUMBO_FRAME_MAX_SIZE 0x2600

#include "zeek/iosource/PktSrc.h"

namespace zeek::iosource
	{

struct worker_thread_args {
    int port_id;
	int queue_id;
    struct rte_ring *ring;
};
static uint64_t queue_drops;

static int GrabPackets(void *args_ptr);
static bool pkt_loop;

class DPDK : public PktSrc
	{
public:
	/**
	 * Constructor.
	 *
	 * path: Name of the interface to open
	 *
	 * is_live: Must be true
	 */
	DPDK(const std::string& path, bool is_live);

	/**
	 * Destructor.
	 */
	virtual ~DPDK();

	static PktSrc* PortInit(const std::string& iface_name, bool is_live);

protected:
	// PktSrc interface.
	void Open() override;
	void Close() override;

	void Process() override;

	void Statistics(PktSrc::Stats* stats) override;

	void DoneWithPacket() override {};
	bool ExtractNextPacket(zeek::Packet* pkt) override { return true; };
	bool PrecompileFilter(int index, const std::string& filter) override { return true; };
	bool SetFilter(int index) override { return true; };
	double GetNextTimeout() override { return 0; };

private:
	inline int port_init(uint16_t port);

	zeek::Packet* pkt;
	PktSrc::Stats queue_stats;

	uint64_t missed_pkts;

	uint16_t my_port_num;
	uint16_t total_queues;
	uint16_t my_queue_num;

	uint32_t retry_us;

	double no_pkts;
	double full_pkts;
	double partial_pkts;
    double pkt_histo[BURST_SIZE];

	Properties props;

	// DPDK-related things
	struct rte_mempool* mbuf_pool;
	struct rte_ring* recv_ring;
	};

	} // namespace zeek::iosource
