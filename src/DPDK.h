#pragma once

#include <inttypes.h>
#include <net/if.h>
#include <stdint.h>
#include <sys/time.h>

#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#include <zeek/RunState.h>

#include "dpdk.bif.h"

#define RX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 100

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

private:
	inline int port_init(uint16_t port);
	zeek::Packet* pkt;

	uint16_t my_port_num;
	uint16_t my_queue_num;

	Properties props;

	// DPDK-related things
	struct rte_mbuf* bufs[BURST_SIZE];
	struct rte_mempool* mbuf_pool;
	};

	} // namespace zeek::iosource
