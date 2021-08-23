# Performance Analysis

## noop

The following code path illustrates a noop. DPDK gets packets as fast as it can, and then does nothing with them.

```mermaid

graph TD;
  run_loop --> DPDKProcess
  rte_eth_rx_burst["rte_eth_rx_burst(1024)"]
  subgraph "DPDK Plugin"
  DPDKProcess(DPDK::Process)
  DPDKProcess --> rte_eth_rx_burst --> loop_start

  subgraph "iterate over packets"
  loop_start(rte_pktmbuf_free)
  loop_start --> loop_start
  end

  end
```

Performance for the noop case is line-rate, almost all 10 million packets were successfully received.

## Naive Approach

In this approach, a burst of packets are fetched, then each is sent one by one into Zeek for processing.

```mermaid

graph TD;
  run_loop --> DPDKProcess
  rte_eth_rx_burst["rte_eth_rx_burst(1024)"]
  subgraph "DPDK Plugin"
  DPDKProcess(DPDK::Process)
  DPDKProcess --> rte_eth_rx_burst --> loop_start

  subgraph "iterate over packets"
  loop_start(rte_pktmbuf_free)
  loop_start --> loop_start
  end

  end
```

Here, only 2.7M packets are received.