#/usr/bin/env bash

pkill -9 zeek
pkill -9 perf

/usr/local/zeek/bin/zeek -i dpdk::ens3f1 &

ZEEK_PID=$(pgrep zeek)

echo "Started zeek ($ZEEK_PID)"

rm perf.data /tmp/perf_zeek-test2.out

perf record -g -F199 --call-graph dwarf -p $ZEEK_PID | perf script | c++filt > /tmp/perf_zeek-test2.out &
PERF_PID=$(pgrep perf | head -n 1)
echo "Started perf ($PERF_PID)"