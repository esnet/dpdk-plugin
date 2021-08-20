#!/usr/bin/env bash

run_cmd () {
    HOST=$1
    CMD=$2
    LOGFILE=$3
    PGREP=$4

    C1FILE=$(mktemp)
    C1FILENAME=$(basename $C1FILE)

    C2FILE=$(mktemp)
    C2FILENAME=$(basename $C2FILE)

    cat <<EOF > $C1FILE
#!/usr/bin/env bash

# Wrapper for $CMD

sudo ./$C2FILENAME >$LOGFILE 2>&1 </dev/null &
sleep 3
pgrep $PGREP | head -n 1
EOF

    cat <<EOF > $C2FILE
#!/usr/bin/env bash

$CMD
EOF

    scp $C1FILE $C2FILE $HOST:
    ssh $HOST chmod +x ./$C1FILENAME ./$C2FILENAME
    ssh $HOST -f "./$C1FILENAME"
}

RUN_ID=$(uuidgen)
echo "Started run with ID $RUN_ID"

ssh zeek-test1.es.net "rm tmp.*"
ssh zeek-test2.es.net "rm tmp.*"

ZEEK_DPDK_PID=$(run_cmd zeek-test2.es.net "pkill -9 zeek; pkill -9 perf; /usr/local/zeek/bin/zeek -i dpdk::ens3f1" /tmp/zeek.out zeek)
echo "Started DPDK Zeek with PID $ZEEK_DPDK_PID"

PERF_DPDK_PID=$(run_cmd zeek-test2.es.net "perf record -g -F199 --call-graph dwarf -p $ZEEK_DPDK_PID -o - | perf script | c++filt" /tmp/perf_zeek-test2.out perf)
echo "Started DPDK perf with PID $PERF_DPDK_PID"

ZEEK_AF_PID=$(run_cmd zeek-test1.es.net "pkill -9 zeek; pkill -9 perf; /usr/local/zeek/bin/zeek -i af_packet::ens3f0 " /tmp/zeek.out zeek)
echo "Started AF_Packet Zeek with PID $ZEEK_AF_PID"

PERF_AF_PID=$(run_cmd zeek-test1.es.net "perf record -g -F199 --call-graph dwarf -p $ZEEK_AF_PID -o - | perf script | c++filt" /tmp/perf_zeek-test1.out perf)
echo "Started AF_Packet perf with PID $PERF_AF_PID"

echo "Starting tcpreplay"
ssh zeek-west1.es.net -f 'sudo tcpreplay -i enp216s0f1 -Kt /usr/local/esnet-security/pcaps/west_dc.pcap'

ssh zeek-test2.es.net -f "sudo kill $ZEEK_DPDK_PID; sleep 3; sudo kill -INT $PERF_DPDK_PID"
ssh zeek-test1.es.net -f "sudo kill $ZEEK_AF_PID; sleep 3; sudo kill -INT $PERF_AF_PID"

scp zeek-test1.es.net:/tmp/perf_zeek-test1.out perf_${RUN_ID}_zeek-test1.out
scp zeek-test2.es.net:/tmp/perf_zeek-test2.out perf_${RUN_ID}_zeek-test2.out

echo "Finished run with ID $RUN_ID"