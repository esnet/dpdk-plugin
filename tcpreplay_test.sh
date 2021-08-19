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

ssh zeek-test2.es.net "rm tmp.*"

ZEEK_PID=$(run_cmd zeek-test2.es.net "pkill -9 zeek; pkill -9 perf; /usr/local/zeek/bin/zeek -i dpdk::ens3f1" /tmp/zeek.out zeek)
echo "Started Zeek with PID $ZEEK_PID"

PERF_PID=$(run_cmd zeek-test2.es.net "perf record -g -F199 --call-graph dwarf -p $ZEEK_PID -o - | perf script | c++filt" /tmp/perf_zeek-test2.out perf)
echo "Started perf with PID $PERF_PID"

echo "Starting tcpreplay"
ssh zeek-west1.es.net -f 'sudo tcpreplay -i enp216s0f1 -Kt /usr/local/esnet-security/pcaps/west_dc.pcap'

ssh zeek-test2.es.net -f "sudo kill $ZEEK_PID; sleep 3; sudo kill -INT $PERF_PID"

scp zeek-test2.es.net:/tmp/perf_zeek-test2.out .

