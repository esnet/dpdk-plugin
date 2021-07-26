#!/bin/bash

TEST_DURATION=60

EPOCH_TIME=$(date +%s)

mkdir worker_1_$EPOCH_TIME worker_2_$EPOCH_TIME

( cd worker_1_$EPOCH_TIME
  sudo timeout $TEST_DURATION /usr/local/zeek/bin/zeek -i dpdk::ens3f1 misc/capture-loss -e "Log::set_buf(Conn::LOG, F)"> ../w1.out 2> ../w1.err &
)

( cd worker_2_$EPOCH_TIME
  sudo QUEUE=yes timeout $TEST_DURATION /usr/local/zeek/bin/zeek -i dpdk::ens3f1 misc/capture-loss -e "Log::set_buf(Conn::LOG, F)" > ../w2.out 2> ../w2.err &
)

sleep $TEST_DURATION

echo "================= # 1 stdout ==================="
cat w1.out
echo "================= # 1 stderr ==================="
cat w1.err

echo "================= # 2 stdout ==================="
cat w2.out
echo "================= # 2 stderr ==================="
cat w2.err

echo "------------------------------------------------"

ls -l worker_*_$EPOCH_TIME

wc -l worker_*_$EPOCH_TIME/conn.log