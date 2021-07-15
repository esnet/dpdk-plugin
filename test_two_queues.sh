#!/bin/bash

sudo rm -Rf worker_1 worker_2 2> /dev/null
mkdir worker_1 worker_2

( cd worker_1
  sudo timeout 60 /usr/local/zeek/bin/zeek -i dpdk::ens3f1 > ../w1.out 2> ../w1.err &
)

( cd worker_2
  sudo QUEUE=yes timeout 60 /usr/local/zeek/bin/zeek -i dpdk::ens3f1 > ../w2.out 2> ../w2.err &
)

sleep 60

echo "================= # 1 stdout ==================="
cat w1.out
echo "================= # 1 stderr ==================="
cat w1.err

echo "================= # 2 stdout ==================="
cat w2.out
echo "================= # 2 stderr ==================="
cat w2.err

echo "------------------------------------------------"

ls -l worker_*

wc -l worker_*/conn.log