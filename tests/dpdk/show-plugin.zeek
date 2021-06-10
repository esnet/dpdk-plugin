# @TEST-EXEC: zeek -NN ESnet::DPDK |sed -e 's/version.*)/version)/g' >output
# @TEST-EXEC: btest-diff output
