#
# Convenience Makefile providing a few common top-level targets.
#

cmake_build_dir=build
arch=`uname -s | tr A-Z a-z`-`uname -m`

all: build-it

build-it:
	@test -e $(cmake_build_dir)/config.status || ./configure
	-@test -e $(cmake_build_dir)/CMakeCache.txt && \
      test $(cmake_build_dir)/CMakeCache.txt -ot `cat $(cmake_build_dir)/CMakeCache.txt | grep ZEEK_DIST | cut -d '=' -f 2`/build/CMakeCache.txt && \
      echo Updating stale CMake cache && \
      touch $(cmake_build_dir)/CMakeCache.txt

	( cd $(cmake_build_dir) && make )

install:
	( cd $(cmake_build_dir) && make install )

clean:
	( cd $(cmake_build_dir) && make clean )

distclean:
	rm -rf $(cmake_build_dir)

test:
	make -C tests


copy:
	rsync --exclude build --exclude .git -rl . zeek-test2:/usr/local/esnet-security/dpdk

build: copy
	ssh zeek-test2 'cd /usr/local/esnet-security/dpdk; PATH=/usr/local/zeek/bin:$$PATH ./configure && make && sudo make install'

demo: build
	ssh zeek-test2 'cd /usr/local/esnet-security/dpdk; ./test_two_queues.sh'