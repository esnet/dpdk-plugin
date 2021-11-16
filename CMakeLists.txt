
cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

project(ZeekPluginDPDK)

include(ZeekPlugin)

zeek_plugin_begin(ESnet DPDK)
zeek_plugin_cc(src/Plugin.cc src/DPDK.cc)
zeek_plugin_dist_files(README CHANGES COPYING VERSION)
zeek_plugin_link_library(rte_eal rte_ethdev rte_mbuf)
zeek_plugin_end()

include(CheckCXXCompilerFlag)
CHECK_CXX_COMPILER_FLAG("-march=native" COMPILER_SUPPORTS_MARCH_NATIVE)
if(COMPILER_SUPPORTS_MARCH_NATIVE)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native")
endif()

include_directories(/usr/include/x86_64-linux-gnu/dpdk /usr/include/dpdk)

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" VERSION LIMIT_COUNT 1)

if ("${PROJECT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
    # Allows building rpm/deb packages via "make package" in build dir.
    include(ConfigurePackaging)
    ConfigurePackaging(${VERSION})
endif ()
