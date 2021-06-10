#include "Plugin.h"
#include "DPDK.h"
#include "zeek/iosource/Component.h"

namespace plugin { namespace ESnet_DPDK { Plugin plugin; }}

using namespace plugin::ESnet_DPDK;

zeek::plugin::Configuration Plugin::Configure() {

    AddComponent(new ::zeek::iosource::PktSrcComponent("DPDK", "dpdk", ::zeek::iosource::PktSrcComponent::LIVE,
                                                       ::zeek::iosource::DPDK::PortInit));

    zeek::plugin::Configuration config;
    config.name = "ESnet::DPDK";
    config.description = "DPDK packet source plugin";
    config.version.major = 0;
    config.version.minor = 1;
    config.version.patch = 0;
    return config;
}
