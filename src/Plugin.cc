
#include "Plugin.h"

namespace plugin { namespace ESnet_DPDK { Plugin plugin; } }

using namespace plugin::ESnet_DPDK;

zeek::plugin::Configuration Plugin::Configure()
	{
	zeek::plugin::Configuration config;
	config.name = "ESnet::DPDK";
	config.description = "<Insert description>";
	config.version.major = 0;
	config.version.minor = 1;
	config.version.patch = 0;
	return config;
	}
