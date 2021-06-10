#pragma once

#include <zeek/plugin/Plugin.h>

namespace plugin {
    namespace ESnet_DPDK {

        class Plugin : public zeek::plugin::Plugin {
        protected:
            zeek::plugin::Configuration Configure() override;
        };

        extern Plugin plugin;

    }
}
