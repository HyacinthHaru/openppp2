#pragma once

/**
 * @file VirtualEthernetIPv6.h
 * @brief Server-side aliases for virtual ethernet IPv6 helpers (defined in protocol/).
 * @author OPENPPP2 Team
 * @license GPL-3.0
 */

#include <ppp/app/protocol/VirtualEthernetIPv6.h>

namespace ppp {
    namespace app {
        namespace server {
            using VirtualEthernetIPv6MinimalHeader = ::ppp::app::protocol::VirtualEthernetIPv6MinimalHeader;
            using ::ppp::app::protocol::ParseVirtualEthernetIPv6Header;
            using ::ppp::app::protocol::VirtualEthernetIPv6PseudoChecksum;
        }
    }
}
