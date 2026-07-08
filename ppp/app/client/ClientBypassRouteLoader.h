#pragma once

#include <boost/asio/ip/address.hpp>

namespace ppp {
    namespace app {
        namespace client {
            class VEthernetNetworkSwitcher;

            class ClientBypassRouteLoader {
            public:
                void Bind(VEthernetNetworkSwitcher* owner) noexcept;

#if defined(_ANDROID) || defined(_IPHONE)
                void SetBypassIpList(ppp::string&& bypass_ip_list) noexcept;
#endif

#if !defined(_ANDROID) && !defined(_IPHONE)
                bool AddLoadIPList(
                    const ppp::string& path,
#if defined(_LINUX)
                    const ppp::string& nic,
#endif
                    const boost::asio::ip::address& gw,
                    const ppp::string& url) noexcept;

                bool LoadAllIPListWithFilePaths(const boost::asio::ip::address& gw) noexcept;
#endif

                bool IsBypassIpAddress(const boost::asio::ip::address& ip) noexcept;

            private:
                VEthernetNetworkSwitcher* owner_ = nullptr;
            };
        }
    }
}
