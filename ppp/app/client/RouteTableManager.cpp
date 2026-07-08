#include <ppp/app/client/RouteTableManager.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/app/client/dns/DnsInterceptor.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/collections/Dictionary.h>
#include <ppp/diagnostics/Telemetry.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/native/rib.h>

#include <chrono>
#include <thread>

#if defined(_ANDROID)
#include <android/log.h>

static bool AndroidDnsRedirectTraceEnabled() noexcept {
#ifdef NDEBUG
    return false;
#else
    return true;
#endif
}

#define ANDROID_DNS_REDIRECT_TRACE(...) \
    do { \
        if (AndroidDnsRedirectTraceEnabled()) { \
            __android_log_print(ANDROID_LOG_INFO, "openppp2", __VA_ARGS__); \
        } \
    } while (0)
#endif

#if defined(_WIN32)
#include <windows/ppp/tap/TapWindows.h>
#include <windows/ppp/win32/network/Router.h>
#include <windows/ppp/win32/network/NetworkInterface.h>
#else
#include <common/unix/UnixAfx.h>
#if defined(_MACOS)
#include <darwin/ppp/tap/TapDarwin.h>
#else
#include <linux/ppp/tap/TapLinux.h>
#endif
#endif

using ppp::collections::Dictionary;
using ppp::net::IPEndPoint;
using ppp::telemetry::Level;

namespace ppp {
    namespace app {
        namespace client {

#if defined(_LINUX) && !defined(_ANDROID) && !defined(_IPHONE)
            static ppp::function<ppp::string(ppp::net::native::RouteEntry&)> Linux_GetNetworkInterfaceName(
                const std::shared_ptr<ppp::tap::ITap>& tap_if,
                const std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface>& tap_ni,
                const std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface>& underlying_ni,
                ppp::unordered_map<uint32_t, ppp::string>& nics) noexcept {

                auto f =
                    [tap_if, tap_ni, underlying_ni, &nics](ppp::net::native::RouteEntry& entry) noexcept {
                        if (entry.NextHop == tap_if->GatewayServer) {
                            return tap_ni->Name;
                        }

                        ppp::string nic;
                        if (Dictionary::TryGetValue(nics, entry.NextHop, nic)) {
                            if (!nic.empty()) {
                                return nic;
                            }
                        }

                        return underlying_ni->Name;
                    };
                return f;
            }
#endif

            void RouteTableManager::Bind(VEthernetNetworkSwitcher* owner) noexcept {
                owner_ = owner;
            }

#if defined(_ANDROID) || defined(_IPHONE)
            bool RouteTableManager::AddAllRoute(const std::shared_ptr<ppp::tap::ITap>& tap) noexcept {
                using RouteInformationTable = VEthernetNetworkSwitcher::RouteInformationTable;
                using RouteInformationTablePtr = VEthernetNetworkSwitcher::RouteInformationTablePtr;

                RouteInformationTablePtr rib = make_shared_object<RouteInformationTable>();
                if (NULLPTR == rib)  {
                    return false;
                }

                owner_->rib_ = rib;

                uint32_t cidr = ntohl(tap->SubmaskAddress);
                cidr = cidr & ntohl(tap->IPAddress);
                cidr = htonl(cidr);
                rib->AddRoute(cidr, IPEndPoint::NetmaskToPrefix(tap->SubmaskAddress), tap->GatewayServer);

                if (ppp::string bypass_ip_list = std::move(owner_->bypass_ip_list_); bypass_ip_list.size() > 0) {
                    bool bypass_loaded = rib->AddAllRoutes(bypass_ip_list, IPEndPoint::LoopbackAddress);
#if defined(_ANDROID)
                    ANDROID_DNS_REDIRECT_TRACE("bypass_ip_list load len=%d ok=%d",
                        (int)bypass_ip_list.size(), bypass_loaded ? 1 : 0);
#endif
                    ppp::telemetry::Log(Level::kDebug, "client", "bypass list updated");
                }

                uint32_t gws[] = {tap->GatewayServer, IPEndPoint::LoopbackAddress};
                ppp::unordered_set<uint32_t> dns_serverss_[2];
                if (NULLPTR != owner_->dns_interceptor_) {
                    owner_->dns_interceptor_->CollectReachabilityIps(
                        owner_->configuration_,
                        owner_->configuration_->dns.intercept_unmatched,
                        [&dns_serverss_](uint32_t ip) noexcept {
                            dns_serverss_[0].emplace(ip);
                        },
                        [&dns_serverss_](uint32_t ip) noexcept {
                            dns_serverss_[1].emplace(ip);
                        });
                }

                ppp::collections::Dictionary::DeduplicationList(dns_serverss_[1], dns_serverss_[0]);
                for (int i = 0; i < arraysizeof(gws); i++) {
                    uint32_t gw = gws[i];
                    for (auto& ip : dns_serverss_[i]) {
                        rib->AddRoute(ip, 32, gw);
                    }
                }

                return true;
            }
#endif

#if !defined(_ANDROID) && !defined(_IPHONE)
            bool RouteTableManager::TryApplyHostedNetworkRoutes() noexcept {
                std::shared_ptr<ppp::tap::ITap> tap = owner_->GetTap();
                if (NULLPTR == tap || !tap->IsHostedNetwork()) {
                    return true;
                }

                if (owner_->route_added_) {
                    return true;
                }

                if (!owner_->route_apply_ready_) {
                    ppp::telemetry::Log(Level::kInfo, "client", "route setup deferred: Open() is still preparing route state");
                    ppp::telemetry::Count("client.route.defer", 1);
                    return true;
                }

                std::shared_ptr<VEthernetExchanger> exchanger = owner_->exchanger_;
                if (NULLPTR == exchanger || exchanger->GetNetworkState() != VEthernetExchanger::NetworkState_Established) {
                    ppp::telemetry::Log(Level::kInfo, "client", "route setup deferred: exchanger is not established");
                    ppp::telemetry::Count("client.route.defer", 1);
                    return true;
                }

                if (exchangeof(owner_->route_added_, true)) {
                    return true;
                }

#if defined(_WIN32)
                if (!owner_->UsePaperAirplaneController()) {
                    owner_->route_added_ = false;
                    ppp::telemetry::Log(Level::kInfo, "client", "route setup failed: paper-airplane controller unavailable");
                    ppp::telemetry::Count("client.route.fail.paper_airplane", 1);
                    return false;
                }
#endif

                AddRoute();

                {
                    ppp::telemetry::SpanScope span("client.dns.apply");
                    struct ScopedDnsApplyHistogram final {
                        std::chrono::steady_clock::time_point started_at = std::chrono::steady_clock::now();

                        ~ScopedDnsApplyHistogram() noexcept {
                            auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - started_at).count();
                            ppp::telemetry::Histogram("client.dns.apply.us", elapsed);
                        }
                    } dns_apply_histogram;

#if defined(_WIN32)
                    auto tun_ni = owner_->tun_ni_;
                    if (NULLPTR != tun_ni) {
                        ppp::win32::network::SetAllNicsDnsAddresses(tun_ni->DnsAddresses, owner_->ni_dns_servers_);
                    }

                    ppp::tap::TapWindows::DnsFlushResolverCache();

                    auto underlying_ni = owner_->underlying_ni_;
                    if (NULLPTR != underlying_ni) {
                        ppp::win32::network::DeleteAllDefaultGatewayRoutes(underlying_ni->GatewayServer);
                    }
#else
                    auto tun_ni = owner_->tun_ni_;
                    if (NULLPTR != tun_ni) {
                        ppp::unix__::UnixAfx::SetDnsAddresses(tun_ni->DnsAddresses);
                    }
#endif
                }
                ppp::telemetry::Log(Level::kDebug, "client", "DNS setup");
                ppp::telemetry::Count("client.dns.setup", 1);

                ProtectDefaultRoute();

                ppp::telemetry::Log(Level::kInfo, "client", "route setup applied after exchanger established");
                return true;
            }

            void RouteTableManager::AddRoute() noexcept {
                ppp::telemetry::SpanScope span("client.route.apply");
                struct ScopedRouteApplyHistogram final {
                    std::chrono::steady_clock::time_point started_at = std::chrono::steady_clock::now();

                    ~ScopedRouteApplyHistogram() noexcept {
                        auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - started_at).count();
                        ppp::telemetry::Histogram("client.route.apply.us", elapsed);
                    }
                } route_apply_histogram;

                ppp::telemetry::Log(Level::kDebug, "client", "route add");
                ppp::telemetry::Count("client.route.add", 1);
#if defined(_WIN32)
                if (auto tap = owner_->GetTap(); NULLPTR != tap) {
                    ppp::win32::network::DeleteAllDefaultGatewayRoutes(owner_->default_routes_, { tap->GatewayServer });
                }

                ppp::win32::network::AddAllRoutes(owner_->rib_);
#elif defined(_MACOS)
                if (auto underlying_ni = owner_->GetUnderlyingNetworkInterface(); NULLPTR != underlying_ni) {
                    if (auto tap = owner_->GetTap(); NULLPTR != tap) {
                        ppp::tap::TapDarwin* darwin_tap = dynamic_cast<ppp::tap::TapDarwin*>(tap.get());
                        if (NULLPTR != darwin_tap && !darwin_tap->IsPromisc()) {
                            for (auto&& [ip, gw] : underlying_ni->DefaultRoutes) {
                                ppp::darwin::tun::utun_del_route(ip, gw);
                            }
                        }
                    }

                    ppp::tap::TapDarwin::AddAllRoutes(owner_->rib_);
                }
#else
                if (auto underlying_ni = owner_->GetUnderlyingNetworkInterface(); NULLPTR != underlying_ni) {
                    if (auto tap_ni = owner_->GetTapNetworkInterface(); NULLPTR != tap_ni) {
                        if (auto tap = owner_->GetTap(); NULLPTR != tap) {
                            ppp::tap::TapLinux* linux_tap = dynamic_cast<ppp::tap::TapLinux*>(tap.get());
                            if (NULLPTR != linux_tap && !linux_tap->IsPromisc()) {
                                VEthernetNetworkSwitcher::RouteInformationTablePtr default_routes = ppp::tap::TapLinux::FindAllDefaultGatewayRoutes({ tap->GatewayServer });
                                owner_->default_routes_ = default_routes;

                                if (NULLPTR != default_routes) {
                                    ppp::tap::TapLinux::DeleteAllRoutes(Linux_GetNetworkInterfaceName(tap, tap_ni, underlying_ni, owner_->nics_), default_routes);
                                }
                            }

                            ppp::tap::TapLinux::AddAllRoutes(Linux_GetNetworkInterfaceName(tap, tap_ni, underlying_ni, owner_->nics_), owner_->rib_);
                        }
                    }
                }
#endif
                AddRouteWithDnsServers();
            }

            bool RouteTableManager::DeleteAllDefaultRoute() noexcept {
                if (auto tap = owner_->GetTap(); NULLPTR != tap) {
#if defined(_WIN32)
                    ppp::vector<MIB_IPFORWARDROW> default_routes;
                    ppp::win32::network::DeleteAllDefaultGatewayRoutes(default_routes, { tap->GatewayServer });
                    return true;
#else
#if defined(_MACOS)
                    auto unix_tap = dynamic_cast<ppp::tap::TapDarwin*>(tap.get());
#else
                    auto unix_tap = dynamic_cast<ppp::tap::TapLinux*>(tap.get());
#endif
                    if (NULLPTR != unix_tap && !unix_tap->IsPromisc()) {
#if defined(_MACOS)
                        auto rib = ppp::tap::TapDarwin::FindAllDefaultGatewayRoutes({ tap->GatewayServer });
                        if (NULLPTR != rib) {
                            for (auto&& [ip, gw] : *rib) {
                                ppp::darwin::tun::utun_del_route(ip, gw);
                            }
                        }
#else
                        auto rib = ppp::tap::TapLinux::FindAllDefaultGatewayRoutes({ tap->GatewayServer });
                        if (NULLPTR != rib) {
                            ppp::tap::TapLinux::DeleteAllRoutes2(rib);
                        }
#endif
                        return true;
                    }
#endif
                }
                return false;
            }

            void RouteTableManager::DeleteRoute() noexcept {
                ppp::telemetry::Log(Level::kDebug, "client", "route delete");
                ppp::telemetry::Count("client.route.delete", 1);
#if defined(_WIN32)
                ppp::win32::network::DeleteAllRoutes(owner_->rib_);

                ppp::win32::network::AddAllRoutes(owner_->default_routes_);

                if (std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface> ni = owner_->underlying_ni_; NULLPTR != ni) {
                    ppp::win32::network::SetDefaultIPGateway(ni->Index, { ni->GatewayServer });
                }
#elif defined(_MACOS)
                if (auto underlying_ni = owner_->GetUnderlyingNetworkInterface(); NULLPTR != underlying_ni) {
                    ppp::tap::TapDarwin::DeleteAllRoutes(owner_->rib_);

                    if (auto tap = owner_->GetTap(); NULLPTR != tap) {
                        ppp::tap::TapDarwin* darwin_tap = dynamic_cast<ppp::tap::TapDarwin*>(tap.get());
                        if (NULLPTR != darwin_tap && !darwin_tap->IsPromisc()) {
                            for (auto&& [ip, gw] : underlying_ni->DefaultRoutes) {
                                ppp::darwin::tun::utun_add_route(ip, gw);
                            }
                        }
                    }
                }
#else
                if (auto underlying_ni = owner_->GetUnderlyingNetworkInterface(); NULLPTR != underlying_ni) {
                    if (auto tap_ni = owner_->GetTapNetworkInterface(); NULLPTR != tap_ni) {
                        if (auto tap = owner_->GetTap(); NULLPTR != tap) {
                            ppp::tap::TapLinux::DeleteAllRoutes(Linux_GetNetworkInterfaceName(tap, tap_ni, underlying_ni, owner_->nics_), owner_->rib_);

                            if (auto default_routes = owner_->default_routes_; NULLPTR != default_routes) {
                                ppp::tap::TapLinux::AddAllRoutes(Linux_GetNetworkInterfaceName(tap, tap_ni, underlying_ni, owner_->nics_), default_routes);
                            }
                        }
                    }
                }
#endif
            }

            void RouteTableManager::AddRouteWithDnsServers() noexcept {
                for (auto& dns_servers : owner_->dns_serverss_) {
                    dns_servers.clear();
                }

                auto add_dns_server_to_dns_servers =
                    [](const std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface>& ni, ppp::unordered_set<uint32_t>& dns_servers) noexcept {
                        if (NULLPTR == ni) {
                            return false;
                        }

                        uint32_t ips[2] = { IPEndPoint::AnyAddress, IPEndPoint::AnyAddress };
                        boost::asio::ip::address nips[] = { ni->IPAddress, ni->SubmaskAddress };
                        for (int i = 0; i < arraysizeof(nips); i++) {
                            boost::asio::ip::address& ip = nips[i];
                            if (ip.is_v4()) {
                                ips[i] = ip.to_v4().to_uint();
                            }
                        }

                        uint32_t rip = ips[0] & ips[1];
                        for (boost::asio::ip::address& ip : ni->DnsAddresses) {
                            if (ip.is_v6()) {
                                continue;
                            }

                            if (!ip.is_v4()) {
                                continue;
                            }

                            if (ip.is_multicast()) {
                                continue;
                            }

                            if (ip.is_loopback()) {
                                continue;
                            }

                            if (ip.is_unspecified()) {
                                continue;
                            }

                            if (IPEndPoint::IsInvalid(ip)) {
                                continue;
                            }

                            uint32_t dip = ip.to_v4().to_uint();
                            uint32_t tip = (dip & ips[1]);
                            if (tip == rip) {
                                continue;
                            }

                            dip = htonl(dip);
                            dns_servers.emplace(dip);
                        }
                        return true;
                    };

                add_dns_server_to_dns_servers(owner_->tun_ni_, owner_->dns_serverss_[0]);
                add_dns_server_to_dns_servers(owner_->underlying_ni_, owner_->dns_serverss_[1]);

                if (NULLPTR != owner_->dns_interceptor_) {
                    owner_->dns_interceptor_->CollectReachabilityIps(
                        owner_->configuration_,
                        owner_->configuration_->dns.intercept_unmatched,
                        [this](uint32_t ip) noexcept {
                            owner_->dns_serverss_[0].emplace(ip);
                        },
                        [this](uint32_t ip) noexcept {
                            owner_->dns_serverss_[1].emplace(ip);
                        });

                    const dns::FakeIpPool* fake_ip_pool = owner_->dns_interceptor_->GetFakeIpPool();
                    if (NULLPTR != fake_ip_pool && fake_ip_pool->IsEnabled()) {
                        if (std::shared_ptr<ppp::tap::ITap> tap = owner_->GetTap(); NULLPTR != tap) {
                            AddRoute(fake_ip_pool->RouteNetwork(), tap->GatewayServer, fake_ip_pool->RoutePrefix());
                        }
                    }
                }

                ppp::collections::Dictionary::DeduplicationList(owner_->dns_serverss_[1], owner_->dns_serverss_[0]);

                if (std::shared_ptr<ppp::tap::ITap> tap = owner_->GetTap(); NULLPTR != tap) {
                    for (uint32_t ip : owner_->dns_serverss_[0]) {
                        AddRoute(ip, tap->GatewayServer, 32);
                    }
                }

                if (std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface> ni = owner_->underlying_ni_; NULLPTR != ni) {
                    boost::asio::ip::address gw = ni->GatewayServer;
                    if (gw.is_v4()) {
                        uint32_t next_hop = htonl(gw.to_v4().to_uint());
                        for (uint32_t ip : owner_->dns_serverss_[1]) {
                            AddRoute(ip, next_hop, 32);
                        }
                    }
                }
            }

            bool RouteTableManager::AddRoute(uint32_t ip, uint32_t gw, int prefix) noexcept {
#if defined(_WIN32)
                MIB_IPFORWARDROW route;
                if (ppp::win32::network::Router::GetBestRoute(ip, route)) {
                    if (route.dwForwardDest == ip && route.dwForwardNextHop != gw) {
                        ppp::win32::network::Router::Delete(route);
                    }
                }

                uint32_t mask = IPEndPoint::PrefixToNetmask(prefix);
                return ppp::win32::network::Router::Add(ip, mask, gw, 1);
#elif defined(_MACOS)
                return ppp::darwin::tun::utun_add_route(ip, prefix, gw);
#else
                if (std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface> ni = owner_->underlying_ni_; NULLPTR != ni) {
                    boost::asio::ip::address next_hop = ni->GatewayServer;
                    if (next_hop.is_v4() && htonl(next_hop.to_v4().to_uint()) == gw) {
                        return ppp::tap::TapLinux::AddRoute(ni->Name, ip, 32, gw);
                    }
                }

                std::shared_ptr<ppp::tap::ITap> tap = owner_->GetTap();
                if (NULLPTR == tap) {
                    return false;
                }

                ppp::tap::TapLinux* linux_tap = dynamic_cast<ppp::tap::TapLinux*>(tap.get());
                if (NULLPTR == linux_tap) {
                    return false;
                }

                return linux_tap->AddRoute(ip, prefix, gw);
#endif
            }

#if defined(_WIN32)
            bool RouteTableManager::DeleteRoute(const std::shared_ptr<MIB_IPFORWARDTABLE>& mib, uint32_t ip, uint32_t gw, int prefix) noexcept {
                if (NULLPTR == mib) {
                    return false;
                }

                uint32_t mask = IPEndPoint::PrefixToNetmask(prefix);
                return ppp::win32::network::Router::Delete(mib, ip, mask, gw);
            }
#else
            bool RouteTableManager::DeleteRoute(uint32_t ip, uint32_t gw, int prefix) noexcept {
#if defined(_MACOS)
                return ppp::darwin::tun::utun_del_route(ip, prefix, gw);
#else
                if (std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface> ni = owner_->underlying_ni_; NULLPTR != ni) {
                    boost::asio::ip::address next_hop = ni->GatewayServer;
                    if (next_hop.is_v4() && htonl(next_hop.to_v4().to_uint()) == gw) {
                        return ppp::tap::TapLinux::DeleteRoute(ni->Name, ip, 32, gw);
                    }
                }

                std::shared_ptr<ppp::tap::ITap> tap = owner_->GetTap();
                if (NULLPTR == tap) {
                    return false;
                }

                ppp::tap::TapLinux* linux_tap = dynamic_cast<ppp::tap::TapLinux*>(tap.get());
                if (NULLPTR == linux_tap) {
                    return false;
                }

                return linux_tap->DeleteRoute(ip, prefix, gw);
#endif
            }
#endif

            void RouteTableManager::DeleteRouteWithDnsServers() noexcept {
                if (std::shared_ptr<ppp::tap::ITap> tap = owner_->GetTap(); NULLPTR != tap) {
#if defined(_WIN32)
                    if (auto mib = ppp::win32::network::Router::GetIpForwardTable(); NULLPTR != mib) {
                        for (uint32_t ip : owner_->dns_serverss_[0]) {
                            DeleteRoute(mib, ip, tap->GatewayServer, 32);
                        }
                    }
#else
                    for (uint32_t ip : owner_->dns_serverss_[0]) {
                        DeleteRoute(ip, tap->GatewayServer, 32);
                    }
#endif
                }

                if (std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface> ni = owner_->underlying_ni_; NULLPTR != ni) {
                    boost::asio::ip::address gw = ni->GatewayServer;
                    if (gw.is_v4()) {
                        uint32_t next_hop = htonl(gw.to_v4().to_uint());
#if defined(_WIN32)
                        if (auto mib = ppp::win32::network::Router::GetIpForwardTable(); NULLPTR != mib) {
                            for (uint32_t ip : owner_->dns_serverss_[1]) {
                                DeleteRoute(mib, ip, next_hop, 32);
                            }
                        }
#else
                        for (uint32_t ip : owner_->dns_serverss_[1]) {
                            DeleteRoute(ip, next_hop, 32);
                        }
#endif
                    }
                }

                for (auto& dns_servers : owner_->dns_serverss_) {
                    dns_servers.clear();
                }
            }

            bool RouteTableManager::ProtectDefaultRoute() noexcept {
                auto tap = owner_->GetTap();
                if (NULLPTR == tap) {
                    return false;
                }

#if !defined(_WIN32)
#if defined(_MACOS)
                auto unix_tap = dynamic_cast<ppp::tap::TapDarwin*>(tap.get());
#else
                auto unix_tap = dynamic_cast<ppp::tap::TapLinux*>(tap.get());
#endif
                if (NULLPTR == unix_tap || unix_tap->IsPromisc()) {
                    return false;
                }
#endif

                auto self = std::static_pointer_cast<VEthernetNetworkSwitcher>(owner_->shared_from_this());
                std::thread([self]() noexcept {
                    auto prepare = [self]() noexcept {
                        if (self->IsDisposed()) {
                            return false;
                        }

                        if (!self->route_added_) {
                            return false;
                        }

                        std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface> underlying_ni = self->underlying_ni_;
                        if (NULLPTR == underlying_ni) {
                            return false;
                        }

                        boost::asio::ip::address gw = underlying_ni->GatewayServer;
                        if (!gw.is_v4()) {
                            return false;
                        }

                        return true;
                    };

                    ppp::SetThreadName("protector");
                    for (;;) {
                        uint64_t start = ppp::GetTickCount();

                        bool ok = prepare();
                        if (!ok) {
                            break;
                        }

                        if (self->prdr_.try_lock()) {
                            ok = prepare();
                            if (ok) {
                                ok = self->route_table_.DeleteAllDefaultRoute();
                            }

                            self->prdr_.unlock();
                            if (!ok) {
                                break;
                            }
                        }

                        uint64_t now = ppp::GetTickCount();
                        uint64_t delta = 0;
                        if (now >= start) {
                            delta = 1000 - std::min<uint64_t>(1000, now - start);
                        }

                        ppp::Sleep(delta);
                    }
                }).detach();
                return true;
            }
#endif

        }
    }
}
