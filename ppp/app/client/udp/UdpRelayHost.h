#pragma once

/**
 * @file UdpRelayHost.h
 * @brief Narrow host surface for the UDP relay pipeline without VEthernetExchanger.h.
 *
 * Phase 2 (P2-b) scaffold: mirrors the proven route::RouteHostPorts / dns::DnsHostPorts
 * pattern. Lets a future ClientDatagramPortManager consume exchanger capabilities through
 * injected callbacks instead of a back-pointer + friend, so the UDP relay can be extracted
 * from the God-Object exchanger. This header only DEFINES the surface; wiring lands in later
 * increments (P2-c/P2-d). See docs/UDP_DECOUPLING_PHASE2_DESIGN.md.
 */

#include <ppp/stdafx.h>

namespace ppp {
    namespace configurations {
        class AppConfiguration;
    }
    namespace tap {
        class ITap;
    }
}

namespace ppp {
    namespace app {
        namespace client {

            class VEthernetExchanger;

            namespace udp {

                /** @brief Injectable exchanger capabilities for the UDP relay pipeline (no exchanger header). */
                struct UdpRelayHostPorts final {
                    /** @brief Current virtual NIC (TUN/TAP) for reinjecting inbound datagrams. */
                    ppp::function<std::shared_ptr<ppp::tap::ITap>()> get_tap;

                    /** @brief Active application configuration. */
                    ppp::function<std::shared_ptr<ppp::configurations::AppConfiguration>()> get_configuration;

                    /** @brief Reinject an inbound datagram to the TUN. Matches switcher::DatagramOutput. */
                    ppp::function<bool(const boost::asio::ip::udp::endpoint& source,
                                       const boost::asio::ip::udp::endpoint& destination,
                                       void* packet, int packet_size, bool caching)> datagram_output;

                    /** @brief Rewrite a fake-ip address to its real one. Matches switcher::RewriteFakeIpAddress. */
                    ppp::function<boost::asio::ip::address(const boost::asio::ip::address& address)> rewrite_fakeip;

                    /**
                     * @brief Send a datagram to the server (link-layer SENDTO).
                     * @note P2-c: the real VirtualEthernetLinklayer::DoSendTo also needs the active
                     *       ITransmission + a coroutine YieldContext; the manager will supply those from
                     *       its own session state rather than through this value-typed port. Kept here as
                     *       the intended surface; wiring resolves the coroutine plumbing in P2-c.
                     */
                    ppp::function<bool(int in_protocol,
                                       const boost::asio::ip::udp::endpoint& source,
                                       const boost::asio::ip::udp::endpoint& destination,
                                       const ppp::Byte* payload, int payload_size)> do_send_to;

                    /** @brief Register a one-shot timeout callback (UDP session aging). */
                    ppp::function<void(int64_t timeout_ms, ppp::function<void()> on_timeout)> emplace_timeout;

                    bool IsValid() const noexcept {
                        return get_tap && get_configuration && datagram_output && do_send_to && emplace_timeout;
                    }
                };

                /** @brief Implemented by the exchanger/switcher to hand out UDP relay capabilities. */
                class IUdpRelayHost {
                public:
                    virtual ~IUdpRelayHost() noexcept = default;

                    virtual UdpRelayHostPorts BuildUdpRelayHostPorts() noexcept = 0;
                };

                /** @brief Factory bridging an IUdpRelayHost into a UdpRelayHostPorts value. */
                UdpRelayHostPorts MakeUdpRelayHostPorts(const std::shared_ptr<IUdpRelayHost>& host) noexcept;

            }
        }
    }
}
