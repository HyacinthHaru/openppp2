#pragma once

/**
 * @file UdpRelayHost.h
 * @brief Narrow host surface for the UDP relay pipeline without VEthernetExchanger.h.
 *
 * Phase 2 (P2-b/P2-c): mirrors the proven route::RouteHostPorts / dns::DnsHostPorts
 * pattern. Lets ClientDatagramPortManager consume exchanger capabilities through injected
 * callbacks instead of a back-pointer + friend, so the UDP relay can be extracted from the
 * God-Object exchanger. See docs/UDP_DECOUPLING_PHASE2_DESIGN.md.
 */

#include <ppp/stdafx.h>

namespace ppp {
    namespace configurations {
        class AppConfiguration;
    }
    namespace tap {
        class ITap;
    }
    namespace transmissions {
        class ITransmission;
    }
}

namespace ppp {
    namespace app {
        namespace client {

            class VEthernetExchanger;
            class VEthernetDatagramPort;

            namespace udp {

                /** @brief Active server transmission handle (matches exchanger's ITransmissionPtr). */
                using ITransmissionPtr = std::shared_ptr<ppp::transmissions::ITransmission>;

                /** @brief Datagram relay port handle (matches exchanger's VEthernetDatagramPortPtr). */
                using VEthernetDatagramPortPtr = std::shared_ptr<VEthernetDatagramPort>;

                /** @brief Local proxy UDP reply handler (matches exchanger's DatagramPacketHandler). */
                using DatagramPacketHandler = ppp::function<bool(const boost::asio::ip::udp::endpoint& source,
                                                                 const boost::asio::ip::udp::endpoint& destination,
                                                                 void* packet, int packet_size)>;

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
                     * @note The coroutine/transmission plumbing stays inside VEthernetDatagramPort
                     *       (P2-d); the manager only manages the session table, so this port models
                     *       the value-typed slice of the link-layer send surface.
                     */
                    ppp::function<bool(int in_protocol,
                                       const boost::asio::ip::udp::endpoint& source,
                                       const boost::asio::ip::udp::endpoint& destination,
                                       const ppp::Byte* payload, int payload_size)> do_send_to;

                    /** @brief Register a one-shot timeout callback (UDP session aging). */
                    ppp::function<void(int64_t timeout_ms, ppp::function<void()> on_timeout)> emplace_timeout;

                    /** @brief Fetch the active server transmission for opening new datagram ports. */
                    ppp::function<ITransmissionPtr()> get_transmission;

                    /** @brief Build a datagram relay port bound to (transmission, source endpoint). */
                    ppp::function<VEthernetDatagramPortPtr(const ITransmissionPtr& transmission,
                                                           const boost::asio::ip::udp::endpoint& source)> create_port;

                    /** @brief Whether the owning exchanger has been disposed. */
                    ppp::function<bool()> is_disposed;

                    bool IsValid() const noexcept {
                        return get_tap && get_configuration && datagram_output && do_send_to &&
                            emplace_timeout && get_transmission && create_port && is_disposed;
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
