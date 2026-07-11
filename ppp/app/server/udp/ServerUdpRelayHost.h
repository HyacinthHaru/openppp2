#pragma once

/**
 * @file ServerUdpRelayHost.h
 * @brief Narrow host surface for the server UDP relay pipeline without VirtualEthernetExchanger.h.
 *
 * P2-e: server-side mirror of the client udp::UdpRelayHostPorts / ClientDatagramPortManager
 * pattern. Lets ServerDatagramPortManager consume exchanger capabilities through injected
 * callbacks instead of a back-pointer + friend, so the UDP relay session table can be
 * extracted from the God-Object exchanger. See docs/UDP_DECOUPLING_P2E_PLAN.md.
 */

#include <ppp/stdafx.h>

namespace ppp {
    namespace transmissions {
        class ITransmission;
    }
}

namespace ppp {
    namespace app {
        namespace server {

            class VirtualEthernetDatagramPort;

            namespace udp {

                /** @brief Active session transmission handle (matches exchanger's ITransmissionPtr). */
                using ITransmissionPtr = std::shared_ptr<ppp::transmissions::ITransmission>;

                /** @brief Datagram relay port handle (matches exchanger's VirtualEthernetDatagramPortPtr). */
                using VirtualEthernetDatagramPortPtr = std::shared_ptr<VirtualEthernetDatagramPort>;

                /** @brief Injectable exchanger capabilities for the server UDP relay pipeline (no exchanger header). */
                struct ServerUdpRelayHostPorts final {
                    /** @brief Build a datagram relay port bound to (transmission, source endpoint). Matches NewDatagramPort. */
                    ppp::function<VirtualEthernetDatagramPortPtr(const ITransmissionPtr& transmission,
                                                                 const boost::asio::ip::udp::endpoint& source)> create_port;

                    /**
                     * @brief Notify that a datagram port was newly opened (session-log side-effect).
                     * @note Keeps the switcher logger / telemetry on the exchanger side so the manager
                     *       stays pure mechanism, mirroring how the client manager leaves telemetry out.
                     */
                    ppp::function<void(const ITransmissionPtr& transmission,
                                       const VirtualEthernetDatagramPortPtr& port)> on_port_opened;

                    bool IsValid() const noexcept {
                        return create_port && on_port_opened;
                    }
                };

                /** @brief Implemented by the exchanger to hand out server UDP relay capabilities. */
                class IServerUdpRelayHost {
                public:
                    virtual ~IServerUdpRelayHost() noexcept = default;

                    virtual ServerUdpRelayHostPorts BuildServerUdpRelayHostPorts() noexcept = 0;
                };

                /** @brief Factory bridging an IServerUdpRelayHost into a ServerUdpRelayHostPorts value. */
                ServerUdpRelayHostPorts MakeServerUdpRelayHostPorts(const std::shared_ptr<IServerUdpRelayHost>& host) noexcept;

            }
        }
    }
}
