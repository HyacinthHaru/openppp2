#pragma once

/**
 * @file ClientDatagramPortManager.h
 * @brief Self-contained client UDP relay session manager with an independent lock (P2-c).
 *
 * Extracts the datagrams_/datagram_handlers_ session tables and their management out of the
 * God-Object VEthernetExchanger. Guarded by its OWN lock, extending H1's "drop the shared
 * lock" spirit to the UDP session table: UDP packets no longer contend the exchanger lock
 * shared with FRP mappings and deadline timers. Consumes exchanger/switcher capabilities via
 * an injected UdpRelayHostPorts instead of a back-pointer + friend.
 */

#include <ppp/stdafx.h>
#include <ppp/net/Ipep.h> // std::hash<udp::endpoint> specialization (must precede the endpoint-keyed tables)
#include <ppp/app/client/udp/UdpRelayHost.h>

namespace ppp {
    namespace app {
        namespace client {
            namespace udp {

                class ClientDatagramPortManager final {
                public:
                    explicit ClientDatagramPortManager(UdpRelayHostPorts ports) noexcept;
                    ~ClientDatagramPortManager() noexcept;

                    ClientDatagramPortManager(const ClientDatagramPortManager&) = delete;
                    ClientDatagramPortManager& operator=(const ClientDatagramPortManager&) = delete;

                    /** @brief Whether the injected ports surface is complete. */
                    bool IsValid() const noexcept;

                private:
                    UdpRelayHostPorts                                                    ports_;
                    /** @brief Independent lock guarding datagrams_ and datagram_handlers_. */
                    std::mutex                                                          syncobj_;
                    /** @brief Active UDP datagram relay port table. */
                    ppp::unordered_map<boost::asio::ip::udp::endpoint,
                        VEthernetDatagramPortPtr>                                       datagrams_;
                    /** @brief Optional local proxy UDP reply handlers. */
                    ppp::unordered_map<boost::asio::ip::udp::endpoint,
                        DatagramPacketHandler>                                          datagram_handlers_;
                };

            }
        }
    }
}
