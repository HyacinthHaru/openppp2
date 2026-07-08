#include "DnsResponseHandler.h"

#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/net/asio/vdns.h>

namespace ppp {
    namespace app {
        namespace client {
            namespace dns {

                void DnsResponseHandler::HandleResolverResponse(
                    const std::shared_ptr<VEthernetNetworkSwitcher>& switcher,
                    const std::shared_ptr<VEthernetExchanger>& exchanger,
                    const std::shared_ptr<ppp::net::packet::BufferSegment>& messages,
                    const boost::asio::ip::udp::endpoint& sourceEP,
                    const boost::asio::ip::udp::endpoint& destEP,
                    ppp::vector<Byte> response) noexcept {

                    DnsResponseHandlerPorts ports;
                    if (NULLPTR != switcher) {
                        const std::shared_ptr<ppp::configurations::AppConfiguration> configuration =
                            switcher->GetConfiguration();
                        if (NULLPTR != configuration && configuration->udp.dns.cache) {
                            ports.enable_dns_cache = true;
                            ports.write_cache =
                                [](const Byte* packet, int packet_size) noexcept {
                                    ppp::net::asio::vdns::AddCache(packet, packet_size);
                                };
                        }
                        ports.datagram_output =
                            [switcher](const boost::asio::ip::udp::endpoint& sourceEP,
                                const boost::asio::ip::udp::endpoint& destinationEP,
                                void* packet,
                                int packet_size,
                                bool caching) noexcept {
                                return switcher->DatagramOutput(
                                    sourceEP, destinationEP, packet, packet_size, caching);
                            };
                    }
                    if (NULLPTR != exchanger) {
                        ports.tunnel_send =
                            [exchanger](const boost::asio::ip::udp::endpoint& sourceEP,
                                const boost::asio::ip::udp::endpoint& destinationEP,
                                const void* packet,
                                int packet_size) noexcept {
                                return exchanger->SendTo(
                                    sourceEP, destinationEP, packet, packet_size);
                            };
                    }

                    HandleWithPorts(ports, messages, sourceEP, destEP, std::move(response));
                }

            }
        }
    }
}
