#include <ppp/app/client/udp/ClientDatagramPortManager.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/app/client/VEthernetDatagramPort.h>
#include <ppp/collections/Dictionary.h>

/**
 * @file ClientDatagramPortManager.cpp
 * @brief Client UDP relay session manager (P2-c). Owns the datagram session tables behind an
 *        independent lock; the data-plane and NAT-timeout GC land in the following increments.
 */

namespace ppp {
    namespace app {
        namespace client {
            namespace udp {

                ClientDatagramPortManager::ClientDatagramPortManager(UdpRelayHostPorts ports) noexcept
                    : ports_(std::move(ports)) {

                }

                ClientDatagramPortManager::~ClientDatagramPortManager() noexcept = default;

                bool ClientDatagramPortManager::IsValid() const noexcept {
                    return ports_.IsValid();
                }

                VEthernetDatagramPortPtr ClientDatagramPortManager::AddNewDatagramPort(
                    const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& source) noexcept {
                    VEthernetDatagramPortPtr datagram = GetDatagramPort(source);
                    if (NULLPTR != datagram) {
                        return datagram;
                    }

                    if (ports_.is_disposed && ports_.is_disposed()) {
                        return NULLPTR;
                    }

                    // create_port (the exchanger's NewDatagramPort) validates the transmission and
                    // allocates the concrete port; a null result propagates the failure unchanged.
                    datagram = ports_.create_port(transmission, source);
                    if (NULLPTR == datagram) {
                        return NULLPTR;
                    }

                    bool ok;
                    {
                        std::lock_guard<std::mutex> scope(syncobj_);
                        ok = datagrams_.emplace(source, datagram).second;
                    }

                    if (!ok) {
                        datagram->Dispose();
                        return NULLPTR;
                    }

                    return datagram;
                }

                VEthernetDatagramPortPtr ClientDatagramPortManager::GetDatagramPort(
                    const boost::asio::ip::udp::endpoint& source) noexcept {
                    std::lock_guard<std::mutex> scope(syncobj_);
                    return ppp::collections::Dictionary::FindObjectByKey(datagrams_, source);
                }

                VEthernetDatagramPortPtr ClientDatagramPortManager::ReleaseDatagramPort(
                    const boost::asio::ip::udp::endpoint& source) noexcept {
                    std::lock_guard<std::mutex> scope(syncobj_);
                    return ppp::collections::Dictionary::ReleaseObjectByKey(datagrams_, source);
                }

            }
        }
    }
}
