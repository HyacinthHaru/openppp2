#include <ppp/app/client/udp/ClientDatagramPortManager.h>

/**
 * @file ClientDatagramPortManager.cpp
 * @brief Client UDP relay session manager (P2-c). This increment lands the scaffold; the
 *        session-table Add/Get/Release, data-plane, and GC land in P2-c task 2..5.
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

            }
        }
    }
}
