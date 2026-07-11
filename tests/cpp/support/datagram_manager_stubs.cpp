#include <ppp/configurations/AppConfiguration.h>
#include <ppp/app/client/VEthernetDatagramPort.h>

/**
 * @file datagram_manager_stubs.cpp
 * @brief Surgical VEthernetDatagramPort stub for ClientDatagramPortManager unit tests (P2-c).
 *
 * Replaces the real port implementation (which drags in the exchanger, transmissions and
 * coroutines) with a spyable no-op. The manager only shuffles/ages ports and calls their
 * public/virtual surface, so recording construct/dispose/sendto/onmessage/finalize here is
 * enough to assert the session-table, data-plane and GC behaviour in isolation.
 */

namespace ppp {
    namespace app {
        namespace client {
            namespace udp {
                namespace test {

                    struct DatagramPortSpy final {
                        int construct = 0;
                        int destruct = 0;
                        int dispose = 0;
                        int sendto = 0;
                        int onmessage = 0;
                        int finalize = 0;

                        void Reset() noexcept {
                            construct = destruct = dispose = sendto = onmessage = finalize = 0;
                        }
                    };

                    DatagramPortSpy& DatagramPortSpyInstance() noexcept {
                        static DatagramPortSpy spy;
                        return spy;
                    }

                }
            }
        }
    }
}

namespace ppp {
    namespace app {
        namespace client {

            VEthernetDatagramPort::VEthernetDatagramPort(const VEthernetExchangerPtr& exchanger,
                const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP) noexcept
                : exchanger_(exchanger)
                , transmission_(transmission)
                , sourceEP_(sourceEP) {
                disposed_ = false;
                onlydns_ = false;
                sendto_ = false;
                finalize_ = 0;
                timeout_ = 0;
                udp::test::DatagramPortSpyInstance().construct++;
            }

            VEthernetDatagramPort::~VEthernetDatagramPort() noexcept {
                udp::test::DatagramPortSpyInstance().destruct++;
            }

            void VEthernetDatagramPort::Dispose() noexcept {
                disposed_ = true;
                udp::test::DatagramPortSpyInstance().dispose++;
            }

            bool VEthernetDatagramPort::SendTo(const void*, int, const boost::asio::ip::udp::endpoint&) noexcept {
                udp::test::DatagramPortSpyInstance().sendto++;
                return true;
            }

            void VEthernetDatagramPort::OnMessage(void*, int, const boost::asio::ip::udp::endpoint&) noexcept {
                udp::test::DatagramPortSpyInstance().onmessage++;
            }

            void VEthernetDatagramPort::Finalize() noexcept {
                udp::test::DatagramPortSpyInstance().finalize++;
            }

        }
    }
}
