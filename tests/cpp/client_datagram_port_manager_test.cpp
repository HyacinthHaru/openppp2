#define BOOST_TEST_MODULE client_datagram_port_manager_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/client/udp/ClientDatagramPortManager.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/app/client/VEthernetDatagramPort.h>

#include "support/datagram_manager_stubs.h"

namespace udp_client = ppp::app::client::udp;
namespace spy_ns = ppp::app::client::udp::test;

namespace {

boost::asio::ip::udp::endpoint Ep(const char* address, unsigned short port) noexcept {
    return boost::asio::ip::udp::endpoint(boost::asio::ip::make_address(address), port);
}

udp_client::VEthernetDatagramPortPtr MakeStubPort(const udp_client::ITransmissionPtr& transmission,
                                                  const boost::asio::ip::udp::endpoint& source) noexcept {
    return std::make_shared<ppp::app::client::VEthernetDatagramPort>(
        std::shared_ptr<ppp::app::client::VEthernetExchanger>(), transmission, source);
}

udp_client::UdpRelayHostPorts MakeFilledPorts() noexcept {
    udp_client::UdpRelayHostPorts ports;
    ports.get_tap = []() noexcept { return std::shared_ptr<ppp::tap::ITap>(); };
    ports.get_configuration = []() noexcept { return std::shared_ptr<ppp::configurations::AppConfiguration>(); };
    ports.datagram_output = [](const boost::asio::ip::udp::endpoint&, const boost::asio::ip::udp::endpoint&,
                               void*, int, bool) noexcept { return true; };
    ports.rewrite_fakeip = [](const boost::asio::ip::address& address) noexcept { return address; };
    ports.do_send_to = [](int, const boost::asio::ip::udp::endpoint&, const boost::asio::ip::udp::endpoint&,
                          const ppp::Byte*, int) noexcept { return true; };
    ports.emplace_timeout = [](int64_t, ppp::function<void()>) noexcept {};
    ports.get_transmission = []() noexcept {
        // Non-null aliasing handle: SendTo only null-checks it before handing it to create_port,
        // and the stub create_port never dereferences it.
        static int transmission_marker = 0;
        return udp_client::ITransmissionPtr(std::shared_ptr<void>(),
            reinterpret_cast<ppp::transmissions::ITransmission*>(&transmission_marker));
    };
    ports.create_port = [](const udp_client::ITransmissionPtr& transmission,
                           const boost::asio::ip::udp::endpoint& source) noexcept { return MakeStubPort(transmission, source); };
    ports.is_disposed = []() noexcept { return false; };
    return ports;
}

}  // namespace

BOOST_AUTO_TEST_CASE(default_ports_is_invalid) {
    udp_client::UdpRelayHostPorts ports;
    BOOST_TEST(!ports.IsValid());
}

BOOST_AUTO_TEST_CASE(filled_ports_is_valid) {
    BOOST_TEST(MakeFilledPorts().IsValid());
}

BOOST_AUTO_TEST_CASE(manager_reflects_ports_validity) {
    udp_client::ClientDatagramPortManager invalid((udp_client::UdpRelayHostPorts()));
    BOOST_TEST(!invalid.IsValid());
    udp_client::ClientDatagramPortManager valid(MakeFilledPorts());
    BOOST_TEST(valid.IsValid());
}

BOOST_AUTO_TEST_CASE(make_udp_relay_host_ports_null_backend_is_invalid) {
    BOOST_TEST(!udp_client::MakeUdpRelayHostPorts(nullptr).IsValid());
}

BOOST_AUTO_TEST_CASE(add_new_datagram_port_dedups_by_source) {
    udp_client::UdpRelayHostPorts ports = MakeFilledPorts();
    int create_calls = 0;
    ports.create_port = [&create_calls](const udp_client::ITransmissionPtr& transmission,
                                        const boost::asio::ip::udp::endpoint& source) noexcept {
        ++create_calls;
        return MakeStubPort(transmission, source);
    };
    udp_client::ClientDatagramPortManager m(ports);

    boost::asio::ip::udp::endpoint src = Ep("10.0.0.1", 5000);
    udp_client::VEthernetDatagramPortPtr a = m.AddNewDatagramPort(udp_client::ITransmissionPtr(), src);
    udp_client::VEthernetDatagramPortPtr b = m.AddNewDatagramPort(udp_client::ITransmissionPtr(), src);

    BOOST_TEST((a != nullptr));
    BOOST_TEST((a == b));
    BOOST_TEST(create_calls == 1);
}

BOOST_AUTO_TEST_CASE(get_and_release_roundtrip) {
    udp_client::ClientDatagramPortManager m(MakeFilledPorts());

    boost::asio::ip::udp::endpoint src = Ep("10.0.0.2", 6000);
    BOOST_TEST((m.GetDatagramPort(src) == nullptr));

    udp_client::VEthernetDatagramPortPtr p = m.AddNewDatagramPort(udp_client::ITransmissionPtr(), src);
    BOOST_TEST((p != nullptr));
    BOOST_TEST((m.GetDatagramPort(src) == p));
    BOOST_TEST((m.ReleaseDatagramPort(src) == p));
    BOOST_TEST((m.GetDatagramPort(src) == nullptr));
}

BOOST_AUTO_TEST_CASE(send_to_creates_port_and_forwards) {
    spy_ns::DatagramPortSpyInstance().Reset();
    udp_client::ClientDatagramPortManager m(MakeFilledPorts());

    unsigned char buf[4] = {1, 2, 3, 4};
    BOOST_TEST(m.SendTo(Ep("10.0.0.3", 7000), Ep("8.8.8.8", 53), buf, static_cast<int>(sizeof(buf))));
    BOOST_TEST(spy_ns::DatagramPortSpyInstance().sendto == 1);
}

BOOST_AUTO_TEST_CASE(receive_empty_packet_finalizes_port) {
    spy_ns::DatagramPortSpyInstance().Reset();
    udp_client::ClientDatagramPortManager m(MakeFilledPorts());

    boost::asio::ip::udp::endpoint src = Ep("10.0.0.4", 8000);
    m.AddNewDatagramPort(udp_client::ITransmissionPtr(), src);
    BOOST_TEST(m.ReceiveFromDestination(src, Ep("1.1.1.1", 53), nullptr, 0));

    BOOST_TEST(spy_ns::DatagramPortSpyInstance().dispose == 1);   // finalize signal = MarkFinalize + Dispose
    BOOST_TEST(spy_ns::DatagramPortSpyInstance().onmessage == 0);
}

BOOST_AUTO_TEST_CASE(receive_with_port_delivers_onmessage) {
    spy_ns::DatagramPortSpyInstance().Reset();
    udp_client::ClientDatagramPortManager m(MakeFilledPorts());

    boost::asio::ip::udp::endpoint src = Ep("10.0.0.5", 9000);
    m.AddNewDatagramPort(udp_client::ITransmissionPtr(), src);
    unsigned char buf[4] = {1, 2, 3, 4};
    m.ReceiveFromDestination(src, Ep("1.1.1.1", 53), buf, static_cast<int>(sizeof(buf)));

    BOOST_TEST(spy_ns::DatagramPortSpyInstance().onmessage == 1);
    BOOST_TEST(spy_ns::DatagramPortSpyInstance().dispose == 0);
}

BOOST_AUTO_TEST_CASE(receive_without_port_reinjects_to_tun) {
    int reinjected = 0;
    udp_client::UdpRelayHostPorts ports = MakeFilledPorts();
    ports.datagram_output = [&reinjected](const boost::asio::ip::udp::endpoint&, const boost::asio::ip::udp::endpoint&,
                                          void*, int, bool) noexcept { ++reinjected; return true; };
    udp_client::ClientDatagramPortManager m(ports);

    unsigned char buf[4] = {1, 2, 3, 4};
    m.ReceiveFromDestination(Ep("10.0.0.6", 1000), Ep("1.1.1.1", 53), buf, static_cast<int>(sizeof(buf)));
    BOOST_TEST(reinjected == 1);
}

BOOST_AUTO_TEST_CASE(datagram_handler_register_dispatch_release) {
    udp_client::ClientDatagramPortManager m(MakeFilledPorts());

    boost::asio::ip::udp::endpoint src = Ep("10.0.0.7", 1100);
    int handled = 0;
    BOOST_TEST(m.RegisterDatagramHandler(src,
        [&handled](const boost::asio::ip::udp::endpoint&, const boost::asio::ip::udp::endpoint&,
                   void*, int) noexcept { ++handled; return true; }));

    unsigned char buf[4] = {1, 2, 3, 4};
    BOOST_TEST(m.ReceiveFromDestination(src, Ep("1.1.1.1", 53), buf, static_cast<int>(sizeof(buf))));
    BOOST_TEST(handled == 1);

    BOOST_TEST(m.ReleaseDatagramHandler(src));
    m.ReceiveFromDestination(src, Ep("1.1.1.1", 53), buf, static_cast<int>(sizeof(buf)));
    BOOST_TEST(handled == 1);   // handler no longer dispatched after release
}
