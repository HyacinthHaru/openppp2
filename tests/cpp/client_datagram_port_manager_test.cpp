#define BOOST_TEST_MODULE client_datagram_port_manager_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/client/udp/ClientDatagramPortManager.h>

namespace udp_client = ppp::app::client::udp;

namespace {

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
    ports.get_transmission = []() noexcept { return udp_client::ITransmissionPtr(); };
    ports.create_port = [](const udp_client::ITransmissionPtr&,
                           const boost::asio::ip::udp::endpoint&) noexcept { return udp_client::VEthernetDatagramPortPtr(); };
    ports.is_disposed = []() noexcept { return false; };
    return ports;
}

}  // namespace

BOOST_AUTO_TEST_CASE(default_ports_is_invalid) {
    udp_client::UdpRelayHostPorts ports;
    BOOST_TEST(!ports.IsValid());
}

BOOST_AUTO_TEST_CASE(filled_ports_is_valid) {
    udp_client::UdpRelayHostPorts ports = MakeFilledPorts();
    BOOST_TEST(ports.IsValid());
}

BOOST_AUTO_TEST_CASE(manager_reflects_ports_validity) {
    udp_client::ClientDatagramPortManager invalid((udp_client::UdpRelayHostPorts()));
    BOOST_TEST(!invalid.IsValid());

    udp_client::ClientDatagramPortManager valid(MakeFilledPorts());
    BOOST_TEST(valid.IsValid());
}

BOOST_AUTO_TEST_CASE(make_udp_relay_host_ports_null_backend_is_invalid) {
    udp_client::UdpRelayHostPorts ports = udp_client::MakeUdpRelayHostPorts(nullptr);
    BOOST_TEST(!ports.IsValid());
}
