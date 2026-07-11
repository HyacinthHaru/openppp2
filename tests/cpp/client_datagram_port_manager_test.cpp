#define BOOST_TEST_MODULE client_datagram_port_manager_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/client/udp/ClientDatagramPortManager.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/app/client/VEthernetDatagramPort.h>

namespace udp_client = ppp::app::client::udp;

namespace {

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
    ports.get_transmission = []() noexcept { return udp_client::ITransmissionPtr(); };
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

BOOST_AUTO_TEST_CASE(add_new_datagram_port_dedups_by_source) {
    udp_client::UdpRelayHostPorts ports = MakeFilledPorts();
    int create_calls = 0;
    ports.create_port = [&create_calls](const udp_client::ITransmissionPtr& transmission,
                                        const boost::asio::ip::udp::endpoint& source) noexcept {
        ++create_calls;
        return MakeStubPort(transmission, source);
    };
    udp_client::ClientDatagramPortManager m(ports);

    boost::asio::ip::udp::endpoint src(boost::asio::ip::make_address("10.0.0.1"), 5000);
    udp_client::VEthernetDatagramPortPtr a = m.AddNewDatagramPort(udp_client::ITransmissionPtr(), src);
    udp_client::VEthernetDatagramPortPtr b = m.AddNewDatagramPort(udp_client::ITransmissionPtr(), src);

    BOOST_TEST((a != nullptr));
    BOOST_TEST((a == b));            // same source endpoint reuses the existing port
    BOOST_TEST(create_calls == 1);   // create_port invoked exactly once
}

BOOST_AUTO_TEST_CASE(get_and_release_roundtrip) {
    udp_client::ClientDatagramPortManager m(MakeFilledPorts());

    boost::asio::ip::udp::endpoint src(boost::asio::ip::make_address("10.0.0.2"), 6000);
    BOOST_TEST((m.GetDatagramPort(src) == nullptr));

    udp_client::VEthernetDatagramPortPtr p = m.AddNewDatagramPort(udp_client::ITransmissionPtr(), src);
    BOOST_TEST((p != nullptr));
    BOOST_TEST((m.GetDatagramPort(src) == p));
    BOOST_TEST((m.ReleaseDatagramPort(src) == p));
    BOOST_TEST((m.GetDatagramPort(src) == nullptr));
}
