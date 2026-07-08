#include <ppp/app/client/dns/DnsResponseHandler.h>
#include <ppp/app/client/VEthernetNetworkTcpipStack.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/app/client/proxys/VEthernetHttpProxySwitcher.h>
#include <ppp/app/client/proxys/VEthernetSocksProxySwitcher.h>
#include <ppp/app/client/proxys/VEthernetHttpProxyConnection.h>
#include <ppp/app/client/dns/DnsInterceptor.h>
#include <ppp/transmissions/proxys/IForwarding.h>
#include <ppp/transmissions/ITransmission.h>
#include <ppp/transmissions/ITransmissionQoS.h>
#include <common/aggligator/aggligator.h>
#include <ppp/IDisposable.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/diagnostics/Telemetry.h>

#include <ppp/io/File.h>
#include <ppp/threading/Timer.h>
#include <ppp/threading/Executors.h>
#include <ppp/collections/Dictionary.h>
#include <ppp/auxiliary/StringAuxiliary.h>
#include <ppp/net/packet/IPFrame.h>
#include <ppp/net/packet/UdpFrame.h>
#include <ppp/net/packet/IcmpFrame.h>
#include <ppp/net/native/ip.h>
#include <ppp/net/native/udp.h>
#include <ppp/net/native/icmp.h>
#include <ppp/net/native/checksum.h>
#include <ppp/app/protocol/VirtualEthernetTcpMss.h>
#include <ppp/ipv6/IPv6Packet.h>

#include <ppp/net/asio/vdns.h>
#include <ppp/dns/DnsResolver.h>
#include <ppp/app/client/dns/DnsResponseHandler.h>
#include <ppp/dns/DnsWireValidation.h>
#include <ppp/configurations/DnsServerValidation.h>
#include <ppp/net/Socket.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/http/HttpClient.h>
#include <ppp/net/asio/InternetControlMessageProtocol.h>

#include <chrono>

#if defined(_ANDROID)
#include <android/log.h>
#include <android/OpenPPP2VpnProtectBridge.h>

static bool AndroidDnsRedirectTraceEnabled() noexcept {
#ifdef NDEBUG
    return false;
#else
    return true;
#endif
}

#define ANDROID_DNS_REDIRECT_TRACE(...) \
    do { \
        if (AndroidDnsRedirectTraceEnabled()) { \
            __android_log_print(ANDROID_LOG_INFO, "openppp2", __VA_ARGS__); \
        } \
    } while (0)
#endif

/**
 * @file VEthernetNetworkSwitcher.cpp
 * @brief Client-side virtual Ethernet network switcher implementation.
 * @details Licensed under GPL-3.0.
 */

#if defined(_WIN32)
#include <windows/ppp/tap/TapWindows.h>
#include <windows/ppp/win32/network/Router.h>
#include <windows/ppp/net/proxies/HttpProxy.h>
#include <windows/ppp/win32/network/NetworkInterface.h>
#include <windows/ppp/app/client/lsp/PaperAirplaneController.h>
#else
#include <common/unix/UnixAfx.h>
#if defined(_MACOS)
#include <darwin/ppp/tap/TapDarwin.h>
#else
#include <linux/ppp/tap/TapLinux.h>
#include <linux/ppp/net/ProtectorNetwork.h>
#endif
#endif


/** @brief Returns whether current platform supports managed IPv6 operations. */
static bool ClientSupportsManagedIPv6() noexcept {
#if defined(_WIN32) || defined(_LINUX) || defined(_MACOS)
    return true;
#else
    return false;
#endif
}

/** @brief Validates whether extensions describe an applicable managed IPv6 assignment. */
static bool HasManagedIPv6Assignment(const ppp::app::protocol::VirtualEthernetInformationExtensions& extensions) noexcept {
    bool status_ok = extensions.IPv6StatusCode == ppp::app::protocol::VirtualEthernetInformationExtensions::IPv6Status_Applied ||
        extensions.IPv6StatusCode == ppp::app::protocol::VirtualEthernetInformationExtensions::IPv6Status_ServerAssigned ||
        extensions.IPv6StatusCode == ppp::app::protocol::VirtualEthernetInformationExtensions::IPv6Status_ClientRequested;

    return status_ok &&
        (extensions.AssignedIPv6Mode == ppp::app::protocol::VirtualEthernetInformationExtensions::IPv6Mode_Nat66 ||
        extensions.AssignedIPv6Mode == ppp::app::protocol::VirtualEthernetInformationExtensions::IPv6Mode_Gua) &&
        extensions.AssignedIPv6AddressPrefixLength == ppp::ipv6::IPv6_MAX_PREFIX_LENGTH &&
        extensions.AssignedIPv6Address.is_v6() &&
        !extensions.AssignedIPv6Address.is_unspecified() &&
        !extensions.AssignedIPv6Address.is_multicast() &&
        !extensions.AssignedIPv6Address.is_loopback();
}

/** @brief Compares two managed IPv6 assignment snapshots for equality. */
static bool SameManagedIPv6Configuration(
    const ppp::app::protocol::VirtualEthernetInformationExtensions& left,
    const ppp::app::protocol::VirtualEthernetInformationExtensions& right) noexcept {

    return left.AssignedIPv6Mode == right.AssignedIPv6Mode &&
        left.AssignedIPv6AddressPrefixLength == right.AssignedIPv6AddressPrefixLength &&
        left.AssignedIPv6Flags == right.AssignedIPv6Flags &&
        left.AssignedIPv6Address == right.AssignedIPv6Address &&
        left.AssignedIPv6Gateway == right.AssignedIPv6Gateway &&
        left.AssignedIPv6RoutePrefix == right.AssignedIPv6RoutePrefix &&
        left.AssignedIPv6RoutePrefixLength == right.AssignedIPv6RoutePrefixLength &&
        left.AssignedIPv6Dns1 == right.AssignedIPv6Dns1 &&
        left.AssignedIPv6Dns2 == right.AssignedIPv6Dns2;
}

using ppp::auxiliary::StringAuxiliary;
using ppp::collections::Dictionary;
using ppp::threading::Timer;
using ppp::threading::Executors;
using ppp::net::AddressFamily;
using ppp::net::IPEndPoint;
using ppp::net::Ipep;
using ppp::net::native::ip_hdr;
using ppp::net::native::udp_hdr;
using ppp::net::native::icmp_hdr;
using ppp::net::packet::IPFlags;
using ppp::net::packet::IPFrame;
using ppp::net::packet::UdpFrame;
using ppp::net::packet::IcmpFrame;
using ppp::net::packet::IcmpType;
using ppp::net::packet::BufferSegment;
using ppp::transmissions::ITransmission;
using ppp::transmissions::proxys::IForwarding;
using ppp::telemetry::Level;

static constexpr ppp::UInt64 QUIC_REJECT_RATE_LIMIT_MS = 1000;
static constexpr size_t QUIC_REJECT_RATE_LIMIT_MAX = 1024;

static ppp::string BuildQuicRejectRateLimitKey(const std::shared_ptr<IPFrame>& packet, const std::shared_ptr<UdpFrame>& frame) noexcept {
    ppp::string key;
    if (NULLPTR == packet || NULLPTR == frame) {
        return key;
    }

    ppp::UInt32 source_ip = packet->Source;
    ppp::UInt32 destination_ip = packet->Destination;
    ppp::UInt16 source_port = static_cast<ppp::UInt16>(frame->Source.Port);
    ppp::UInt16 destination_port = static_cast<ppp::UInt16>(frame->Destination.Port);

    key.resize((sizeof(source_ip) << 1) + (sizeof(source_port) << 1));
    char* out = &key[0];
    memcpy(out, &source_ip, sizeof(source_ip));
    out += sizeof(source_ip);
    memcpy(out, &destination_ip, sizeof(destination_ip));
    out += sizeof(destination_ip);
    memcpy(out, &source_port, sizeof(source_port));
    out += sizeof(source_port);
    memcpy(out, &destination_port, sizeof(destination_port));
    return key;
}

namespace ppp {
    namespace app {
        namespace client {
            /** @brief Constructs network switcher and initializes baseline state flags. */
            VEthernetNetworkSwitcher::VEthernetNetworkSwitcher(const std::shared_ptr<boost::asio::io_context>& context, bool lwip, bool vnet, bool mta, const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration) noexcept
                : VEthernet(context, lwip, vnet, mta)
                , configuration_(configuration)
                , dns_interceptor_(std::make_unique<dns::DnsInterceptor>())
                , icmppackets_aid_(0) {

                route_table_.Bind(this);
                address_manager_.Bind(this);

#if !defined(_ANDROID) && !defined(_IPHONE)
                route_added_     = false;
#if defined(_LINUX)
                protect_mode_    = false;
#endif
#endif
                static_mode_     = false;
                block_quic_      = false;
                icmppackets_aid_ = RandomNext();
            }

            /** @brief Finalizes network switcher on destruction. */
            VEthernetNetworkSwitcher::~VEthernetNetworkSwitcher() noexcept {
                Finalize();
            }

            /** @brief Creates concrete TCP/IP stack implementation for VEthernet. */
            std::shared_ptr<ppp::ethernet::VNetstack> VEthernetNetworkSwitcher::NewNetstack() noexcept {
                auto my = shared_from_this();
                auto self = std::dynamic_pointer_cast<VEthernetNetworkSwitcher>(my);
                return make_shared_object<VEthernetNetworkTcpipStack>(self);
            }

            /** @brief Performs periodic tick maintenance for QoS, exchanger, and timers. */
            bool VEthernetNetworkSwitcher::OnTick(uint64_t now) noexcept {
                if (!VEthernet::OnTick(now)) {
                    return false;
                }

                std::shared_ptr<ppp::transmissions::ITransmissionQoS> qos = qos_;
                if (NULLPTR != qos) {
                    qos->Update(now);
                }

                std::shared_ptr<VEthernetExchanger> exchanger = exchanger_;
                if (NULLPTR != exchanger) {
                    exchanger->Update();
                }

                std::shared_ptr<IForwarding> forwarding = forwarding_;
                if (NULLPTR != forwarding) {
                    forwarding->Update(now);
                }

                ppp::vector<int> releases_icmppackets;
                for (;;) {
                    SynchronizedObjectScope scope(GetSynchronizedObject());
                    for (auto&& kv : icmppackets_) {
                        const VEthernetIcmpPacket& icmppacket = kv.second;
                        if (icmppacket.datetime > now) {
                            continue;
                        }

                        releases_icmppackets.emplace_back(kv.first);
                    }

                    for (int ack_id : releases_icmppackets) {
                        ppp::collections::Dictionary::RemoveValueByKey(icmppackets_, ack_id);
                    }

                    break;
                }

                VEthernetTickEventHandler tick_event = TickEvent;
                if (tick_event) {
                    tick_event(this, now);
                }

                return true;
            }

            /** @brief Handles native IPv4 packet input and forwards eligible NAT traffic. */
            bool VEthernetNetworkSwitcher::OnPacketInput(ppp::net::native::ip_hdr* packet, int packet_length, int header_length, int proto, bool vnet) noexcept {
                if (!vnet) {
                    return false;
                }

                if (proto != ppp::net::native::ip_hdr::IP_PROTO_TCP &&
                    proto != ppp::net::native::ip_hdr::IP_PROTO_UDP &&
                    proto != ppp::net::native::ip_hdr::IP_PROTO_ICMP) {
                    return false;
                }

                std::shared_ptr<VEthernetExchanger> exchanger = exchanger_;
                if (NULLPTR == exchanger) {
                    return false;
                }

                std::shared_ptr<ITap> tap = GetTap();
                if (NULLPTR == tap) {
                    return false;
                }

                uint32_t destination = packet->dest;
                if (destination == tap->IPAddress || packet->src != tap->IPAddress) {
                    return false;
                }

                uint32_t gw = tap->GatewayServer;
                uint32_t mask = tap->SubmaskAddress;
                if (IPAddressIsGatewayServer(destination, gw, mask)) {
                    return false;
                }

                if (destination != ppp::net::native::ip_hdr::IP_ADDR_BROADCAST_VALUE) {
                    if ((destination & mask) != (gw & mask)) {
                        return false;
                    }
                }

                exchanger->Nat(packet, packet_length);
                return true;
            }

            /** @brief Handles raw IPv6 packet input and forwards approved traffic. */
            bool VEthernetNetworkSwitcher::OnPacketInput(Byte* packet, int packet_length, bool vnet) noexcept {
                if (NULLPTR == packet || packet_length < ppp::ipv6::IPv6_HEADER_MIN_SIZE) {
                    return false;
                }


                if (!IsApprovedIPv6Packet(packet, packet_length)) {
                    return false;
                }

                boost::asio::ip::address_v6 source;
                boost::asio::ip::address_v6 destination;
                if (!ppp::ipv6::TryParsePacket(packet, packet_length, source, destination)) {
                    return false;
                }

                app::protocol::ClampTcpMssIPv6(packet, packet_length, app::protocol::ComputeDynamicTcpMss(false, app::protocol::kVEthernetTunnelOverhead));

                std::shared_ptr<VEthernetExchanger> exchanger = exchanger_;
                if (NULLPTR == exchanger) {
                    return false;
                }

                exchanger->Nat(packet, packet_length);
                return true;
            }

            /** @brief Validates IPv6 packet source and destination against assigned policy. */
            bool VEthernetNetworkSwitcher::IsApprovedIPv6Packet(Byte* packet, int packet_length) noexcept {
                if (NULLPTR == packet || packet_length < ppp::ipv6::IPv6_HEADER_MIN_SIZE) {
                    return false;
                }

                boost::asio::ip::address_v6 source;
                boost::asio::ip::address_v6 destination;
                if (!ppp::ipv6::TryParsePacket(packet, packet_length, source, destination)) {
                    return false;
                }

                boost::asio::ip::address_v6::bytes_type src_bytes = source.to_bytes();
                if (src_bytes[0] == 0xfe && (src_bytes[1] & 0xc0) == 0x80) {
                    return false;
                }

                if (destination.is_unspecified() || destination.is_loopback() || destination.is_multicast()) {
                    return false;
                }

                const VirtualEthernetInformationExtensions& approved = information_extensions_;
                bool valid_mode = approved.AssignedIPv6Mode == VirtualEthernetInformationExtensions::IPv6Mode_Nat66 ||
                    approved.AssignedIPv6Mode == VirtualEthernetInformationExtensions::IPv6Mode_Gua;
                if (!address_manager_.Ipv6Applied() || !valid_mode || approved.AssignedIPv6AddressPrefixLength != ppp::ipv6::IPv6_MAX_PREFIX_LENGTH || !approved.AssignedIPv6Address.is_v6()) {
                    return false;
                }

                if (source != approved.AssignedIPv6Address.to_v6()) {
                    return false;
                }

                return true;
            }

            /** @brief Routes parsed IP frame to protocol-specific handlers. */
            bool VEthernetNetworkSwitcher::OnPacketInput(const std::shared_ptr<IPFrame>& packet) noexcept {
                if (packet->ProtocolType == ip_hdr::IP_PROTO_UDP) {
                    return OnUdpPacketInput(packet);
                }
                elif(packet->ProtocolType == ip_hdr::IP_PROTO_ICMP) {
                    return OnIcmpPacketInput(packet);
                }
                else {
                    return false;
                }
            }

            /** @brief Applies per-flow rate limiting for blocked QUIC ICMP rejects. */
            bool VEthernetNetworkSwitcher::ShouldEmitBlockedQuicReject(const std::shared_ptr<IPFrame>& packet, const std::shared_ptr<UdpFrame>& frame, UInt64 now) noexcept {
                ppp::string key = BuildQuicRejectRateLimitKey(packet, frame);
                if (key.empty()) {
                    return true;
                }

                SynchronizedObjectScope scope(GetSynchronizedObject());
                auto existing = quic_reject_rate_limits_.find(key);
                if (existing != quic_reject_rate_limits_.end()) {
                    if (now - existing->second < QUIC_REJECT_RATE_LIMIT_MS) {
                        return false;
                    }

                    existing->second = now;
                    return true;
                }

                if (quic_reject_rate_limits_.size() >= QUIC_REJECT_RATE_LIMIT_MAX) {
                    for (auto tail = quic_reject_rate_limits_.begin(); tail != quic_reject_rate_limits_.end();) {
                        if (now - tail->second >= QUIC_REJECT_RATE_LIMIT_MS) {
                            tail = quic_reject_rate_limits_.erase(tail);
                        }
                        else {
                            ++tail;
                        }
                    }

                    if (quic_reject_rate_limits_.size() >= QUIC_REJECT_RATE_LIMIT_MAX) {
                        quic_reject_rate_limits_.erase(quic_reject_rate_limits_.begin());
                    }
                }

                quic_reject_rate_limits_.emplace(std::move(key), now);
                return true;
            }

            /** @brief Emits ICMP Port Unreachable so QUIC clients quickly fall back to TCP. */
            bool VEthernetNetworkSwitcher::RejectBlockedQuic(const std::shared_ptr<IPFrame>& packet, const std::shared_ptr<UdpFrame>& frame) noexcept {
                if (NULLPTR == packet || NULLPTR == frame) {
                    return false;
                }

                UInt64 now = Executors::GetTickCount();
                if (!ShouldEmitBlockedQuicReject(packet, frame, now)) {
                    return true;
                }

                std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = GetBufferAllocator();
                std::shared_ptr<BufferSegment> original = IPFrame::ToArray(allocator, packet.get());
                if (NULLPTR == original || NULLPTR == original->Buffer) {
                    return false;
                }

                int ip_header_size = sizeof(ip_hdr);
                if (NULLPTR != packet->Options) {
                    ip_header_size += packet->Options->Length;
                }

                if (original->Length < ip_header_size + (int)sizeof(udp_hdr)) {
                    return false;
                }

                int quote_size = std::min<int>(original->Length, ip_header_size + (int)sizeof(udp_hdr));
                std::shared_ptr<BufferSegment> quote = make_shared_object<BufferSegment>(
                    wrap_shared_pointer(original->Buffer.get(), original->Buffer), quote_size);
                if (NULLPTR == quote) {
                    return false;
                }

                IcmpFrame icmp;
                icmp.Type = IcmpType::ICMP_DUR;
                icmp.Code = 3; // Port unreachable.
                icmp.Source = packet->Destination;
                icmp.Destination = packet->Source;
                icmp.Ttl = IPFrame::DefaultTtl;
                icmp.AddressesFamily = AddressFamily::InterNetwork;
                icmp.Payload = quote;

                std::shared_ptr<IPFrame> reply = IcmpFrame::ToIp(allocator, &icmp);
                if (NULLPTR == reply) {
                    return false;
                }

                return Output(reply.get());
            }

            /** @brief Handles UDP frame forwarding, DNS redirect, and static mode paths. */
            bool VEthernetNetworkSwitcher::OnUdpPacketInput(const std::shared_ptr<IPFrame>& packet) noexcept {
                std::shared_ptr<UdpFrame> frame = UdpFrame::Parse(packet.get());
                if (NULLPTR == frame) {
                    return false;
                }

                const std::shared_ptr<BufferSegment>& messages = frame->Payload;
                if (NULLPTR == messages) {
                    return false;
                }

                std::shared_ptr<VEthernetExchanger> exchanger = exchanger_;
                if (NULLPTR == exchanger) {
                    return false;
                }

                // Check whether dns resolution packets need to be redirected.
                int destinationPort = frame->Destination.Port;
                if (destinationPort == PPP_DNS_SYS_PORT) {
#if defined(_ANDROID)
ANDROID_DNS_REDIRECT_TRACE(
                        "dns_redirect udp53 input src_port=%d dst_port=%d payload=%d dst=%s",
                        (int)frame->Source.Port,
                        (int)frame->Destination.Port,
                        NULLPTR != messages ? (int)messages->Length : -1,
                        Ipep::ToAddress(packet->Destination).to_string().c_str());
#endif
                    if (RedirectDnsServer(exchanger, packet, frame, messages)) {
#if defined(_ANDROID)
    ANDROID_DNS_REDIRECT_TRACE( "dns_redirect udp53 handled");
#endif
                        return true;
                    }
                    {
                        const auto self = std::static_pointer_cast<VEthernetNetworkSwitcher>(
                            shared_from_this());
                        const boost::asio::ip::udp::endpoint sourceEP =
                            IPEndPoint::ToEndPoint<boost::asio::ip::udp>(frame->Source);
                        const boost::asio::ip::udp::endpoint destEP(
                            Ipep::ToAddress(packet->Destination), PPP_DNS_SYS_PORT);
                        dns::DnsResponseHandler::HandleResolverResponse(
                            std::static_pointer_cast<VEthernetNetworkSwitcher>(shared_from_this()),
                            exchanger, messages, sourceEP, destEP, ppp::vector<Byte>{});
                    }
                    return true;
                }

                if (block_quic_ && destinationPort == PPP_HTTPS_SYS_PORT) {
                    // TODO: Also strip/ignore DNS HTTPS/SVCB records that advertise h3/alpn
                    // so clients avoid attempting QUIC before this packet-level reject path.
                    return RejectBlockedQuic(packet, frame);
                }

                // If the VPN uses static transmission mode, ensure that the link is link ready.
                if (static_mode_) {
                    auto& static_ = configuration_->udp.static_;
                    if (static_.quic && destinationPort == PPP_HTTPS_SYS_PORT) {
                        if (exchanger->StaticEchoAllocated()) {
                            return exchanger->StaticEchoPacketToRemoteExchanger(frame);
                        }
                    }
                    elif(static_.dns && destinationPort == PPP_DNS_SYS_PORT) {
                        if (exchanger->StaticEchoAllocated()) {
                            return exchanger->StaticEchoPacketToRemoteExchanger(frame);
                        }
                    }
                    elif(exchanger->StaticEchoAllocated()) {
                        return exchanger->StaticEchoPacketToRemoteExchanger(frame);
                    }
                }

                boost::asio::ip::udp::endpoint sourceEP = IPEndPoint::ToEndPoint<boost::asio::ip::udp>(frame->Source);
                boost::asio::ip::udp::endpoint destinationEP = IPEndPoint::ToEndPoint<boost::asio::ip::udp>(frame->Destination);
                const boost::asio::ip::address rewritten = RewriteFakeIpAddress(destinationEP.address());
                if (rewritten != destinationEP.address()) {
                    destinationEP = boost::asio::ip::udp::endpoint(rewritten, destinationEP.port());
                }
                bool ok = exchanger->SendTo(sourceEP, destinationEP, messages->Buffer.get(), messages->Length);
                if (destinationEP.port() == PPP_DNS_SYS_PORT || !ok) {
                    ppp::telemetry::Log(Level::kInfo, "switcher", "UDP send source=%s:%u destination=%s:%u bytes=%d ok=%d error=%d",
                        sourceEP.address().to_string().c_str(),
                        sourceEP.port(),
                        destinationEP.address().to_string().c_str(),
                        destinationEP.port(),
                        messages->Length,
                        ok ? 1 : 0,
                        (int)ppp::diagnostics::GetLastErrorCode());
                }
                return ok;
            }

            /** @brief Sends ICMP Echo Reply generated from tracked packet context. */
            bool VEthernetNetworkSwitcher::ER(const std::shared_ptr<IPFrame>& packet, const std::shared_ptr<IcmpFrame>& frame, int ttl, const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept {
                std::shared_ptr<IPFrame> reply = ppp::net::asio::InternetControlMessageProtocol::ER(packet, frame, ttl, allocator);
                if (NULLPTR == reply) {
                    return false;
                }
                else {
                    return Output(reply.get());
                }
            }

            /** @brief Sends ICMP Time Exceeded generated from tracked packet context. */
            bool VEthernetNetworkSwitcher::TE(const std::shared_ptr<IPFrame>& packet, const std::shared_ptr<IcmpFrame>& frame, UInt32 source, const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept {
                std::shared_ptr<IPFrame> reply = ppp::net::asio::InternetControlMessageProtocol::TE(packet, frame, source, allocator);
                if (NULLPTR == reply) {
                    return false;
                }
                else {
                    return Output(reply.get());
                }
            }

            /** @brief Resolves ACK identifier and emits appropriate ICMP response packet. */
            bool VEthernetNetworkSwitcher::ERORTE(int ack_id) noexcept {
                std::shared_ptr<IPFrame> packet;
                if (ack_id != 0) {
                    SynchronizedObjectScope scope(GetSynchronizedObject());
                    bool ok = Dictionary::RemoveValueByKey(icmppackets_, ack_id, packet,
                        [](VEthernetIcmpPacket& value) noexcept {
                            return value.packet;
                        });
                    if (!ok) {
                        return false;
                    }
                }

                if (NULLPTR == packet) {
                    return false;
                }

                std::shared_ptr<ITap> tap = GetTap();
                if (NULLPTR == tap) {
                    return false;
                }

                std::shared_ptr<IcmpFrame> frame = IcmpFrame::Parse(packet.get());
                if (NULLPTR == frame) {
                    return false;
                }

                std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = GetBufferAllocator();
                if (IPAddressIsGatewayServer(frame->Destination, tap->GatewayServer, tap->SubmaskAddress)) {
                    int ttl = std::max<int>(1, static_cast<int>(frame->Ttl) - 1);
                    return ER(packet, frame, ttl, allocator);
                }
                else {
                    return TE(packet, frame, tap->GatewayServer, allocator);
                }
            }

            /** @brief Processes ICMP input and dispatches to gateway/other echo paths. */
            bool VEthernetNetworkSwitcher::OnIcmpPacketInput(const std::shared_ptr<IPFrame>& packet) noexcept {
                std::shared_ptr<VEthernetExchanger> exchanger = exchanger_;
                if (NULLPTR == exchanger) {
                    return false;
                }

                std::shared_ptr<ITap> tap = GetTap();
                if (NULLPTR == tap) {
                    return false;
                }

                std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = GetBufferAllocator();
                std::shared_ptr<IcmpFrame> frame = IcmpFrame::Parse(packet.get());
#if defined(_ANDROID)
                __android_log_print(ANDROID_LOG_INFO, "openppp2", "icmp_input dst=%s ttl=%d type=%d code=%d frame=%p",
                    Ipep::ToAddress(packet->Destination).to_string().c_str(),
                    packet->Ttl,
                    NULLPTR != frame ? (int)frame->Type : -1,
                    NULLPTR != frame ? (int)frame->Code : -1,
                    (void*)frame.get());
#endif
                if (NULLPTR == frame || frame->Ttl == 0) {
                    return false;
                }

                // The mobile TUN can feed locally generated ICMP errors such as
                // destination-unreachable/port-unreachable for short-lived UDP
                // sockets. The echo forwarding path only supports echo probes;
                // forwarding ICMP errors through it can dereference stale timer
                // state in the native exchanger and crash the VPN process.
                if (frame->Type != IcmpType::ICMP_ECHO && frame->Type != IcmpType::ICMP_ER) {
#if defined(_ANDROID)
ANDROID_DNS_REDIRECT_TRACE( "icmp_drop unsupported type=%d code=%d dst=%s",
                        (int)frame->Type,
                        (int)frame->Code,
                        Ipep::ToAddress(packet->Destination).to_string().c_str());
#endif
                    return false;
                }

                elif(IPAddressIsGatewayServer(frame->Destination, tap->GatewayServer, tap->SubmaskAddress)) {
#if defined(_ANDROID)
ANDROID_DNS_REDIRECT_TRACE( "icmp_gateway dst=%s", Ipep::ToAddress(packet->Destination).to_string().c_str());
#endif
                    return EchoGatewayServer(exchanger, packet, allocator);
                }
                elif(frame->Ttl == 1) {
#if defined(_ANDROID)
ANDROID_DNS_REDIRECT_TRACE( "icmp_ttl1 dst=%s", Ipep::ToAddress(packet->Destination).to_string().c_str());
#endif
                    return EchoGatewayServer(exchanger, packet, allocator);
                }
                else {
                    int ttl = std::max<int>(0, static_cast<int>(packet->Ttl) - 1);
                    if (packet->Ttl < 1) {
                        return false;
                    }

                    frame->Ttl = ttl;
                    packet->Ttl = ttl;

#if defined(_ANDROID)
ANDROID_DNS_REDIRECT_TRACE( "icmp_other dst=%s ttl=%d", Ipep::ToAddress(packet->Destination).to_string().c_str(), ttl);
#endif
                    return EchoOtherServer(exchanger, packet, allocator);
                }
            }

            /** @brief Forwards ICMP packet to non-gateway destination through exchanger. */
            bool VEthernetNetworkSwitcher::EchoOtherServer(const std::shared_ptr<VEthernetExchanger>& exchanger, const std::shared_ptr<IPFrame>& packet, const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept {
                if (NULLPTR == exchanger) {
                    return false;
                }

                if (IsDisposed()) {
                    return false;
                }

                std::shared_ptr<BufferSegment> messages = IPFrame::ToArray(allocator, packet.get());
                if (NULLPTR == messages) {
#if defined(_ANDROID)
                    __android_log_print(ANDROID_LOG_WARN, "openppp2", "icmp_other to_array failed dst=%s",
                        Ipep::ToAddress(packet->Destination).to_string().c_str());
#endif
                    return false;
                }

                auto& static_ = configuration_->udp.static_;
                if ((static_mode_ && static_.icmp) && exchanger->StaticEchoAllocated()) {
                    bool se_ok = exchanger->StaticEchoPacketToRemoteExchanger(packet.get());
#if defined(_ANDROID)
ANDROID_DNS_REDIRECT_TRACE( "icmp_other static_echo dst=%s ok=%d",
                        Ipep::ToAddress(packet->Destination).to_string().c_str(), (int)se_ok);
#endif
                    if (se_ok) {
                        return true;
                    }
                }

                bool ok = exchanger->Echo(messages->Buffer.get(), messages->Length);
#if defined(_ANDROID)
                __android_log_print(ANDROID_LOG_INFO, "openppp2", "icmp_other echo dst=%s ok=%d",
                    Ipep::ToAddress(packet->Destination).to_string().c_str(), (int)ok);
#endif
                return ok;
            }

            /** @brief Tracks ICMP packet by ACK ID and triggers remote gateway echo flow. */
            bool VEthernetNetworkSwitcher::EchoGatewayServer(const std::shared_ptr<VEthernetExchanger>& exchanger, const std::shared_ptr<IPFrame>& packet, const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept {
                static constexpr int max_icmp_packets_aid = (1 << 24) - 1;

                if (NULLPTR == exchanger) {
                    return false;
                }

                int ack_id = 0;
                /** @brief Allocates a unique ACK ID and stores packet until callback/timeout. */
                for (SynchronizedObjectScope scope(GetSynchronizedObject());;) {
                    if (IsDisposed()) {
                        return false;
                    }

                    VEthernetIcmpPacket e = { Executors::GetTickCount() + ppp::net::asio::InternetControlMessageProtocol::MAX_ICMP_TIMEOUT, packet };
                    bool static_exchange = false;

                    for (int i = 0; i < UINT16_MAX; i++) {
                        ack_id = ++icmppackets_aid_;
                        if (ack_id < 1) {
                            icmppackets_aid_ = 0;
                            continue;
                        }

                        if (ack_id > max_icmp_packets_aid) {
                            icmppackets_aid_ = 0;
                            continue;
                        }

                        if (ppp::collections::Dictionary::ContainsKey(icmppackets_, ack_id)) {
                            continue;
                        }

                        if (!ppp::collections::Dictionary::TryAdd(icmppackets_, ack_id, e)) {
                            return false;
                        }

                        auto& static_ = configuration_->udp.static_;
                        if ((static_mode_ && static_.icmp) && exchanger->StaticEchoAllocated()) {
                            static_exchange = true;
                            break;
                        }
                        elif(exchanger->Echo(ack_id)) {
#if defined(_ANDROID)
        ANDROID_DNS_REDIRECT_TRACE( "icmp_gateway echo ack_id=%d ok=1", ack_id);
#endif
                            return true;
                        }

                        ppp::collections::Dictionary::TryRemove(icmppackets_, ack_id);
                        return false;
                    }

                    if (static_exchange) {
                        break;
                    }

                    return false;
                }

                bool ok = exchanger->StaticEchoGatewayServer(ack_id);
#if defined(_ANDROID)
                __android_log_print(ANDROID_LOG_INFO, "openppp2", "icmp_gateway static_echo ack_id=%d ok=%d", ack_id, (int)ok);
#endif
                if (ok) {
                    return true;
                }
                else {
                    SynchronizedObjectScope scope(GetSynchronizedObject());
                    ppp::collections::Dictionary::TryRemove(icmppackets_, ack_id);
                    return false;
                }
            }

            /** @brief Dispatches switcher finalization and then disposes base VEthernet. */
            void VEthernetNetworkSwitcher::Dispose() noexcept {
                auto self = std::static_pointer_cast<VEthernetNetworkSwitcher>(shared_from_this());
                std::shared_ptr<boost::asio::io_context> context = GetContext();
                boost::asio::dispatch(*context,
                    [self, this, context]() noexcept {
                        Finalize();
                    });
                ppp::telemetry::Log(Level::kInfo, "client", "TUN detached");
                VEthernet::Dispose();
            }

            /** @brief Releases objects, packets, and timeout handlers. */
            void VEthernetNetworkSwitcher::Finalize() noexcept {
#if !defined(_ANDROID) && !defined(_IPHONE)
                RestoreAssignedIPv4();
#endif
                ReleaseAllObjects();
                ReleaseAllPackets();
                ReleaseAllTimeouts();
            }

            /** @brief Clears all tracked ICMP packet records. */
            void VEthernetNetworkSwitcher::ReleaseAllPackets() noexcept {
                // Clear all ICMP packet container.
                SynchronizedObjectScope scope(GetSynchronizedObject());
                icmppackets_.clear();
                quic_reject_rate_limits_.clear();
            }

            /** @brief Releases all registered timeout callbacks. */
            void VEthernetNetworkSwitcher::ReleaseAllTimeouts() noexcept {
                TimeoutEventHandlerTable timeouts; {
                    // Clear all ICMP packet container.
                    SynchronizedObjectScope scope(GetSynchronizedObject());
                    timeouts = std::move(timeouts_);
                    timeouts_.clear();
                }

                // Release all timeout callbacks.
                Timer::ReleaseAllTimeouts(timeouts);
            }

#if defined(_ANDROID) || defined(_IPHONE)
            /** @brief Stores bypass IP list text used by mobile route setup. */
            void VEthernetNetworkSwitcher::SetBypassIpList(ppp::string&& bypass_ip_list) noexcept {
                bypass_ip_list_ = std::move(bypass_ip_list);
            }
#endif

            /** @brief Creates QoS controller with configured bandwidth policy. */
            std::shared_ptr<ppp::transmissions::ITransmissionQoS> VEthernetNetworkSwitcher::NewQoS() noexcept {
                int64_t bandwidth = std::max<int64_t>(0, configuration_->client.bandwidth);
                if (bandwidth < 0) {
                    bandwidth *= (1024 >> 3); /* Kbps. */
                }

                std::shared_ptr<boost::asio::io_context> context = GetContext();
                return make_shared_object<ppp::transmissions::ITransmissionQoS>(context, bandwidth);
            }

            /** @brief Creates exchanger instance using configured client GUID. */
            std::shared_ptr<VEthernetExchanger> VEthernetNetworkSwitcher::NewExchanger() noexcept {
                std::shared_ptr<ppp::configurations::AppConfiguration> configuration = GetConfiguration();
                auto guid = StringAuxiliary::GuidStringToInt128(configuration->client.guid);
                if (guid == 0) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionIdInvalid, std::shared_ptr<VEthernetExchanger>(NULLPTR));
                }

                auto my = shared_from_this();
                auto self = std::dynamic_pointer_cast<VEthernetNetworkSwitcher>(my);
                return make_shared_object<VEthernetExchanger>(self, configuration, GetContext(), guid);
            }

            /** @brief Creates HTTP proxy switcher bound to exchanger. */
            VEthernetNetworkSwitcher::VEthernetHttpProxySwitcherPtr VEthernetNetworkSwitcher::NewHttpProxy(const std::shared_ptr<VEthernetExchanger>& exchanger) noexcept {
                if (NULLPTR == exchanger) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionTransportMissing, VEthernetNetworkSwitcher::VEthernetHttpProxySwitcherPtr(NULLPTR));
                }
                else {
                    return make_shared_object<VEthernetHttpProxySwitcher>(exchanger);
                }
            }

            /** @brief Creates SOCKS proxy switcher bound to exchanger. */
            VEthernetNetworkSwitcher::VEthernetSocksProxySwitcherPtr VEthernetNetworkSwitcher::NewSocksProxy(const std::shared_ptr<VEthernetExchanger>& exchanger) noexcept {
                if (NULLPTR == exchanger) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionTransportMissing, VEthernetNetworkSwitcher::VEthernetSocksProxySwitcherPtr(NULLPTR));
                }
                else {
                    return make_shared_object<VEthernetSocksProxySwitcher>(exchanger);
                }
            }

            /** @brief Returns buffer allocator from runtime configuration. */
            std::shared_ptr<ppp::threading::BufferswapAllocator> VEthernetNetworkSwitcher::GetBufferAllocator() noexcept {
                return configuration_->GetBufferAllocator();
            }

            /** @brief Converts UDP payload to IP frame and emits it to local output. */
            boost::asio::ip::address VEthernetNetworkSwitcher::RewriteFakeIpAddress(const boost::asio::ip::address& addr) const noexcept {
                if (!addr.is_v4() || NULLPTR == dns_interceptor_) {
                    return addr;
                }

                const dns::FakeIpPool* pool = dns_interceptor_->GetFakeIpPool();
                if (NULLPTR == pool || !pool->IsEnabled()) {
                    return addr;
                }

                const uint32_t fake_host = addr.to_v4().to_uint();
                const uint32_t real_host = pool->LookupRealIpHostOrder(fake_host);
                if (real_host == 0) {
                    return addr;
                }

                return boost::asio::ip::address_v4(real_host);
            }

            bool VEthernetNetworkSwitcher::DatagramOutput(const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, void* packet, int packet_size, bool caching) noexcept {
                if (NULLPTR == packet || packet_size < 1) {
                    return false;
                }

                if (IsDisposed()) {
                    return false;
                }

                boost::asio::ip::udp::endpoint remoteEP = Ipep::V6ToV4(destinationEP);
                boost::asio::ip::address address = remoteEP.address();
                if (address.is_v4()) {
                    std::shared_ptr<BufferSegment> messages = make_shared_object<BufferSegment>();
                    if (NULLPTR == messages) {
                        return false;
                    }

                    messages->Buffer = wrap_shared_pointer(reinterpret_cast<Byte*>(packet));
                    messages->Length = packet_size;

                    std::shared_ptr<UdpFrame> frame = make_shared_object<UdpFrame>();
                    if (NULLPTR == frame) {
                        return false;
                    }

                    frame->AddressesFamily = AddressFamily::InterNetwork;
                    frame->Source = IPEndPoint::ToEndPoint(remoteEP);
                    frame->Destination = IPEndPoint::ToEndPoint(sourceEP);
                    frame->Payload = messages;

                    if (caching && configuration_->udp.dns.cache) {
                        int destinationPort = destinationEP.port();
                        if (destinationPort == PPP_DNS_SYS_PORT) {
                            ppp::net::asio::vdns::AddCache((Byte*)packet, packet_size);
                        }
                    }

                    std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = GetBufferAllocator();
                    std::shared_ptr<IPFrame> ip = UdpFrame::ToIp(allocator, frame.get());
                    return Output(ip.get());
                }

                return false;
            }

#if !defined(_ANDROID) && !defined(_IPHONE)
            bool VEthernetNetworkSwitcher::ApplyAssignedIPv6(const VirtualEthernetInformationExtensions& extensions) noexcept {
                return address_manager_.ApplyAssignedIPv6(extensions);
            }

            void VEthernetNetworkSwitcher::RestoreAssignedIPv6() noexcept {
                address_manager_.RestoreAssignedIPv6();
            }

            bool VEthernetNetworkSwitcher::ApplyAssignedIPv4(const VirtualEthernetInformationExtensions& extensions) noexcept {
                return address_manager_.ApplyAssignedIPv4(extensions);
            }

            void VEthernetNetworkSwitcher::RestoreAssignedIPv4() noexcept {
                address_manager_.RestoreAssignedIPv4();
            }

#endif

            void VEthernetNetworkSwitcher::ClearPeerPrefixRoutes() noexcept {
#if defined(_WIN32)
                auto mib = ppp::win32::network::Router::GetIpForwardTable();
#endif
                for (const auto& route : applied_peer_prefix_routes_) {
#if defined(_WIN32)
                    if (NULLPTR != mib) {
                        route_table_.DeleteRoute(mib, route.Destination, route.NextHop, route.Prefix);
                    }
#elif !defined(_ANDROID) && !defined(_IPHONE)
                    route_table_.DeleteRoute(route.Destination, route.NextHop, route.Prefix);
#endif
                }
                applied_peer_prefix_routes_.clear();
                if (NULLPTR != peer_prefix_rib_) {
                    peer_prefix_rib_->Clear();
                }
                if (NULLPTR != peer_prefix_fib_) {
                    peer_prefix_fib_->Clear();
                }
                peer_prefix_rib_ = NULLPTR;
                peer_prefix_fib_ = NULLPTR;
            }

            bool VEthernetNetworkSwitcher::ApplyPeerPrefixRoutes(const VirtualEthernetInformationExtensions& extensions) noexcept {
                if (proxy_only_) {
                    return false;
                }

                std::shared_ptr<ppp::tap::ITap> tap = GetTap();
                if (NULLPTR == tap) {
                    return false;
                }

                ClearPeerPrefixRoutes();

                RouteInformationTablePtr rib = make_shared_object<RouteInformationTable>();
                if (NULLPTR == rib) {
                    return false;
                }

                const auto& dynamic_routes = extensions.PeerRouteTable.HasAny()
                    ? extensions.PeerRouteTable.routes
                    : dynamic_peer_routes_;

                auto install_route = [&](const ppp::app::protocol::PeerPrefixRouteEntry& route) -> bool {
                    if (!route.HasVia()) {
                        return false;
                    }

                    if (route.prefix <= 0 || route.prefix > net::native::MAX_PREFIX_VALUE_V4) {
                        return false;
                    }

                    uint32_t network = route.NetworkHost();
                    uint32_t via = route.ViaHost();
                    if (network == 0 || via == 0) {
                        return false;
                    }

                    if (via == tap->IPAddress) {
                        return false;
                    }

#if !defined(_ANDROID) && !defined(_IPHONE)
                    if (!route_table_.AddRoute(network, via, route.prefix)) {
                        return false;
                    }
#endif

                    if (!rib->AddRoute(network, route.prefix, via)) {
#if defined(_WIN32)
                        if (auto mib = ppp::win32::network::Router::GetIpForwardTable(); NULLPTR != mib) {
                            route_table_.DeleteRoute(mib, network, via, route.prefix);
                        }
#elif !defined(_ANDROID) && !defined(_IPHONE)
                        route_table_.DeleteRoute(network, via, route.prefix);
#endif
                        return false;
                    }

                    net::native::RouteEntry entry;
                    entry.Destination = network;
                    entry.Prefix = route.prefix;
                    entry.NextHop = via;
                    applied_peer_prefix_routes_.emplace_back(entry);
                    return true;
                };

                bool any = false;
                if (NULLPTR != configuration_) {
                    for (const auto& route : configuration_->client.peer_routes) {
                        ppp::app::protocol::PeerPrefixRouteEntry entry;
                        entry.network = route.network;
                        entry.prefix = route.prefix;
                        entry.via = route.via;
                        any |= install_route(entry);
                    }
                }

                for (const auto& route : dynamic_routes) {
                    any |= install_route(route);
                }

                if (any) {
                    ForwardInformationTablePtr fib = make_shared_object<ForwardInformationTable>();
                    if (NULLPTR != fib) {
                        fib->Fill(*rib);
                        if (fib->IsAvailable()) {
                            peer_prefix_rib_ = rib;
                            peer_prefix_fib_ = fib;
                        }
                    }

                    ppp::telemetry::Log(Level::kInfo, "client", "peer prefix routes applied: static+dynamic count=%zu",
                        applied_peer_prefix_routes_.size());
                    ppp::telemetry::Count("client.peer_routes.applied", 1);
                }

                return any;
            }

            /** @brief Adapts base information callback to extension-aware overload. */
            bool VEthernetNetworkSwitcher::OnInformation(const std::shared_ptr<VirtualEthernetInformation>& info) noexcept {
                VirtualEthernetInformationExtensions extensions;
                extensions.Clear();
                return OnInformation(info, extensions);
            }

            /** @brief Updates runtime state from server information and extensions. */
            bool VEthernetNetworkSwitcher::OnInformation(const std::shared_ptr<VirtualEthernetInformation>& info, const VirtualEthernetInformationExtensions& extensions) noexcept {
                std::shared_ptr<VEthernetExchanger> exchanger = exchanger_;
                if (NULLPTR == exchanger) {
                    return false;
                }


#if !defined(_ANDROID) && !defined(_IPHONE)
                bool previous_assignment = HasManagedIPv6Assignment(information_extensions_);
                bool current_assignment = HasManagedIPv6Assignment(extensions);
                if (address_manager_.Ipv6Applied() && (!previous_assignment || !current_assignment || !SameManagedIPv6Configuration(information_extensions_, extensions))) {
                    RestoreAssignedIPv6();
                }

                information_extensions_ = extensions;

                if (NULLPTR != dns_interceptor_) {
                    dns_interceptor_->OnSessionInfo(extensions, HasManagedIPv6Assignment(extensions));
                }

                bool valid_ipv6_assignment = HasManagedIPv6Assignment(extensions);
                if (!valid_ipv6_assignment && address_manager_.Ipv6Applied()) {
                    RestoreAssignedIPv6();
                }

                if (valid_ipv6_assignment) {
                    if (!ClientSupportsManagedIPv6()) {
                    }
                    elif (extensions.AssignedIPv6Mode != VirtualEthernetInformationExtensions::IPv6Mode_Nat66 &&
                        extensions.AssignedIPv6Mode != VirtualEthernetInformationExtensions::IPv6Mode_Gua) {
                    }
                    elif (!address_manager_.Ipv6Applied()) {
                        ApplyAssignedIPv6(extensions);
                    }
                }

                // Apply server-assigned IPv4 address to TAP interface.
                {
                    const auto& ipv4 = extensions.ClientIPv4Assign;
                    if (ipv4.enabled && ipv4.accepted) {
                        if (!address_manager_.Ipv4Applied()) {
                            ApplyAssignedIPv4(extensions);
                        }
                    }
                    elif (address_manager_.Ipv4Applied()) {
                        RestoreAssignedIPv4();
                    }
                }
#else
                information_extensions_ = extensions;

                if (NULLPTR != dns_interceptor_) {
                    dns_interceptor_->OnSessionInfo(extensions, HasManagedIPv6Assignment(extensions));
                }
#endif

                // Parse and log IPv4 assignment response from server.
                // The assignment is stored in information_extensions_ (already saved above)
                // and logged here for telemetry.  TAP application of the assigned IPv4
                // address is intentionally deferred to a future phase.
                if (extensions.ClientIPv4Assign.enabled) {
                    const auto& ipv4 = extensions.ClientIPv4Assign;
                    if (ipv4.accepted) {
                        ppp::telemetry::Count("client.ipv4.assigned", 1);
                        ppp::telemetry::Log(Level::kInfo, "client", "ipv4 assigned: %s/%s gw=%s (mode=%s conflict=%d)",
                            ipv4.address.c_str(), ipv4.mask.c_str(), ipv4.gateway.c_str(),
                            ipv4.mode.c_str(), static_cast<int>(ipv4.conflict));
                    }
                    else {
                        ppp::telemetry::Count("client.ipv4.rejected", 1);
                        ppp::telemetry::Log(Level::kInfo, "client", "ipv4 request rejected: reason=%s mode=%s",
                            ipv4.reason.c_str(), ipv4.mode.c_str());
                    }
                }

                if (extensions.P2P.HasAny()) {
                    const auto& p2p = extensions.P2P;
                    ppp::telemetry::Log(Level::kInfo, "p2p", "control action=%s mode=%s peer=%s candidates=%zu reason=%s",
                        p2p.action.c_str(),
                        p2p.mode.c_str(),
                        ppp::net::IPEndPoint::ToAddressString(p2p.peer_virtual_ip).c_str(),
                        p2p.candidates.size(),
                        p2p.reason.c_str());
                    ppp::telemetry::Count("p2p.control", 1);
                }

                if (extensions.PeerRouteTable.HasAny()) {
                    dynamic_peer_routes_ = extensions.PeerRouteTable.routes;
                    ApplyPeerPrefixRoutes(extensions);
                }
                elif (!configuration_->client.peer_routes.empty()) {
                    ApplyPeerPrefixRoutes(extensions);
                }

                std::shared_ptr<ppp::transmissions::ITransmissionQoS> qos = qos_;
                if (NULLPTR != qos) {
                    int64_t bandwidth = static_cast<int64_t>(info->BandwidthQoS) * (1024 >> 3); /* Kbps. */
                    qos->SetBandwidth(bandwidth);
                }

                // If the user still has the remaining incoming/outgoing traffic and the expiration time is not reached,
                // The VPN link is regarded as successful. Otherwise, the VPN link needs to be disconnected.
                if (info->Valid()) {
                    return true;
                }

                // If the VPN link needs to be disconnected, the client requires the active end, and the server forcibly disconnects.
                // This prevents you from bypassing the disconnection problem by modifying the code of the client switch.
                std::shared_ptr<ppp::transmissions::ITransmission> transmission = exchanger->GetTransmission();
                if (NULLPTR != transmission) {
                    transmission->Dispose();
                }

                return false;
            }

#if defined(_WIN32)
            /** @brief Creates Windows PaperAirplane controller bound to exchanger. */
            VEthernetNetworkSwitcher::PaperAirplaneControllerPtr VEthernetNetworkSwitcher::NewPaperAirplaneController() noexcept {
                std::shared_ptr<VEthernetExchanger> exchanger = GetExchanger();
                if (NULLPTR == exchanger) {
                    return NULLPTR;
                }
                else {
                    return make_shared_object<PaperAirplaneController>(exchanger);
                }
            }
#elif defined(_LINUX)
            /** @brief Creates Linux protector network instance for socket protection. */
            VEthernetNetworkSwitcher::ProtectorNetworkPtr VEthernetNetworkSwitcher::NewProtectorNetwork() noexcept {
#if defined(_ANDROID)
                // Embedding the so framework into the Android platform does not use sendfd/recvfd unix to share fd across processes,
                // So you cannot pass in network cards or unix path names.
                ppp::string dev;
                return make_shared_object<ProtectorNetwork>(dev);
#else
                std::shared_ptr<NetworkInterface> ni = GetUnderlyingNetworkInterface();
                if (NULLPTR == ni) {
                    return NULLPTR;
                }

                return make_shared_object<ProtectorNetwork>(ni->Name);
#endif
            }
#endif

            /** @brief Retrieves latest information snapshot from exchanger. */
            std::shared_ptr<VEthernetNetworkSwitcher::VirtualEthernetInformation> VEthernetNetworkSwitcher::GetInformation() noexcept {
                std::shared_ptr<VEthernetExchanger> exchanger = exchanger_;
                if (NULLPTR == exchanger) {
                    return NULLPTR;
                }

                return exchanger->GetInformation();
            }

            /** @brief Creates transmission statistics collector instance. */
            VEthernetNetworkSwitcher::ITransmissionStatisticsPtr VEthernetNetworkSwitcher::NewStatistics() noexcept {
                return make_shared_object<ITransmissionStatistics>();
            }

#if defined(_WIN32)
            /** @brief Builds switcher network-interface snapshot from Windows adapter details. */
            static std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface> Windows_GetNetworkInterface(const ppp::win32::network::AdapterInterfacePtr& ai, const ppp::win32::network::NetworkInterfacePtr& ni) noexcept {
                if (NULLPTR == ai || NULLPTR == ni) {
                    return NULLPTR;
                }

                std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface> result = make_shared_object<VEthernetNetworkSwitcher::NetworkInterface>();
                if (NULLPTR == result) {
                    return NULLPTR;
                }

                boost::system::error_code ec;
                result->Id = ni->Guid;
                result->Index = ai->IfIndex;
                result->Name = ni->ConnectionId;
                result->Description = ni->Description;
                Ipep::StringsTransformToAddresses(ni->DnsAddresses, result->DnsAddresses);

                result->IPAddress = StringToAddress(ai->Address.data(), ec);
                result->SubmaskAddress = StringToAddress(ai->Mask.data(), ec);
                result->GatewayServer = StringToAddress(ai->GatewayServer.data(), ec);
                return result;
            }

            /** @brief Resolves Windows network-interface snapshot by adapter interface. */
            static std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface> Windows_GetNetworkInterface(const ppp::win32::network::AdapterInterfacePtr& ai) noexcept {
                if (NULLPTR == ai) {
                    return NULLPTR;
                }

                auto ni = ppp::win32::network::GetNetworkInterfaceByInterfaceIndex(ai->IfIndex);
                return Windows_GetNetworkInterface(ai, ni);
            }

            /** @brief Gets Windows TAP-side network-interface snapshot. */
            static std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface> Windows_GetTapNetworkInterface(const std::shared_ptr<VEthernetNetworkSwitcher::ITap>& tap) noexcept {
                int interface_index = tap->GetInterfaceIndex();
                if (interface_index == -1) {
                    return NULLPTR;
                }

                ppp::vector<ppp::win32::network::AdapterInterfacePtr> interfaces;
                if (ppp::win32::network::GetAllAdapterInterfaces(interfaces)) {
                    for (auto&& ai : interfaces) {
                        if (ai->IfIndex == interface_index) {
                            return Windows_GetNetworkInterface(ai);
                        }
                    }
                }

                return NULLPTR;
            }

            /** @brief Gets Windows underlying physical network-interface snapshot. */
            static std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface> Windows_GetUnderlyingNetowrkInterface(const std::shared_ptr<VEthernetNetworkSwitcher::ITap>& tap, const ppp::string& nic) noexcept {
                auto [ai, ni] = ppp::win32::network::GetUnderlyingNetowrkInterface2(tap->GetId(), nic);
                return Windows_GetNetworkInterface(ai, ni);
            }
#elif !defined(_ANDROID) && !defined(_IPHONE)
            class UnixNetworkInterface final : public VEthernetNetworkSwitcher::NetworkInterface {
            public:
                ppp::string DnsResolveConfiguration;

            public:
                /** @brief Restores Unix DNS resolver configuration from captured state. */
                static bool SetDnsResolveConfiguration(const std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface>& underlying_ni) noexcept {
                    if (NULLPTR == underlying_ni) {
                        return false;
                    }

                    UnixNetworkInterface* ni = dynamic_cast<UnixNetworkInterface*>(underlying_ni.get());
                    if (NULLPTR == ni) {
                        return false;
                    }

                    return ppp::unix__::UnixAfx::SetDnsResolveConfiguration(ni->DnsResolveConfiguration);
                }
            };

            /** @brief Gets Unix TAP/TUN-side network-interface snapshot. */
            static std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface> Unix_GetTapNetworkInterface(const std::shared_ptr<VEthernetNetworkSwitcher::ITap>& tap) noexcept {
                int interface_index = tap->GetInterfaceIndex();
                if (interface_index == -1) {
                    return NULLPTR;
                }

                int dev_handle = (int)reinterpret_cast<std::intptr_t>(tap->GetHandle());
                if (dev_handle == -1) {
                    return NULLPTR;
                }

                ppp::string interface_name;
#if defined(_MACOS)
                if (!ppp::darwin::tun::utun_get_if_name(dev_handle, interface_name)) {
                    return NULLPTR;
                }
#else
                if (!ppp::tap::TapLinux::GetInterfaceName(dev_handle, interface_name)) {
                    return NULLPTR;
                }
#endif

                std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface> ni = make_shared_object<VEthernetNetworkSwitcher::NetworkInterface>();
                if (NULLPTR == ni) {
                    return NULLPTR;
                }

                ni->Index = interface_index;
                ni->Name = interface_name;
                ni->GatewayServer = IPEndPoint::ToEndPoint<boost::asio::ip::tcp>(IPEndPoint(tap->GatewayServer, IPEndPoint::MinPort)).address();
                ni->IPAddress = IPEndPoint::ToEndPoint<boost::asio::ip::tcp>(IPEndPoint(tap->IPAddress, IPEndPoint::MinPort)).address();
                ni->SubmaskAddress = IPEndPoint::ToEndPoint<boost::asio::ip::tcp>(IPEndPoint(tap->SubmaskAddress, IPEndPoint::MinPort)).address();

#if defined(_MACOS)
                ppp::tap::TapDarwin* darwin_tap = dynamic_cast<ppp::tap::TapDarwin*>(tap.get());
                if (NULLPTR != darwin_tap) {
                    ni->DnsAddresses = darwin_tap->GetDnsAddresses();
                }
#else
                ppp::tap::TapLinux* linux_tap = dynamic_cast<ppp::tap::TapLinux*>(tap.get());
                ni->Id = ppp::tap::TapLinux::GetDeviceId(interface_name);

                if (NULLPTR != linux_tap) {
                    ni->DnsAddresses = linux_tap->GetDnsAddresses();
                }
#endif
                return ni;
            }

            /** @brief Gets Unix underlying physical network-interface snapshot. */
            static std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface> Unix_GetUnderlyingNetowrkInterface(const std::shared_ptr<VEthernetNetworkSwitcher::ITap>& tap, const ppp::string& nic) noexcept {
                std::shared_ptr<UnixNetworkInterface> ni = make_shared_object<UnixNetworkInterface>();
                if (NULLPTR == ni) {
                    return NULLPTR;
                }

#if defined(_MACOS)
                using NetworkInterface = ppp::tap::TapDarwin::NetworkInterface;

                ppp::vector<NetworkInterface::Ptr> network_interfaces;
                if (!ppp::tap::TapDarwin::GetAllNetworkInterfaces(network_interfaces)) {
                    return NULLPTR;
                }

                NetworkInterface::Ptr network_interface = ppp::tap::TapDarwin::GetPreferredNetworkInterface2(network_interfaces, nic);
                if (NULLPTR == network_interface) {
                    return NULLPTR;
                }

                ni->Index = network_interface->Index;
                ni->Name = network_interface->Name;

                struct {
                    boost::asio::ip::address* address;
                    ppp::string* address_string;
                } addresses[] = {{&ni->GatewayServer, &network_interface->GatewayServer},
                    {&ni->IPAddress, &network_interface->IPAddress}, {&ni->SubmaskAddress, &network_interface->SubnetmaskAddress}};

                for (int i = 0; i < arraysizeof(addresses); i++) {
                    auto& r = addresses[i];
                    ppp::string* address_string = r.address_string;
                    if (address_string->empty()) {
                        continue;
                    }

                    boost::system::error_code ec;
                    *r.address = StringToAddress(address_string->data(), ec);
                    if (ec) {
                        return NULLPTR;
                    }
                }

                ni->DefaultRoutes = std::move(network_interface->GatewayAddresses);
#else
                ppp::string interface_name;
                ppp::UInt32 ip, gw, mask;
                if (!ppp::tap::TapLinux::GetPreferredNetworkInterface(interface_name, ip, mask, gw, nic)) {
                    return NULLPTR;
                }

                ni->Id = ppp::tap::TapLinux::GetDeviceId(interface_name);
                ni->Index = ppp::tap::TapLinux::GetInterfaceIndex(interface_name);
                ni->Name = interface_name;
                ni->GatewayServer = IPEndPoint::ToEndPoint<boost::asio::ip::tcp>(IPEndPoint(gw, IPEndPoint::MinPort)).address();
                ni->IPAddress = IPEndPoint::ToEndPoint<boost::asio::ip::tcp>(IPEndPoint(ip, IPEndPoint::MinPort)).address();
                ni->SubmaskAddress = IPEndPoint::ToEndPoint<boost::asio::ip::tcp>(IPEndPoint(mask, IPEndPoint::MinPort)).address();
#endif

                ni->DnsResolveConfiguration = ppp::unix__::UnixAfx::GetDnsResolveConfiguration();
                ppp::unix__::UnixAfx::GetDnsAddresses(ni->DnsResolveConfiguration, ni->DnsAddresses);
                return ni;
            }
#endif

            /** @brief Enables or disables outbound QUIC blocking policy. */
            bool VEthernetNetworkSwitcher::BlockQUIC(bool value) noexcept {
                // Set the status of the current VPN client switcher that needs to block QUIC traffic flags.
                block_quic_ = value;
                return true;
            }

#if defined(_WIN32)
            /** @brief Applies local HTTP proxy endpoint to Windows system settings. */
            bool VEthernetNetworkSwitcher::SetHttpProxyToSystemEnv() noexcept {
                // Windows platform uses the system's Internet function library to set the system HTTP proxy environment.
                auto http_proxy = GetHttpProxy();
                if (NULLPTR == http_proxy) {
                    return ClearHttpProxyToSystemEnv();
                }

                boost::asio::ip::tcp::endpoint localEP = http_proxy->GetLocalEndPoint();
                int localPort = localEP.port();
                if (localPort <= IPEndPoint::MinPort || localPort > IPEndPoint::MaxPort) {
                    return ClearHttpProxyToSystemEnv();
                }

                boost::asio::ip::address localIP = localEP.address();
                if (IPEndPoint::IsInvalid(localIP)) {
                    localIP = boost::asio::ip::address_v4::loopback();
                }

                ppp::string server = ppp::net::Ipep::ToAddressString<ppp::string>(localIP) + ":" + stl::to_string<ppp::string>(localPort);
                ppp::string pac;
                bool bok = ppp::net::proxies::HttpProxy::SetSystemProxy(server, pac, true) &&
                    ppp::net::proxies::HttpProxy::SetSystemProxy(server) &&
                    ppp::net::proxies::HttpProxy::RefreshSystemProxy();
                if (!bok) {
                    return ClearHttpProxyToSystemEnv();
                }

                return bok;
            }

            /** @brief Clears Windows system HTTP proxy settings managed by switcher. */
            bool VEthernetNetworkSwitcher::ClearHttpProxyToSystemEnv() noexcept {
                // Windows platform uses the system's Internet function library to clear the system HTTP proxy environment.
                ppp::string server;
                ppp::string pac;
                return ppp::net::proxies::HttpProxy::SetSystemProxy(server, pac, false);
            }
#endif

#if defined(_ANDROID) || defined(_IPHONE)
            /** @brief Builds mobile-side route table including bypass and DNS exceptions. */
            bool VEthernetNetworkSwitcher::AddAllRoute(const std::shared_ptr<ITap>& tap) noexcept {
                if (!route_table_.AddAllRoute(tap)) {
                    return false;
                }

                return AddRemoteEndPointToIPList(Ipep::ToAddress(IPEndPoint::LoopbackAddress));
            }
#endif

            /** @brief Creates and configures static-mode aggligator instance. */
            bool VEthernetNetworkSwitcher::PreparedAggregator() noexcept {
                std::shared_ptr<boost::asio::io_context> context = ppp::threading::Executors::GetDefault();
                if (NULLPTR == context) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RuntimeIoContextMissing);
                }

                std::shared_ptr<Byte> buffer = ppp::threading::Executors::GetCachedBuffer(context);
                if (NULLPTR == buffer) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryBufferNull);
                }

                std::shared_ptr<aggligator::aggligator> aggligator =
                    make_shared_object<aggligator::aggligator>(*context, buffer, PPP_BUFFER_SIZE, PPP_AGGLIGATOR_CONGESTIONS);
                if (NULLPTR == aggligator) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                }

                aggligator_ = aggligator;
#if defined(_LINUX)
                aggligator->ProtectorNetwork = GetProtectorNetwork();
#endif
                aggligator->AppConfiguration = configuration_;
                aggligator->BufferswapAllocator = configuration_->GetBufferAllocator();
                return true;
            }

            /** @brief Initializes switcher runtime components and opens all services. */
            bool VEthernetNetworkSwitcher::Open(const std::shared_ptr<ITap>& tap) noexcept {
                ppp::telemetry::SpanScope span("client.connect");
                struct ScopedConnectHistogram final {
                    std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();

                    ~ScopedConnectHistogram() noexcept {
                        int64_t elapsed = static_cast<int64_t>(std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start).count());
                        ppp::telemetry::Histogram("client.connect.us", elapsed);
                    }
                } connect_histogram;

#if !defined(_ANDROID) && !defined(_IPHONE)
                if (!proxy_only_) {
#if defined(_WIN32)
                underlying_ni_ = Windows_GetUnderlyingNetowrkInterface(tap, preferred_nic_);
#else
                underlying_ni_ = Unix_GetUnderlyingNetowrkInterface(tap, preferred_nic_);
#endif

                if (auto underlying_ni = underlying_ni_; NULLPTR != underlying_ni) {
                    boost::asio::ip::address& ngw = preferred_ngw_;
                    if (!IPEndPoint::IsInvalid(ngw)) {
                        underlying_ni->GatewayServer = ngw;
                    }
                }
                else {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkInterfaceUnavailable);
                }

                FixUnderlyingNgw();
                }
#endif
                // Construction of VEtherent virtual Ethernet switcher processing framework.
                /** @brief Creates base VEthernet framework before higher-level services. */
                if (!VEthernet::Open(tap)) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionOpenFailed);
                }

                ppp::net::asio::vdns::ClearCache();

                ppp::telemetry::Log(Level::kInfo, "client", proxy_only_ ? "proxy-only session starting" : "TUN attached");
                ppp::telemetry::Count(proxy_only_ ? "client.proxy.attach" : "client.tun.attach", 1);

#if !defined(_ANDROID) && !defined(_IPHONE)
                if (!proxy_only_) {
#if defined(_WIN32)
                tun_ni_ = Windows_GetTapNetworkInterface(tap);
#else
                tun_ni_ = Unix_GetTapNetworkInterface(tap);
#endif

                if (NULLPTR == tun_ni_) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TunnelDeviceMissing);
                }
                }
#endif

                // Initial a new network statistics.
                statistics_ = NewStatistics();

                // Instantiate the local QoS throughput speed control module!
                std::shared_ptr<ppp::transmissions::ITransmissionQoS> qos = NewQoS();
                if (NULLPTR == qos) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RuntimeInitializationFailed);
                }

#if defined(_LINUX)
                ProtectorNetworkPtr protector_network;
#if defined(_ANDROID)
                protector_network = NewProtectorNetwork();
                if (NULLPTR == protector_network) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TunnelProtectionConfigureFailed);
                }
#else
                if (!proxy_only_ && protect_mode_) {
                    protector_network = NewProtectorNetwork();
                }
#endif
#endif
                // Instantiate and open the internal virtual Ethernet switch that needs to be switcher to the remote.
                std::shared_ptr<VEthernetExchanger> exchanger = NewExchanger();
                if (NULLPTR == exchanger) {
                    return false;
                }
                elif(!exchanger->Open()) {
                    IDisposable::DisposeReferences(qos, exchanger);
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionOpenFailed);
                }

                // Enable the local HTTP PROXY server middleware to provide proxy services directly by the VPN.
                VEthernetHttpProxySwitcherPtr http_proxy = NewHttpProxy(exchanger);
                if (NULLPTR == http_proxy) {
                    return false;
                }
                elif(http_proxy->Open()) {
                    http_proxy_ = std::move(http_proxy);
                }
                else {
                    http_proxy->Dispose();
                    http_proxy.reset();
                }

                // Enable the local SOCKS PROXY server middleware to provide proxy services directly by the VPN.
                VEthernetSocksProxySwitcherPtr socks_proxy = NewSocksProxy(exchanger);
                if (NULLPTR == socks_proxy) {
                    return false;
                }
                elif(socks_proxy->Open()) {
                    socks_proxy_ = std::move(socks_proxy);
                }
                else {
                    socks_proxy->Dispose();
                    socks_proxy.reset();
                }

                // Mounts the various service objects created and opened by the current constructor.
                qos_             = std::move(qos);
                exchanger_       = std::move(exchanger);

#if defined(_LINUX)
                protect_network_ = std::move(protector_network);
#endif

                if (proxy_only_) {
                    if (NULLPTR == http_proxy_ && NULLPTR == socks_proxy_) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SocketBindFailed);
                    }

                    ppp::telemetry::Log(Level::kInfo, "client", "proxy-only connected");
                    ppp::telemetry::Count("client.proxy.connect", 1);
                    return true;
                }

                if (NULLPTR != dns_interceptor_) {
                    dns_interceptor_->Open(
                        configuration_,
                        GetContext(),
                        proxy_only_
#if defined(_LINUX)
                        , protect_network_
#endif
                    );
                }

                // New the beast network bandwidth aggregator.
                if (static_mode_ && configuration_->udp.static_.aggligator > 0) {
                    if (!PreparedAggregator()) {
                        return false;
                    }
                }

#if defined(_ANDROID) || defined(_IPHONE)
                if (!proxy_only_ && !AddAllRoute(tap)) {
                    IDisposable::DisposeReferences(qos, exchanger, http_proxy);
                    return false;
                }
#else
                // Load all IPList route table configuration files that need to be loaded.
                if (auto underlying_ni = underlying_ni_; NULLPTR != underlying_ni) {
                    LoadAllIPListWithFilePaths(underlying_ni->GatewayServer);

                    // Add VPN remote server to IPList bypass route table iplist.
                    if (!AddRemoteEndPointToIPList(underlying_ni->GatewayServer)) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RouteAddFailed);
                    }
                }
#endif

                // Attempt to load the routing table configuration if the routing table is configured correctly.
                if (RouteInformationTablePtr rib = rib_; NULLPTR != rib) {
                    ForwardInformationTablePtr fib = make_shared_object<ForwardInformationTable>();
                    if (NULLPTR != fib) {
                        fib->Fill(*rib);

                        if (fib->IsAvailable()) {
                            fib_ = fib;
                        }
                    }
                }

#if !defined(_ANDROID) && !defined(_IPHONE)
                route_apply_ready_ = true;
                if (!TryApplyHostedNetworkRoutes()) {
                    return false;
                }
#endif
                ppp::telemetry::Log(Level::kInfo, "client", "client connected");
                ppp::telemetry::Count("client.connect", 1);
                return true;
            }

#if defined(_WIN32)
            /** @brief Starts optional PaperAirplane helper service on Windows. */
            bool VEthernetNetworkSwitcher::UsePaperAirplaneController() noexcept {
                // Open the [PaperAirplane NSP/LSP] paper airplane server controller,
                // Depending on the configuration and whether it is a CLI command line hosted network flag.
                if (configuration_->client.paper_airplane.tcp) {
                    PaperAirplaneControllerPtr controller = NewPaperAirplaneController();
                    if (NULLPTR == controller) {
                        return false;
                    }

                    // Clean up resources constructed by the current function when opening the server side of the paper plane fails.
                    auto tun_ni = tun_ni_;
                    if (NULLPTR != tun_ni) {
                        auto tap = GetTap();
                        if (NULLPTR != tap) {
                            if (!controller->Open(tun_ni->Index, tap->IPAddress, tap->SubmaskAddress)) {
                                IDisposable::DisposeReferences(controller);
                                return false;
                            }
                        }
                    }

                    // Open the paper plane successfully when you move the created instance on the local variable to
                    // The virtual ethernet switch hosted fields.
                    paper_airplane_ctrl_ = std::move(controller);
                }
                return true;
            }
#endif

#if !defined(_ANDROID) && !defined(_IPHONE)
            /** @brief Attempts to restore default route on underlying physical NIC. */
            bool VEthernetNetworkSwitcher::FixUnderlyingNgw() noexcept {
                auto ni = underlying_ni_;
                if (NULLPTR == ni) {
                    return false;
                }

                auto gw = ni->GatewayServer;
                if (gw.is_v4() && !IPEndPoint::IsInvalid(gw) && !gw.is_loopback()) {
                    uint32_t next_hop = htonl(gw.to_v4().to_uint());
#if defined(_WIN32)
                    // Repair physical ethernet route table information on windows platform!
                    ppp::win32::network::Router::Add(IPEndPoint::AnyAddress, IPEndPoint::AnyAddress, next_hop, 1);
#elif defined(_MACOS)
                    ppp::darwin::tun::utun_add_route2(IPEndPoint::AnyAddress, IPEndPoint::AnyAddress, next_hop);
#else
                    // Repair physical ethernet route table information on linux platform!
                    ppp::tap::TapLinux::AddRoute(ni->Name, IPEndPoint::AnyAddress, IPEndPoint::AnyAddress, next_hop);
#endif
                    return true;
                }

                return false;
            }

            /** @brief Removes VPN route entries and restores system defaults. */
            void VEthernetNetworkSwitcher::DeleteRoute() noexcept {
                ClearPeerPrefixRoutes();
                route_table_.DeleteRoute();
                FixUnderlyingNgw();
                route_table_.DeleteRouteWithDnsServers();
            }

            /** @brief Returns formatted cached remote URI string. */
            ppp::string VEthernetNetworkSwitcher::GetRemoteUri() noexcept {
                return server_ru_;
            }

            /** @brief Sets preferred physical NIC hint for route operations. */
            void VEthernetNetworkSwitcher::PreferredNic(const ppp::string& nic) noexcept {
                preferred_nic_ = nic;
            }

            /** @brief Sets preferred physical gateway hint for route operations. */
            void VEthernetNetworkSwitcher::PreferredNgw(const boost::asio::ip::address& gw) noexcept {
                preferred_ngw_ = gw;
            }

            /** @brief Registers IP-list file or URL source for later route loading. */
            bool VEthernetNetworkSwitcher::AddLoadIPList(
                const ppp::string&                                              path,
#if defined(_LINUX)
                const ppp::string&                                              nic,
#endif
                const boost::asio::ip::address&                                 gw,
                const ppp::string&                                              url) noexcept {

                using File = ppp::io::File;

                if (path.empty()) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FilePathInvalid);
                }

                ppp::string fullpath = File::RewritePath(path.data());
                if (fullpath.empty()) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FilePathInvalid);
                }

                fullpath = File::GetFullPath(path.data());
                if (fullpath.empty()) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FilePathInvalid);
                }

                bool vbgp_url = ppp::net::http::HttpClient::VerifyUri(url, NULLPTR, NULLPTR, NULLPTR, NULLPTR);
                if (!vbgp_url && !File::Exists(fullpath.data())) {
                    if (ppp::diagnostics::ErrorCode::FileNotFound == ppp::diagnostics::GetLastErrorCode()) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RouteListFileNotFound);
                    }

                    if (ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ConfigRouteLoadFailed);
                    }

                    return false;
                }

                uint32_t ngw = IPEndPoint::AnyAddress;
                if (
#if defined(_LINUX)
                    !nic.empty() &&
#endif
                    gw.is_v4() && !IPEndPoint::IsInvalid(gw)) {
                    ngw = htonl(gw.to_v4().to_uint());
                }

                LoadIPListFileVectorPtr ribs = ribs_;
                if (NULLPTR == ribs) {
                    ribs = make_shared_object<LoadIPListFileVector>();
                    ribs_ = ribs;
                }

                if (NULLPTR == ribs) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                }
                else {
                    auto tail = std::find_if(ribs->begin(), ribs->end(),
                        [&fullpath](const std::pair<ppp::string, uint32_t>& i) noexcept {
                            return i.first == fullpath;
                        });
                    if (tail != ribs->end()) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RouteListRegistrationDuplicate);
                    }
                }

                if (vbgp_url) {
                    RouteIPListTablePtr vbgp = vbgp_;
                    if (NULLPTR == vbgp)  {
                        vbgp = make_shared_object<RouteIPListTable>();
                        if (NULLPTR == vbgp) {
                            return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::VbgpRouteTableAllocFailed);
                        }

                        vbgp_ = vbgp;
                    }

                    vbgp->emplace(std::make_pair(fullpath, url));
                }

#if defined(_LINUX)
                if (ngw != IPEndPoint::AnyAddress) {
                    nics_.emplace(std::make_pair(ngw, nic));
                }
#endif

                ribs->emplace_back(std::make_pair(fullpath, ngw));
                return true;
            }

            /** @brief Loads all registered IP-list files into route information table. */
            bool VEthernetNetworkSwitcher::LoadAllIPListWithFilePaths(const boost::asio::ip::address& gw) noexcept {
                rib_ = NULLPTR;
                fib_ = NULLPTR;

                // Load all the route table iplist configuration files that need to be loaded.
                bool any = false;
                if (gw.is_v4()) {
                    // Obtain the numerical address of the next hop in the IP route table, which is a function implementation of the bypass-iplist.
                    boost::asio::ip::address_v4 in = gw.to_v4();
                    if (uint32_t next_hop = htonl(in.to_uint()); !IPEndPoint::IsInvalid(in)) {
                        if (LoadIPListFileVectorPtr ribs = std::move(ribs_); NULLPTR != ribs) {
                            // Loop in all iplist route table configuration files.
                            RouteInformationTablePtr rib = make_shared_object<RouteInformationTable>();
                            if (NULLPTR != rib) {
                                for (auto&& kv : *ribs) {
                                    const ppp::string& path = kv.first;
                                    const uint32_t ngw = kv.second != IPEndPoint::AnyAddress ? kv.second : next_hop;
                                    any |= rib->AddAllRoutesByIPList(path, ngw);
                                }

                                // Loading is considered valid only if any route is added.
                                if (any) {
                                    rib_ = rib;
                                    ppp::telemetry::Log(Level::kDebug, "client", "bypass list updated");
                                }
                            }
                        }
                    }
                }

                // A value filled once can only be used once and then reset.
                ribs_.reset();
                return any;
            }

#endif

            /** @brief Checks whether destination IP should bypass VPN forwarding path. */
            bool VEthernetNetworkSwitcher::IsBypassIpAddress(const boost::asio::ip::address& ip) noexcept {
                if (!ip.is_v4()) {
                    return false;
                }

                if (ip.is_unspecified()) {
                    return false;
                }

                if (ip.is_multicast()) {
                    return false;
                }

                if (ppp::net::IPEndPoint::IsInvalid(ip)) {
                    return false;
                }

                auto tap = GetTap();
                if (NULLPTR == tap) {
                    return false;
                }

                uint32_t nip = htonl(ip.to_v4().to_uint());
#if defined(_ANDROID) || defined(_IPHONE)
                // Use the mobile RIB/FIB built from bypass_ip_list (private LAN, geo CN, DNS, server).
                // Default: only listed CIDRs bypass the tunnel; everything else goes through VPN.
                if (auto fib = fib_; NULLPTR != fib) {
                    uint32_t ngw = fib->GetNextHop(nip);
                    return ngw != tap->GatewayServer;
                }

                return false;
#elif defined(_WIN32)
                DWORD dwInterfaceIndex;
                if (!::GetBestInterface((IPAddr)nip, &dwInterfaceIndex)) {
                    return false;
                }

                return dwInterfaceIndex != (DWORD)tap->GetInterfaceIndex();
#else
                // OS X provides basic routing table processing so that the HTTP proxy provided by the VPN can route
                // The traffic instead of having to deliver it to the VPN server for processing.
                //
                // It is only supported when the VPN opens the network card promisbity mode,
                // Which is to support the PC only a single network card can provide a reliable VPN virtual network
                // For the local area network through the kernel SNAT mechanism.
                //
                // Note: Google Android and Huawei HarmonyOS platforms (the VPN network adapter promiscuous mode must be enabled)
                // Snat: iptables -t nat -I POSTROUTING -s 192.168.0.24 -j SNAT --to-source 10.0.0.2
                return ppp::net::Socket::GetBestInterfaceIP(nip) != tap->IPAddress;
#endif
            }

            /** @brief Releases all runtime services, routes, and related resources. */
            void VEthernetNetworkSwitcher::ReleaseAllObjects() noexcept {
                ppp::telemetry::Log(Level::kInfo, "client", "client disconnected");
                ppp::telemetry::Count("client.disconnect", 1);

#if !defined(_ANDROID) && !defined(_IPHONE)
                // Windows platform needs to set the prdr synchronization lock state to prevent the problem of multi-thread concurrent competition.
                SynchronizedObjectScope scope(prdr_);
#endif

                // Clear event bindings.
                TickEvent = NULLPTR;

                // Stop and release the http-proxy service.
                if (VEthernetHttpProxySwitcherPtr http_proxy = std::move(http_proxy_); NULLPTR != http_proxy) {
                    http_proxy->Dispose();
                }

                // Stop and release the socks-proxy service.
                if (VEthernetSocksProxySwitcherPtr socks_proxy = std::move(socks_proxy_); NULLPTR != socks_proxy) {
                    socks_proxy->Dispose();
                }

                // Close and release the exchanger.
                if (std::shared_ptr<VEthernetExchanger> exchanger = std::move(exchanger_); NULLPTR != exchanger) {
                    exchanger->Dispose();
                }

                // Shutdown and release the qos control module.
                if (std::shared_ptr<ppp::transmissions::ITransmissionQoS> qos = std::move(qos_);  NULLPTR != qos) {
                    qos->Dispose();
                }

                // Close and release the aggligator.
                if (std::shared_ptr<aggligator::aggligator> aggligator = std::move(aggligator_); NULLPTR != aggligator) {
                    aggligator->close();
                }

                // Close and release the forwarding.
                if (IForwardingPtr forwarding = std::move(forwarding_); NULLPTR != forwarding) {
                    forwarding->Dispose();
                }

                if (NULLPTR != dns_interceptor_) {
                    dns_interceptor_->Close();
                }

#if defined(_WIN32)
                // On Windows platforms, you need to try to turn off the [PaperAirplane NSP/LSP] server-side controller.
                if (PaperAirplaneControllerPtr controller = std::move(paper_airplane_ctrl_);  NULLPTR != controller) {
                    controller->Dispose();
                }
#endif

#if !defined(_ANDROID) && !defined(_IPHONE)
                RestoreAssignedIPv6();
                route_apply_ready_ = false;

                // Delete VPN route table information configured in the operating system!
                if (exchangeof(route_added_, false)) {
                    // Delete routes entries configured by the VPN program from the operating system.
                    DeleteRoute();

#if defined(_WIN32)
                    ppp::telemetry::Log(Level::kDebug, "client", "DNS teardown");
                    // Restore all dns servers addresses that have been configured when VPN routes are enabled.
                    ppp::win32::network::SetAllNicsDnsAddresses(ni_dns_servers_);

                    // Windows clients need to request the operating system FLUSH to reset all DNS query cache immediately after
                    // The VPN is constructed, because the original DNS cache may not be the best destination IP resolution record
                    // Available in the region where the VPN server is located.
                    ppp::tap::TapWindows::DnsFlushResolverCache();
#else
                    ppp::telemetry::Log(Level::kDebug, "client", "DNS teardown");
                    // Restore the original linux /etc/resolve.conf to linux operating system configuration files.
                    UnixNetworkInterface::SetDnsResolveConfiguration(GetUnderlyingNetworkInterface());
#endif
                }

                ClearPeerPrefixRoutes();

                // To clean up the managed and unmanaged data currently held by the class,
                // You need to go through the complete construct fill process again after the Release of this function.
                ribs_.reset();
                tun_ni_.reset();
                underlying_ni_.reset();

                // Clear the reference pointers of the held vBGP without making specific clarification, as this may pose thread safety issues.
                vbgp_ = NULLPTR;

#if !defined(_MACOS)
                // Clear the routing table, forwarding table, and DNS server list of the network card, including cache.
                rib_ = NULLPTR;
                fib_ = NULLPTR;
#endif

                // Clear all route tables and forwarding tables held by the current object.
                LoadAllIPListWithFilePaths(boost::asio::ip::address_v4::any());
#endif

#if defined(_LINUX)
                // Release the network protector held by the current VPN local client switcher.
                if (auto protector = std::move(protect_network_); NULLPTR != protector) {
                    // In android platform you need to request the DetachJNI function of the network protector.
#if defined(_ANDROID)
                    protector->DetachJNI();
#endif
                }
#endif
            }

            /** @brief Removes timeout callback associated with a key. */
            bool VEthernetNetworkSwitcher::DeleteTimeout(void* k) noexcept {
                if (NULLPTR == k) {
                    return false;
                }

                SynchronizedObjectScope scope(GetSynchronizedObject());
                return Dictionary::RemoveValueByKey(timeouts_, k);
            }

            /** @brief Registers timeout callback associated with a key. */
            bool VEthernetNetworkSwitcher::EmplaceTimeout(void* k, const std::shared_ptr<ppp::threading::Timer::TimeoutEventHandler>& timeout) noexcept {
                if (NULLPTR == k || NULLPTR == timeout) {
                    return false;
                }

                SynchronizedObjectScope scope(GetSynchronizedObject());
                auto r = timeouts_.emplace(k, timeout);
                return r.second;
            }

            /** @brief Loads DNS redirect rules from file or inline content. */
            bool VEthernetNetworkSwitcher::LoadAllDnsRules(const ppp::string& rules, bool load_file_or_string) noexcept {
                if (rules.empty()) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::VEthernetNetworkSwitcherDnsRulesEmpty);
                }

                int events = 0;
                if (NULLPTR != dns_interceptor_) {
                    events = dns_interceptor_->LoadRules(rules, load_file_or_string);
                }

                if (1 > events) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ConfigDnsRuleLoadFailed);
                }

                return true;
            }

            /** @brief Adds remote endpoints and static servers to route/bypass tables. */
            bool VEthernetNetworkSwitcher::AddRemoteEndPointToIPList(const boost::asio::ip::address& gw) noexcept {
                using ProtocolType = VEthernetExchanger::ProtocolType;

                // This function must be executed after the remote exchanger object has been created.
                std::shared_ptr<VEthernetExchanger> exchanger = exchanger_;
                if (NULLPTR == exchanger) {
                    return false;
                }

                // Initialize and try the proxy forwarding object if the link does require proxy forwarding services.
                IForwardingPtr forwarding = make_shared_object<IForwarding>(GetContext(), configuration_);
                if (NULLPTR == forwarding) {
                    return false;
                }
                elif(forwarding->Open()) {
                    forwarding_ = forwarding;
#if defined(_LINUX)
                    forwarding->ProtectorNetwork = GetProtectorNetwork();
#endif
                }
                else {
                    forwarding->Dispose();
                    forwarding.reset();
                }

                boost::asio::ip::tcp::endpoint remoteEP;
                ppp::string hostname;
                ppp::string address;
                ppp::string path;
                ppp::string server;
                int port;
                ProtocolType protocol_type = ProtocolType::ProtocolType_PPP;

                // Obtaining the IP endpoint address of the VPN remote server may involve synchronizing the network, as it may be in domain-name format.
                static constexpr ppp::coroutines::YieldContext* y = NULLPTR;

                if (!exchanger->GetRemoteEndPoint(y, hostname, address, path, port, protocol_type, server, remoteEP)) {
                    return false;
                }
                else {
                    server_ru_ = "[";
                    server_ru_ += hostname;
                    server_ru_ += "]";
                    server_ru_ += ":";
                    server_ru_ += stl::to_string<ppp::string>(NULLPTR != forwarding ? forwarding->GetRemotePort() : port);
                    server_ru_ += "/";

                    if (protocol_type == ProtocolType::ProtocolType_Http || protocol_type == ProtocolType::ProtocolType_WebSocket) {
                        server_ru_ += "ppp+ws";
                    }
                    elif(protocol_type == ProtocolType::ProtocolType_HttpSSL || protocol_type == ProtocolType::ProtocolType_WebSocketSSL) {
                        server_ru_ += "ppp+wss";
                    }
                    else {
                        server_ru_ += "ppp+tcp";
                    }

                    if (NULLPTR != forwarding) {
                        remoteEP = forwarding->GetProxyEndPoint();
                    }
                }

                // Add the default IP address of the vpn virtual network adapter to the RIB route table.
                RouteInformationTablePtr rib = rib_;
                if (NULLPTR == rib) {
                    rib = make_shared_object<RouteInformationTable>();
                    rib_ = rib;
                }

                // CIDR: 0.0.0.0/0; 0.0.0.0/1; 128.0.0.0/1
                if (NULLPTR != rib) {
                    if (auto tap = GetTap(); NULLPTR != tap) {
                        rib->AddRoute(IPEndPoint::AnyAddress, 0, tap->GatewayServer);
                        rib->AddRoute(IPEndPoint::AnyAddress, 1, tap->GatewayServer);
                        rib->AddRoute(inet_addr("128.0.0.0"), 1, tap->GatewayServer);
                    }
                }

                // Note that we only need to set IPV4 routes, not IPV6 routes.
                boost::asio::ip::address remoteIP = remoteEP.address();
                IPEndPoint serverEP = IPEndPoint::ToEndPoint(remoteEP);
                if (IPEndPoint::IsInvalid(serverEP)) {
                    return false;
                }

                // Add IPV4 route table settings.
                auto fib_add_route_ipv4 =
                    [&rib, &gw](const boost::asio::ip::address& remoteIP) noexcept {
                        if (remoteIP.is_v6()) {
                            return true;
                        }

                        if (NULLPTR == rib) {
                            return false;
                        }

                        bool processed = gw.is_v4() && remoteIP.is_v4();
                        if (!processed) {
                            return false;
                        }

                        // First convert the IP addresses of both.
                        uint32_t ip = htonl(remoteIP.to_v4().to_uint());
                        uint32_t nx = htonl(gw.to_v4().to_uint());

                        // Add route information to rib!
                        return rib->AddRoute(ip, 32, nx);
                    };

                // Check whether the static tunnel specifies an IP address endpoint (required for transit).
                ppp::unordered_set<boost::asio::ip::tcp::endpoint> servers;
                /** @brief Parses and registers one static tunnel server endpoint. */
                auto StaticEchoAddRemoteEndPoint =
                    [this, &servers, &fib_add_route_ipv4, &exchanger](const ppp::string& server_string) noexcept {
                        if (server_string.empty()) {
                            return false;
                        }

                        ppp::string host_string;
                        int port;

                        if (!ppp::net::Ipep::ParseEndPoint(server_string, host_string, port)) {
                            return false;
                        }

                        if (port <= IPEndPoint::MinPort || port > IPEndPoint::MaxPort) {
                            return false;
                        }

                        IPEndPoint remoteEP = ppp::net::Ipep::GetEndPoint(host_string, port);
                        if (IPEndPoint::IsInvalid(remoteEP)) {
                            return false;
                        }

                        boost::asio::ip::udp::endpoint ep =
                            IPEndPoint::ToEndPoint<boost::asio::ip::udp>(remoteEP);
                        if (!remoteEP.IsLoopback() && !fib_add_route_ipv4(ep.address())) {
                            return false;
                        }

                        if (aggligator_) {
                            auto r = servers.emplace(
                                IPEndPoint::ToEndPoint<boost::asio::ip::tcp>(remoteEP));
                            return r.second;
                        }

                        return exchanger->StaticEchoAddRemoteEndPoint(ep);
                    };

                for (const ppp::string& server_string : configuration_->udp.static_.servers) {
                    if (!StaticEchoAddRemoteEndPoint(server_string)) {
                        return false;
                    }
                }

                // Open the beast network bandwidth aggregator.
                if (std::shared_ptr<aggligator::aggligator> aggligator = aggligator_; NULLPTR != aggligator) {
                    if (servers.empty()) {
                        aggligator_.reset();
                        aggligator->close();
                    }
                    elif(!aggligator->client_open(configuration_->udp.static_.aggligator, servers)) {
                        return false;
                    }
                }

                // The gateway address must be IPV4 or it is considered a failure because there is no V6 gateway serving the V4 address.
                if (serverEP.IsLoopback()) {
                    return true;
                }

                return fib_add_route_ipv4(remoteIP);
            }

            /** @brief Entry point for DNS redirection decision and async execution. */
            bool VEthernetNetworkSwitcher::RedirectDnsServer(
                const std::shared_ptr<VEthernetExchanger>& exchanger,
                const std::shared_ptr<IPFrame>& packet,
                const std::shared_ptr<UdpFrame>& frame,
                const std::shared_ptr<BufferSegment>& messages) noexcept {

                if (NULLPTR == dns_interceptor_) {
                    return false;
                }

                return dns_interceptor_->HandleQuery(
                    std::static_pointer_cast<VEthernetNetworkSwitcher>(shared_from_this()),
                    exchanger, packet, frame, messages);
            }

            /** @brief Gets current static mode and optionally updates it. */
            bool VEthernetNetworkSwitcher::StaticMode(bool* static_mode) noexcept {
                SynchronizedObjectScope scope(GetSynchronizedObject());
                bool snow = static_mode_;
                if (NULLPTR != static_mode) {
                    static_mode_ = *static_mode;
                }

                return snow;
            }

            /** @brief Gets current proxy-only mode and optionally updates it. */
            bool VEthernetNetworkSwitcher::ProxyOnly(bool* proxy_only) noexcept {
                SynchronizedObjectScope scope(GetSynchronizedObject());
                bool previous = proxy_only_;
                if (NULLPTR != proxy_only) {
                    proxy_only_ = *proxy_only;
                }

                return previous;
            }

            /** @brief Gets current mux size and optionally updates it. */
            uint16_t VEthernetNetworkSwitcher::Mux(uint16_t* mux) noexcept {
                SynchronizedObjectScope scope(GetSynchronizedObject());
                uint16_t snow = mux_;
                if (NULLPTR != mux) {
                    mux_ = *mux;
                }

                return snow;
            }

            /** @brief Gets current mux acceleration flags and optionally updates them. */
            uint8_t VEthernetNetworkSwitcher::MuxAcceleration(uint8_t* mux_acceleration) noexcept {
                SynchronizedObjectScope scope(GetSynchronizedObject());
                uint8_t snow = mux_acceleration_;
                if (NULLPTR != mux_acceleration) {
                    mux_acceleration_ = *mux_acceleration;
                }

                return snow;
            }

            /** @brief Performs periodic update work for static-echo socket rotation. */
            bool VEthernetNetworkSwitcher::OnUpdate(uint64_t now) noexcept {
                if (VEthernet::OnUpdate(now)) {
                    std::shared_ptr<VEthernetExchanger> exchanger = exchanger_;
                    if (NULLPTR != exchanger) {
                        exchanger->StaticEchoSwapAsynchronousSocket();
                    }
                }

                return false;
            }

#if !defined(_ANDROID) && !defined(_IPHONE)
#if defined(_LINUX)
            /** @brief Gets current Linux protect mode and optionally updates it. */
            bool VEthernetNetworkSwitcher::ProtectMode(bool* protect_mode) noexcept {
                SynchronizedObjectScope scope(GetSynchronizedObject());
                bool snow = protect_mode_;
                if (NULLPTR != protect_mode) {
                    protect_mode_ = *protect_mode;
                }

                return snow;
            }
#endif
#endif
        }
    }
}
