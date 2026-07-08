#include "DnsUdpRelay.h"

#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/app/client/dns/DnsResponseHandler.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/dns/DnsWireValidation.h>
#include <ppp/net/Socket.h>
#include <ppp/threading/Timer.h>
#include <ppp/threading/Executors.h>

#if defined(_ANDROID)
#include <android/log.h>

static bool AndroidDnsUdpRelayTraceEnabled() noexcept {
#ifdef NDEBUG
    return false;
#else
    return true;
#endif
}

#define ANDROID_DNS_UDP_RELAY_TRACE(...) \
    do { \
        if (AndroidDnsUdpRelayTraceEnabled()) { \
            __android_log_print(ANDROID_LOG_INFO, "openppp2", __VA_ARGS__); \
        } \
    } while (0)
#else
#define ANDROID_DNS_UDP_RELAY_TRACE(...) ((void)0)
#endif

namespace ppp {
    namespace app {
        namespace client {
            namespace dns {

                bool DnsUdpRelay::RunCoroutine(
                    VEthernetNetworkSwitcher& switcher,
                    ppp::coroutines::YieldContext& y,
                    const std::shared_ptr<boost::asio::ip::udp::socket>& socket,
                    const std::shared_ptr<Byte>& buffer,
                    const boost::asio::ip::address& serverIP,
                    const std::shared_ptr<VEthernetExchanger>& exchanger,
                    const std::shared_ptr<ppp::net::packet::UdpFrame>& frame,
                    const std::shared_ptr<ppp::net::packet::BufferSegment>& messages,
                    const std::shared_ptr<boost::asio::io_context>& context,
                    const boost::asio::ip::address& destinationIP) noexcept {

                    const auto self = std::static_pointer_cast<VEthernetNetworkSwitcher>(
                        switcher.shared_from_this());
                    const boost::asio::ip::udp::endpoint sourceEP =
                        ppp::net::IPEndPoint::ToEndPoint<boost::asio::ip::udp>(frame->Source);
                    const boost::asio::ip::udp::endpoint destinationEP(
                        destinationIP, frame->Destination.Port);
                    const auto fallback_tunnel = [self, exchanger, messages, sourceEP, destinationEP]() noexcept {
                        DnsResponseHandler::HandleResolverResponse(
                            self, exchanger, messages, sourceEP, destinationEP, ppp::vector<Byte>{});
                    };

                    boost::system::error_code ec;
                    boost::asio::ip::udp::endpoint serverEP(serverIP, frame->Destination.Port);

                    bool opened = ppp::coroutines::asio::async_open(y, *socket, serverEP.protocol());
                    if (!opened) {
#if defined(_ANDROID)
                        __android_log_print(ANDROID_LOG_ERROR, "openppp2", "dns_redirect socket_open failed server=%s",
                            serverIP.to_string().c_str());
#endif
                        fallback_tunnel();
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::UdpOpenFailed);
                    }

                    int handle = socket->native_handle();
                    ANDROID_DNS_UDP_RELAY_TRACE("dns_redirect socket_open fd=%d server=%s port=%d",
                        handle,
                        serverIP.to_string().c_str(),
                        (int)frame->Destination.Port);
                    ppp::net::Socket::AdjustDefaultSocketOptional(handle, serverIP.is_v4());
                    ppp::net::Socket::SetTypeOfService(handle);
                    ppp::net::Socket::SetSignalPipeline(handle, false);
                    ppp::net::Socket::ReuseSocketAddress(handle, true);

#if defined(_LINUX)
                    if (!serverIP.is_loopback()) {
                        auto protector_network = switcher.GetProtectorNetwork();
                        if (NULLPTR != protector_network) {
                            if (!protector_network->Protect(handle, y)) {
#if defined(_ANDROID)
                                __android_log_print(ANDROID_LOG_ERROR, "openppp2", "dns_redirect protect failed fd=%d server=%s",
                                    handle,
                                    serverIP.to_string().c_str());
#endif
                                fallback_tunnel();
                                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TunnelProtectionConfigureFailed);
                            }
                            ANDROID_DNS_UDP_RELAY_TRACE("dns_redirect protect ok fd=%d server=%s",
                                handle,
                                serverIP.to_string().c_str());
                        }
#if defined(_ANDROID)
                        else {
                            __android_log_print(ANDROID_LOG_WARN, "openppp2", "dns_redirect protector missing fd=%d server=%s",
                                handle,
                                serverIP.to_string().c_str());
                        }
#endif
                    }
#endif

                    socket->send_to(boost::asio::buffer(messages->Buffer.get(), messages->Length), serverEP,
                        boost::asio::socket_base::message_end_of_record, ec);
                    if (ec) {
#if defined(_ANDROID)
                        __android_log_print(ANDROID_LOG_ERROR, "openppp2", "dns_redirect send failed fd=%d server=%s ec=%d",
                            handle,
                            serverIP.to_string().c_str(),
                            ec.value());
#endif
                        fallback_tunnel();
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::UdpSendFailed);
                    }
                    ANDROID_DNS_UDP_RELAY_TRACE("dns_redirect send ok fd=%d server=%s bytes=%d",
                        handle,
                        serverIP.to_string().c_str(),
                        NULLPTR != messages ? (int)messages->Length : -1);

                    const std::weak_ptr<boost::asio::ip::udp::socket> socket_weak(socket);
                    const std::shared_ptr<ppp::configurations::AppConfiguration> configuration =
                        switcher.GetConfiguration();

                    const auto cb = make_shared_object<Timer::TimeoutEventHandler>(
                        [socket_weak, handle](Timer*) noexcept {
#if defined(_ANDROID)
                            __android_log_print(ANDROID_LOG_WARN, "openppp2", "dns_redirect timeout fd=%d", handle);
#endif
                            const std::shared_ptr<boost::asio::ip::udp::socket> locked = socket_weak.lock();
                            if (locked) {
                                ppp::net::Socket::Closesocket(locked);
                            }
                        });
                    if (NULLPTR == cb) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    }

                    const auto timeout = Timer::Timeout(context, (uint64_t)configuration->udp.dns.timeout * 1000, *cb);
                    if (NULLPTR == timeout) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RuntimeTimerCreateFailed);
                    }

                    if (!switcher.EmplaceTimeout(socket.get(), cb)) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MappingEntryConflict);
                    }

                    const auto max_buffer_size = PPP_BUFFER_SIZE;
                    const auto serverEPPtr = make_shared_object<boost::asio::ip::udp::endpoint>();
                    if (NULLPTR == serverEPPtr) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    }

                    auto receive_again = make_shared_object<std::function<void()> >();
                    if (NULLPTR == receive_again) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    }

                    *receive_again = [self, &switcher, socket, timeout, buffer, sourceEP, destinationEP, serverEP, serverEPPtr, messages, exchanger, max_buffer_size, handle, receive_again]() noexcept {
                        socket->async_receive_from(boost::asio::buffer(buffer.get(), max_buffer_size), *serverEPPtr,
                            [self, &switcher, socket, timeout, buffer, sourceEP, destinationEP, serverEP, serverEPPtr, messages, exchanger, handle, receive_again](boost::system::error_code ec, size_t sz) noexcept {
                                if (ec == boost::system::errc::success && sz > 0) {
                                    if (!ShouldAcceptRelayResponse(
                                            *serverEPPtr, serverEP,
                                            messages->Buffer.get(), messages->Length,
                                            buffer.get(), static_cast<int>(sz))) {
                                        (*receive_again)();
                                        return;
                                    }

                                    ANDROID_DNS_UDP_RELAY_TRACE("dns_redirect recv ok fd=%d bytes=%d",
                                        handle,
                                        (int)sz);
                                    switcher.DatagramOutput(sourceEP, destinationEP, buffer.get(), static_cast<int>(sz));
                                }
                                else {
#if defined(_ANDROID)
                                    __android_log_print(ANDROID_LOG_WARN, "openppp2", "dns_redirect recv failed fd=%d ec=%d",
                                        handle,
                                        ec.value());
#endif
                                    DnsResponseHandler::HandleResolverResponse(
                                        self, exchanger, messages, sourceEP, destinationEP, ppp::vector<Byte>{});
                                }

                                switcher.DeleteTimeout(socket.get());
                                *receive_again = std::function<void()>();
                                ppp::net::Socket::Closesocket(socket);
                                if (timeout) {
                                    timeout->Stop();
                                    timeout->Dispose();
                                }
                            });
                    };
                    (*receive_again)();
                    return true;
                }

                bool DnsUdpRelay::Spawn(
                    const std::shared_ptr<VEthernetNetworkSwitcher>& switcher,
                    const std::shared_ptr<VEthernetExchanger>& exchanger,
                    const std::shared_ptr<ppp::net::packet::IPFrame>& packet,
                    const std::shared_ptr<ppp::net::packet::UdpFrame>& frame,
                    const std::shared_ptr<ppp::net::packet::BufferSegment>& messages,
                    const boost::asio::ip::address& serverIP,
                    const boost::asio::ip::address& destinationIP) noexcept {

                    if (!CanSpawn(switcher, exchanger)) {
                        return false;
                    }

                    std::shared_ptr<boost::asio::io_context> context = exchanger->GetContext();
                    if (NULLPTR == context) {
                        return false;
                    }

                    std::shared_ptr<Byte> buffer = exchanger->GetBuffer();
                    if (NULLPTR == buffer) {
                        const auto configuration = switcher->GetConfiguration();
                        const auto allocator = configuration ? configuration->GetBufferAllocator() : nullptr;
                        if (allocator) {
                            buffer = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, PPP_BUFFER_SIZE);
                        }
                        if (NULLPTR == buffer) {
                            buffer = std::shared_ptr<Byte>(new Byte[PPP_BUFFER_SIZE], std::default_delete<Byte[]>());
                        }
                    }

                    const std::shared_ptr<boost::asio::ip::udp::socket> socket =
                        make_shared_object<boost::asio::ip::udp::socket>(*context);
                    if (!socket) {
                        return false;
                    }

                    const auto allocator = switcher->GetConfiguration()->GetBufferAllocator();
                    return ppp::coroutines::YieldContext::Spawn(allocator.get(), *context,
                        [switcher, socket, buffer, frame, messages, packet, context, serverIP, destinationIP, exchanger](ppp::coroutines::YieldContext& y) noexcept {
                            (void)packet;
                            return DnsUdpRelay::RunCoroutine(
                                *switcher, y, socket, buffer, serverIP, exchanger, frame, messages, context, destinationIP);
                        });
                }

            }
        }
    }
}
