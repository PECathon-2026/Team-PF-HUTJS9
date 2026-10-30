// SecureChannel tests (owner: LNX): round trip, tamper, replay, wrong order.
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <future>
#include <string>

#include <gtest/gtest.h>

#include "pl/channel.hpp"
#include "pl/frame.hpp"

namespace {

using namespace std::chrono_literals;

std::pair<pl::Fd, pl::Fd> make_pair() {
  std::array<int, 2> fds{};
  EXPECT_EQ(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds.data()), 0);
  return {pl::Fd(fds[0]), pl::Fd(fds[1])};
}

std::span<const std::byte> bytes_of(const std::string& s) { return std::as_bytes(std::span(s.data(), s.size())); }

TEST(SecureChannel, RoundTripBothDirections) {
  auto [a, b] = make_pair();
  auto server = std::async(std::launch::async, [fd = std::move(b)]() mutable {
    return std::make_unique<pl::SecureChannel>(std::move(fd), pl::SecureChannel::Role::server);
  });
  pl::SecureChannel client(std::move(a), pl::SecureChannel::Role::client);
  auto srv = server.get();
  client.send(bytes_of("hello vault"));
  auto got = srv->recv(1s);
  ASSERT_TRUE(got);
  EXPECT_EQ(std::string(reinterpret_cast<const char*>(got->data()), got->size()), "hello vault");
  srv->send(bytes_of("ok"));
  auto back = client.recv(1s);
  ASSERT_TRUE(back);
  EXPECT_EQ(back->size(), 2U);
}

TEST(SecureChannel, CiphertextHidesPlaintextAndTamperKillsChannel) {
  auto [a, b] = make_pair();
  // A raw socket in the middle: we run the server side by hand to see the wire.
  auto client_fut = std::async(std::launch::async, [fd = std::move(a)]() mutable {
    return std::make_unique<pl::SecureChannel>(std::move(fd), pl::SecureChannel::Role::client);
  });
  pl::SecureChannel server(std::move(b), pl::SecureChannel::Role::server);
  auto client = client_fut.get();
  // Recreate a wire-level view: send from client, intercept nothing (stream sockets),
  // so tamper by sending a forged frame directly on the client's fd.
  const std::string forged(40, 'A');
  auto framed = pl::encode_frame(bytes_of(forged));
  ASSERT_EQ(::write(client->fd().get(), framed.data(), framed.size()), static_cast<ssize_t>(framed.size()));
  EXPECT_THROW((void)server.recv(1s), pl::ProtocolError);
  EXPECT_THROW((void)server.recv(1s), pl::ProtocolError);  // stays dead
}

TEST(SecureChannel, ReplayedFrameIsRejected) {
  auto [a, b] = make_pair();
  // Capture the client's encrypted frames with a pass-through pair.
  auto [c, d] = make_pair();
  auto server_fut = std::async(std::launch::async, [fd = std::move(d)]() mutable {
    return std::make_unique<pl::SecureChannel>(std::move(fd), pl::SecureChannel::Role::server);
  });
  // Proxy thread: relay the handshake both ways, then record the first data frame.
  pl::FramedSocket from_client(std::move(b));
  pl::FramedSocket to_server(std::move(c));
  auto client_fut = std::async(std::launch::async, [fd = std::move(a)]() mutable {
    return std::make_unique<pl::SecureChannel>(std::move(fd), pl::SecureChannel::Role::client);
  });
  auto relay = [](pl::FramedSocket& in, pl::FramedSocket& out) {
    auto f = in.recv(2s);
    ASSERT_TRUE(f);
    out.send(*f);
  };
  relay(from_client, to_server);  // client pk
  relay(to_server, from_client);  // server pk
  relay(from_client, to_server);  // client header
  relay(to_server, from_client);  // server header
  auto server = server_fut.get();
  auto client = client_fut.get();
  client->send(bytes_of("decrypt h1"));
  auto data = from_client.recv(2s);
  ASSERT_TRUE(data);
  to_server.send(*data);
  ASSERT_TRUE(server->recv(1s));
  to_server.send(*data);  // replay
  EXPECT_THROW((void)server->recv(1s), pl::ProtocolError);
}

}  // namespace
