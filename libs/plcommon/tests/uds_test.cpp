#include "pl/uds.hpp"

#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <thread>

namespace {

using namespace std::chrono_literals;

// Accepts any message whose "schema" is "ok.v1".
class OkValidator final : public pl::MessageValidator {
 public:
  [[nodiscard]] pl::ValidationResult validate(std::string_view id, const nlohmann::json& /*m*/) const override {
    return id == "ok.v1" ? pl::ValidationResult::success() : pl::ValidationResult::failure({"/schema: unknown"});
  }
};

std::string temp_socket_path(const char* name) {
  return (std::filesystem::temp_directory_path() / (std::string("pl-") + name + "-" + std::to_string(::getpid()) + ".sock")).string();
}

std::pair<pl::FramedSocket, pl::FramedSocket> socket_pair() {
  std::array<int, 2> fds{};
  EXPECT_EQ(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds.data()), 0);
  return {pl::FramedSocket(pl::Fd(fds[0])), pl::FramedSocket(pl::Fd(fds[1]))};
}

TEST(Uds, ListenConnectAcceptAndPeerCreds) {
  const auto path = temp_socket_path("lca");
  auto listener = pl::listen_unix(path);
  std::thread client([&] {
    pl::FramedSocket c(pl::connect_unix(path));
    c.send_json({{"schema", "ok.v1"}, {"n", 1}}, nullptr);
  });
  auto conn = pl::accept_unix(listener, 2000ms);
  ASSERT_TRUE(conn.has_value());
  const auto creds = pl::peer_credentials(*conn);
  EXPECT_EQ(creds.uid, ::getuid());
  pl::FramedSocket s(std::move(*conn));
  const OkValidator v;
  const auto msg = s.recv_json(v, 2000ms);
  client.join();
  ASSERT_TRUE(msg.has_value());
  EXPECT_EQ((*msg)["n"], 1);
  std::filesystem::remove(path);
}

TEST(Uds, AcceptTimesOut) {
  const auto path = temp_socket_path("timeout");
  auto listener = pl::listen_unix(path);
  EXPECT_FALSE(pl::accept_unix(listener, 10ms).has_value());
  std::filesystem::remove(path);
}

TEST(Uds, ReplacesStaleSocketButNotRegularFile) {
  const auto path = temp_socket_path("stale");
  { auto first = pl::listen_unix(path); }
  EXPECT_NO_THROW({ auto again = pl::listen_unix(path); });
  std::filesystem::remove(path);
  std::ofstream(path) << "not a socket";
  EXPECT_THROW({ auto bad = pl::listen_unix(path); }, std::runtime_error);
  std::filesystem::remove(path);
}

TEST(Uds, RejectsTooLongPath) {
  EXPECT_THROW({ auto s = pl::listen_unix(std::string(200, 'a')); }, std::invalid_argument);
  EXPECT_THROW({ auto s = pl::connect_unix(""); }, std::invalid_argument);
}

TEST(Uds, ConnectToMissingSocketThrows) {
  EXPECT_THROW({ auto s = pl::connect_unix("/nonexistent/pl.sock"); }, std::system_error);
}

TEST(Uds, RecvTimesOutAndReportsIt) {
  auto [a, b] = socket_pair();
  EXPECT_FALSE(b.recv(10ms).has_value());
  EXPECT_TRUE(b.timed_out());
}

TEST(Uds, CleanEofReturnsNullopt) {
  auto [a, b] = socket_pair();
  { pl::FramedSocket gone = std::move(a); }
  EXPECT_FALSE(b.recv(1000ms).has_value());
  EXPECT_FALSE(b.timed_out());
}

TEST(Uds, EofInsideFrameIsProtocolError) {
  std::array<int, 2> fds{};
  ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds.data()), 0);
  pl::FramedSocket b{pl::Fd(fds[1])};
  const std::array<unsigned char, 6> partial = {0, 0, 0, 9, 'a', 'b'};
  ASSERT_EQ(::write(fds[0], partial.data(), partial.size()), 6);
  ::close(fds[0]);
  EXPECT_THROW((void)b.recv(1000ms), pl::ProtocolError);
}

TEST(Uds, BadHeaderIsProtocolError) {
  std::array<int, 2> fds{};
  ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds.data()), 0);
  pl::FramedSocket b{pl::Fd(fds[1])};
  const std::array<unsigned char, 4> zero = {0, 0, 0, 0};
  ASSERT_EQ(::write(fds[0], zero.data(), zero.size()), 4);
  EXPECT_THROW((void)b.recv(1000ms), pl::ProtocolError);
  ::close(fds[0]);
}

TEST(Uds, SendValidatesWhenAsked) {
  auto [a, b] = socket_pair();
  const OkValidator v;
  EXPECT_THROW(a.send_json({{"schema", "nope.v1"}}, &v), pl::ProtocolError);
  EXPECT_NO_THROW(a.send_json({{"schema", "nope.v1"}}, nullptr));
}

TEST(Uds, RecvRejectsSchemaFailureAndBadJson) {
  auto [a, b] = socket_pair();
  const OkValidator v;
  a.send_json({{"schema", "nope.v1"}}, nullptr);
  EXPECT_THROW((void)b.recv_json(v, 1000ms), pl::ProtocolError);
  auto [c, d] = socket_pair();
  c.send(std::as_bytes(std::span<const char>("{not json", 9)));
  EXPECT_THROW((void)d.recv_json(v, 1000ms), pl::ProtocolError);
  auto [e, f] = socket_pair();
  e.send(std::as_bytes(std::span<const char>("[1]", 3)));
  EXPECT_THROW((void)f.recv_json(v, 1000ms), pl::ProtocolError);  // no "schema"
}

TEST(Uds, JsonDepthLimit) {
  const auto nested = [](unsigned depth) {
    return std::string(depth, '[') + std::string(depth, ']');
  };
  const auto ok = nested(pl::kMaxJsonDepth);
  const auto deep = nested(pl::kMaxJsonDepth + 1);
  EXPECT_NO_THROW((void)pl::parse_json_bounded(std::as_bytes(std::span<const char>(ok.data(), ok.size()))));
  EXPECT_THROW((void)pl::parse_json_bounded(std::as_bytes(std::span<const char>(deep.data(), deep.size()))), pl::ProtocolError);
}

TEST(Uds, JsonDepthCountsContainersOnly) {
  const auto wrap = [](unsigned depth, const std::string& inner) {
    return std::string(depth, '[') + inner + std::string(depth, ']');
  };
  const auto parse = [](const std::string& s) { return pl::parse_json_bounded(std::as_bytes(std::span<const char>(s.data(), s.size()))); };
  EXPECT_NO_THROW((void)parse(wrap(pl::kMaxJsonDepth, "1")));
  EXPECT_NO_THROW((void)parse(wrap(pl::kMaxJsonDepth - 1, "{\"a\":1}")));
  EXPECT_THROW((void)parse(wrap(pl::kMaxJsonDepth, "{\"a\":1}")), pl::ProtocolError);
  EXPECT_THROW((void)parse(wrap(pl::kMaxJsonDepth + 1, "1")), pl::ProtocolError);
}

TEST(Uds, RejectsNanAndLoneSurrogates) {
  for (const std::string bad : {R"({"x": NaN})", R"({"x": Infinity})", R"({"x": "\ud800"})"}) {
    EXPECT_THROW((void)pl::parse_json_bounded(std::as_bytes(std::span<const char>(bad.data(), bad.size()))), pl::ProtocolError) << bad;
  }
}

TEST(Uds, SocketFileModeAndSendTimeout) {
  const auto path = temp_socket_path("mode");
  { auto l = pl::listen_unix(path, 4, 0600); }
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-member-init,hicpp-member-init)
  struct stat st{};
  ASSERT_EQ(::lstat(path.c_str(), &st), 0);
  EXPECT_EQ(st.st_mode & 0777U, 0600U);
  std::filesystem::remove(path);
  auto [a, b] = socket_pair();  // b never reads
  const std::string big(1 << 20, 'x');
  EXPECT_THROW(a.send(std::as_bytes(std::span<const char>(big.data(), big.size())), 50ms), pl::ProtocolError);
}

TEST(Uds, FdMoveAndRelease) {
  pl::Fd a(::dup(STDERR_FILENO));
  ASSERT_TRUE(a.valid());
  pl::Fd b = std::move(a);
  EXPECT_FALSE(a.valid());  // NOLINT(bugprone-use-after-move,clang-analyzer-cplusplus.Move): moved-from state is specified
  EXPECT_TRUE(b.valid());
  pl::Fd c;
  c = std::move(b);
  const int raw = c.release();
  EXPECT_FALSE(c.valid());
  ::close(raw);
}

}  // namespace
