// Unix domain stream sockets with framed messages (owner: LNX, AD-04).
// All sockets are SOCK_CLOEXEC. Errors throw std::system_error; a peer that
// closes mid-frame or sends a bad header is a protocol error (fail-closed).
#pragma once

#include <sys/types.h>

#include <chrono>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "pl/frame.hpp"
#include "pl/validate.hpp"

namespace pl {

class Fd {
 public:
  Fd() noexcept = default;
  explicit Fd(int fd) noexcept : fd_(fd) {}
  ~Fd();
  Fd(const Fd&) = delete;
  Fd& operator=(const Fd&) = delete;
  Fd(Fd&& o) noexcept : fd_(o.release()) {}
  Fd& operator=(Fd&& o) noexcept;

  [[nodiscard]] int get() const noexcept { return fd_; }
  [[nodiscard]] bool valid() const noexcept { return fd_ >= 0; }
  int release() noexcept;
  void reset() noexcept;

 private:
  int fd_ = -1;
};

struct PeerCredentials {
  pid_t pid;
  uid_t uid;
  gid_t gid;
};

class ProtocolError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

inline constexpr unsigned kMaxJsonDepth = 64;

// Parses a frame payload as JSON, rejecting malformed input and nesting deeper
// than kMaxJsonDepth. Throws ProtocolError.
[[nodiscard]] nlohmann::json parse_json_bounded(std::span<const std::byte> payload);

inline constexpr std::chrono::milliseconds kDefaultSendTimeout{5000};

// Binds and listens on `path` (an existing stale socket file is replaced).
// The socket file is created with `mode` (default owner+group read/write) via the
// umask at bind time, so there is no chmod-after-bind race. umask is process-wide:
// call this during single-threaded startup.
[[nodiscard]] Fd listen_unix(const std::string& path, int backlog = 16, unsigned mode = 0660);
[[nodiscard]] Fd connect_unix(const std::string& path);
// Waits up to `timeout` for a connection; nullopt on timeout.
[[nodiscard]] std::optional<Fd> accept_unix(const Fd& listener, std::chrono::milliseconds timeout);
[[nodiscard]] PeerCredentials peer_credentials(const Fd& sock);

class FramedSocket {
 public:
  explicit FramedSocket(Fd fd, std::uint32_t max_frame = kMaxFrameBytes) : fd_(std::move(fd)), decoder_(max_frame) {}

  // Throws ProtocolError if the peer doesn't drain the frame within `timeout`.
  void send(std::span<const std::byte> payload, std::chrono::milliseconds timeout = kDefaultSendTimeout);
  // Next payload; nullopt on clean EOF at a frame boundary or on timeout (timed_out() tells which).
  // Throws ProtocolError on a bad header or EOF inside a frame.
  [[nodiscard]] std::optional<std::vector<std::byte>> recv(std::chrono::milliseconds timeout);
  [[nodiscard]] bool timed_out() const noexcept { return timed_out_; }
  [[nodiscard]] const Fd& fd() const noexcept { return fd_; }

  // JSON messages. send_json validates when a validator is given (debug/test
  // builds pass one, SHARED §5). recv_json always validates and throws
  // ProtocolError on malformed JSON or a schema failure.
  void send_json(const nlohmann::json& message, const MessageValidator* validator,
                 std::chrono::milliseconds timeout = kDefaultSendTimeout);
  [[nodiscard]] std::optional<nlohmann::json> recv_json(const MessageValidator& validator, std::chrono::milliseconds timeout);

 private:
  Fd fd_;
  FrameDecoder decoder_;
  bool timed_out_ = false;
};

}  // namespace pl
