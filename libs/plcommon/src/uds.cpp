#include "pl/uds.hpp"

#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <iterator>
#include <cerrno>
#include <cstring>
#include <system_error>

namespace pl {

namespace {

[[noreturn]] void throw_errno(const char* what) { throw std::system_error(errno, std::generic_category(), what); }

sockaddr_un make_addr(const std::string& path) {
  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  if (path.empty() || path.size() >= sizeof(addr.sun_path)) {
    throw std::invalid_argument("unix socket path is empty or too long");
  }
  std::copy_n(path.c_str(), path.size() + 1, std::begin(addr.sun_path));
  return addr;
}

// Returns false on timeout.
bool wait_fd(int fd, short events, std::chrono::milliseconds timeout) {
  pollfd p{fd, events, 0};
  for (;;) {
    const int r = ::poll(&p, 1, static_cast<int>(timeout.count()));
    if (r > 0) {
      return true;
    }
    if (r == 0) {
      return false;
    }
    if (errno != EINTR) {
      throw_errno("poll");
    }
  }
}

}  // namespace

nlohmann::json parse_json_bounded(std::span<const std::byte> payload) {
  bool too_deep = false;
  const nlohmann::json::parser_callback_t limit = [&too_deep](int depth, nlohmann::json::parse_event_t /*event*/,
                                                              nlohmann::json& /*parsed*/) {
    if (depth >= static_cast<int>(kMaxJsonDepth)) {  // depth is 0-based: kMaxJsonDepth containers deep is the limit
      too_deep = true;
      return false;
    }
    return true;
  };
  const auto* begin = reinterpret_cast<const char*>(payload.data());
  nlohmann::json message = nlohmann::json::parse(begin, begin + payload.size(), limit, /*allow_exceptions=*/false);
  if (message.is_discarded() || too_deep) {
    throw ProtocolError(too_deep ? "incoming JSON nests too deeply" : "incoming frame is not valid JSON");
  }
  return message;
}

Fd::~Fd() { reset(); }

Fd& Fd::operator=(Fd&& o) noexcept {
  if (this != &o) {
    reset();
    fd_ = o.release();
  }
  return *this;
}

int Fd::release() noexcept {
  const int fd = fd_;
  fd_ = -1;
  return fd;
}

void Fd::reset() noexcept {
  if (fd_ >= 0) {
    ::close(fd_);
    fd_ = -1;
  }
}

Fd listen_unix(const std::string& path, int backlog, unsigned mode) {
  const sockaddr_un addr = make_addr(path);
  Fd fd(::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0));
  if (!fd.valid()) {
    throw_errno("socket");
  }
  struct stat st{};
  if (::lstat(path.c_str(), &st) == 0) {
    if (!S_ISSOCK(st.st_mode)) {
      throw std::runtime_error("refusing to replace a non-socket file at the socket path");
    }
    ::unlink(path.c_str());
  }
  if (::bind(fd.get(), reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0) {
    throw_errno("bind");
  }
  if (::chmod(path.c_str(), static_cast<mode_t>(mode)) != 0) {
    throw_errno("chmod");
  }
  if (::listen(fd.get(), backlog) != 0) {
    throw_errno("listen");
  }
  return fd;
}

Fd connect_unix(const std::string& path) {
  const sockaddr_un addr = make_addr(path);
  Fd fd(::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0));
  if (!fd.valid()) {
    throw_errno("socket");
  }
  while (::connect(fd.get(), reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0) {
    if (errno != EINTR) {
      throw_errno("connect");
    }
  }
  return fd;
}

std::optional<Fd> accept_unix(const Fd& listener, std::chrono::milliseconds timeout) {
  if (!wait_fd(listener.get(), POLLIN, timeout)) {
    return std::nullopt;
  }
  for (;;) {
    const int c = ::accept4(listener.get(), nullptr, nullptr, SOCK_CLOEXEC);
    if (c >= 0) {
      return Fd(c);
    }
    if (errno != EINTR) {
      throw_errno("accept4");
    }
  }
}

PeerCredentials peer_credentials(const Fd& sock) {
  ucred cred{};
  socklen_t len = sizeof(cred);
  if (::getsockopt(sock.get(), SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0) {
    throw_errno("getsockopt(SO_PEERCRED)");
  }
  return {cred.pid, cred.uid, cred.gid};
}

void FramedSocket::send(std::span<const std::byte> payload) {
  const auto frame = encode_frame(payload);
  std::size_t off = 0;
  while (off < frame.size()) {
    const ssize_t n = ::send(fd_.get(), frame.data() + off, frame.size() - off, MSG_NOSIGNAL);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      throw_errno("send");
    }
    off += static_cast<std::size_t>(n);
  }
}

std::optional<std::vector<std::byte>> FramedSocket::recv(std::chrono::milliseconds timeout) {
  timed_out_ = false;
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  std::array<std::byte, std::size_t{64} * 1024> chunk{};
  for (;;) {
    if (auto payload = decoder_.next()) {
      return payload;
    }
    if (decoder_.failed()) {
      throw ProtocolError(std::string("bad frame: ") + std::string(to_string(decoder_.error())));
    }
    const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
    if (left.count() <= 0 || !wait_fd(fd_.get(), POLLIN, left)) {
      timed_out_ = true;
      return std::nullopt;
    }
    const ssize_t n = ::recv(fd_.get(), chunk.data(), chunk.size(), 0);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      throw_errno("recv");
    }
    if (n == 0) {
      if (decoder_.buffered() != 0) {
        throw ProtocolError("peer closed inside a frame");
      }
      return std::nullopt;
    }
    decoder_.feed(std::span<const std::byte>(chunk.data(), static_cast<std::size_t>(n)));
  }
}

void FramedSocket::send_json(const nlohmann::json& message, const MessageValidator* validator) {
  if (validator != nullptr) {
    const auto r = validate_dispatch(*validator, message);
    if (!r.ok) {
      throw ProtocolError("outgoing message fails its schema");
    }
  }
  const std::string text = message.dump();
  send(std::as_bytes(std::span<const char>(text.data(), text.size())));
}

std::optional<nlohmann::json> FramedSocket::recv_json(const MessageValidator& validator, std::chrono::milliseconds timeout) {
  auto payload = recv(timeout);
  if (!payload) {
    return std::nullopt;
  }
  nlohmann::json message = parse_json_bounded(*payload);
  if (const auto r = validate_dispatch(validator, message); !r.ok) {
    throw ProtocolError("incoming message fails its schema");
  }
  return message;
}

}  // namespace pl
