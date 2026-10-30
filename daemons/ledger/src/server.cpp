#include "ledger/server.hpp"

#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstring>
#include <iostream>

namespace pl::ledger {

namespace {

void set_nonblocking(int fd) {
  const int fl = ::fcntl(fd, F_GETFL, 0);
  if (fl < 0 || ::fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) throw std::system_error(errno, std::generic_category(), "fcntl");
}

// Sends a whole frame, waiting up to timeout_ms for the peer to drain. False: drop the peer.
bool send_frame(int fd, const nlohmann::json& msg, int timeout_ms) {
  const auto frame = encode_frame(msg.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace));
  std::size_t off = 0;
  while (off < frame.size()) {
    const ssize_t n = ::send(fd, reinterpret_cast<const char*>(frame.data()) + off, frame.size() - off,
                             MSG_NOSIGNAL | MSG_DONTWAIT);
    if (n > 0) {
      off += static_cast<std::size_t>(n);
      continue;
    }
    if (n < 0 && errno == EINTR) continue;
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      pollfd p{fd, POLLOUT, 0};
      if (::poll(&p, 1, timeout_ms) <= 0) return false;
      continue;
    }
    return false;
  }
  return true;
}

std::uint64_t now_ms() {
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
}

}  // namespace

Server::Server(Ledger& ledger, const std::string& ingest_path, const std::string& stream_path)
    : ledger_(ledger), ingest_listener_(listen_unix(ingest_path, 16, 0660)),
      stream_listener_(listen_unix(stream_path, 16, 0660)) {
  ledger_.set_sink([this](const nlohmann::json& m) { broadcast(m); });
}

void Server::accept_ingest() {
  while (auto fd = accept_unix(ingest_listener_, std::chrono::milliseconds(0))) {
    set_nonblocking(fd->get());
    ingest_.push_back(Ingest{std::move(*fd), FrameDecoder{kMaxIngestFrame}});
  }
}

void Server::accept_stream() {
  while (auto fd = accept_unix(stream_listener_, std::chrono::milliseconds(0))) {
    set_nonblocking(fd->get());
    bool ok = true;
    for (const auto& m : ledger_.subscribe_burst()) {
      if (!send_frame(fd->get(), m, 200)) {
        ok = false;
        break;
      }
    }
    if (ok) subs_.push_back(std::move(*fd));
  }
}

void Server::broadcast(const nlohmann::json& msg) {
  for (auto it = subs_.begin(); it != subs_.end();) {
    if (!send_frame(it->get(), msg, 50)) it = subs_.erase(it);
    else ++it;
  }
}

bool Server::read_ingest(Ingest& c) {
  std::array<std::byte, 65536> buf{};
  const ssize_t n = ::recv(c.fd.get(), buf.data(), buf.size(), MSG_DONTWAIT);
  if (n == 0) return false;
  if (n < 0) return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;
  c.dec.feed(std::span<const std::byte>(buf.data(), static_cast<std::size_t>(n)));
  while (auto payload = c.dec.next()) {
    IngestResult r;
    try {
      r = ledger_.ingest(parse_json_bounded(*payload));
    } catch (const ProtocolError&) {
      r = ledger_.reject_unparsed(RejectCode::schema_invalid);
    }
    nlohmann::json ack = r.accepted ? nlohmann::json{{"ok", true}, {"seq", r.seq}}
                                    : nlohmann::json{{"ok", false}, {"rule_id", r.rule_id}, {"code", r.code}};
    if (!send_frame(c.fd.get(), ack, 100)) return false;
  }
  if (c.dec.failed()) {
    (void)ledger_.reject_unparsed(RejectCode::oversize);
    return false;
  }
  return true;
}

void Server::step(int timeout_ms) {
  std::vector<pollfd> fds;
  fds.push_back({ingest_listener_.get(), POLLIN, 0});
  fds.push_back({stream_listener_.get(), POLLIN, 0});
  for (const auto& c : ingest_) fds.push_back({c.fd.get(), POLLIN, 0});
  for (const auto& s : subs_) fds.push_back({s.get(), POLLIN, 0});
  const std::size_t n_ing = ingest_.size();
  if (::poll(fds.data(), fds.size(), timeout_ms) < 0 && errno != EINTR) {
    throw std::system_error(errno, std::generic_category(), "poll");
  }
  if ((fds[0].revents & POLLIN) != 0) accept_ingest();
  if ((fds[1].revents & POLLIN) != 0) accept_stream();
  // Ingest connections (only those that existed when polled).
  std::vector<bool> keep(n_ing, true);
  for (std::size_t i = 0; i < n_ing; ++i) {
    const short re = fds[2 + i].revents;
    if ((re & (POLLIN | POLLHUP | POLLERR)) != 0) keep[i] = read_ingest(ingest_[i]);
  }
  for (std::size_t i = n_ing; i-- > 0;) {
    if (!keep[i]) ingest_.erase(ingest_.begin() + static_cast<std::ptrdiff_t>(i));
  }
  // Subscribers: any readable event is EOF or junk; subscribers never send.
  for (std::size_t i = subs_.size(); i-- > 0;) {
    const std::size_t pi = 2 + n_ing + i;
    if (pi < fds.size() && (fds[pi].revents & (POLLIN | POLLHUP | POLLERR)) != 0 && i < subs_.size()) {
      char b[256];
      const ssize_t r = ::recv(subs_[i].get(), b, sizeof b, MSG_DONTWAIT);
      if (r == 0 || (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) {
        subs_.erase(subs_.begin() + static_cast<std::ptrdiff_t>(i));
      }
    }
  }
  const std::uint64_t t = now_ms();
  if (t - last_stats_ms_ >= 1000) {
    last_stats_ms_ = t;
    broadcast(ledger_.stats_message());
  }
}

void Server::run(const std::atomic<bool>& stop) {
  while (!stop.load()) step(250);
}

}  // namespace pl::ledger
