// Minimal HTTP/1.1 helpers (owner: LNX). See http.hpp.
#include "pl/gate/http.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>

namespace pl::gate {

std::optional<HttpRequest> parse_request_head(std::string_view raw) {
  const auto end = raw.find("\r\n\r\n");
  if (end == std::string_view::npos) {
    return std::nullopt;
  }
  HttpRequest r;
  r.head = std::string(raw.substr(0, end + 4));
  r.rest = std::string(raw.substr(end + 4));
  const auto line_end = raw.find("\r\n");
  const auto line = raw.substr(0, line_end);
  const auto s1 = line.find(' ');
  const auto s2 = line.rfind(' ');
  if (s1 == std::string_view::npos || s2 == s1) {
    return std::nullopt;
  }
  r.method = std::string(line.substr(0, s1));
  r.target = std::string(line.substr(s1 + 1, s2 - s1 - 1));
  r.version = std::string(line.substr(s2 + 1));
  if (r.version != "HTTP/1.1" && r.version != "HTTP/1.0") {
    return std::nullopt;
  }
  std::size_t p = line_end + 2;
  while (p < end) {
    const auto e = raw.find("\r\n", p);
    const auto h = raw.substr(p, e - p);
    const auto c = h.find(':');
    if (c != std::string_view::npos) {
      std::string name(h.substr(0, c));
      std::transform(name.begin(), name.end(), name.begin(),
                     [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
      auto v = h.substr(c + 1);
      while (!v.empty() && v.front() == ' ') {
        v.remove_prefix(1);
      }
      r.headers[name] = std::string(v);
    }
    p = e + 2;
  }
  return r;
}

std::optional<HttpRequest> read_request(int fd, std::size_t limit, std::chrono::milliseconds timeout) {
  std::string buf;
  std::array<char, 4096> chunk{};
  while (buf.find("\r\n\r\n") == std::string::npos) {
    if (buf.size() > limit) {
      return std::nullopt;
    }
    pollfd pfd{fd, POLLIN, 0};
    if (::poll(&pfd, 1, static_cast<int>(timeout.count())) <= 0) {
      return std::nullopt;
    }
    const auto n = ::read(fd, chunk.data(), chunk.size());
    if (n <= 0) {
      return std::nullopt;
    }
    buf.append(chunk.data(), static_cast<std::size_t>(n));
  }
  return parse_request_head(buf);
}

Fd tcp_connect(const std::string& host, int port, std::chrono::milliseconds timeout) {
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* res = nullptr;
  const auto port_s = std::to_string(port);
  if (::getaddrinfo(host.c_str(), port_s.c_str(), &hints, &res) != 0) {
    return Fd{};
  }
  Fd out;
  for (auto* a = res; a != nullptr; a = a->ai_next) {
    Fd s(::socket(a->ai_family, a->ai_socktype | SOCK_CLOEXEC, a->ai_protocol));
    if (!s.valid()) {
      continue;
    }
    timeval tv{static_cast<time_t>(timeout.count() / 1000), static_cast<suseconds_t>((timeout.count() % 1000) * 1000)};
    (void)::setsockopt(s.get(), SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    (void)::setsockopt(s.get(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    if (::connect(s.get(), a->ai_addr, a->ai_addrlen) == 0) {
      out = std::move(s);
      break;
    }
  }
  ::freeaddrinfo(res);
  return out;
}

Fd tcp_listen(const std::string& addr, int port) {
  Fd s(::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
  if (!s.valid()) {
    throw std::runtime_error("gate: socket");
  }
  const int one = 1;
  (void)::setsockopt(s.get(), SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
  sockaddr_in sa{};
  sa.sin_family = AF_INET;
  sa.sin_port = htons(static_cast<std::uint16_t>(port));
  if (::inet_pton(AF_INET, addr.c_str(), &sa.sin_addr) != 1 ||
      ::bind(s.get(), reinterpret_cast<const sockaddr*>(&sa), sizeof sa) != 0 || ::listen(s.get(), 64) != 0) {
    throw std::runtime_error("gate: bind/listen");
  }
  return s;
}

bool write_all(int fd, std::string_view data) {
  while (!data.empty()) {
    const auto n = ::send(fd, data.data(), data.size(), MSG_NOSIGNAL);
    if (n <= 0) {
      return false;
    }
    data.remove_prefix(static_cast<std::size_t>(n));
  }
  return true;
}

void splice_bidirectional(int a, int b) {
  std::array<pollfd, 2> fds{{{a, POLLIN, 0}, {b, POLLIN, 0}}};
  std::array<char, 16384> buf{};
  for (;;) {
    if (::poll(fds.data(), fds.size(), 300000) <= 0) {
      return;
    }
    for (std::size_t i = 0; i < 2; ++i) {
      if ((fds.at(i).revents & (POLLIN | POLLHUP | POLLERR)) == 0) {
        continue;
      }
      const auto n = ::read(fds.at(i).fd, buf.data(), buf.size());
      if (n <= 0 || !write_all(fds.at(1 - i).fd, std::string_view(buf.data(), static_cast<std::size_t>(n)))) {
        return;
      }
    }
  }
}

std::optional<HttpResponse> http_post_json(const std::string& host, int port, const std::string& path,
                                           const std::string& body, std::chrono::milliseconds timeout) {
  Fd s = tcp_connect(host, port, timeout);
  if (!s.valid()) {
    return std::nullopt;
  }
  std::string req = "POST " + path + " HTTP/1.1\r\nHost: " + host + "\r\nContent-Type: application/json\r\n" +
                    "Content-Length: " + std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
  if (!write_all(s.get(), req)) {
    return std::nullopt;
  }
  std::string resp;
  std::array<char, 8192> chunk{};
  for (;;) {
    const auto n = ::read(s.get(), chunk.data(), chunk.size());
    if (n < 0) {
      return std::nullopt;
    }
    if (n == 0) {
      break;
    }
    resp.append(chunk.data(), static_cast<std::size_t>(n));
    if (resp.size() > 16U * 1024U * 1024U) {
      return std::nullopt;
    }
  }
  const auto he = resp.find("\r\n\r\n");
  if (resp.rfind("HTTP/1.", 0) != 0 || he == std::string::npos || resp.size() < 12) {
    return std::nullopt;
  }
  HttpResponse out;
  (void)std::from_chars(resp.data() + 9, resp.data() + 12, out.status);
  out.body = resp.substr(he + 4);
  if (resp.substr(0, he).find("chunked") != std::string::npos) {
    // De-chunk.
    std::string plain;
    std::size_t p = 0;
    while (p < out.body.size()) {
      const auto le = out.body.find("\r\n", p);
      if (le == std::string::npos) {
        break;
      }
      std::size_t len = 0;
      (void)std::from_chars(out.body.data() + p, out.body.data() + le, len, 16);
      if (len == 0) {
        break;
      }
      plain += out.body.substr(le + 2, len);
      p = le + 2 + len + 2;
    }
    out.body = std::move(plain);
  }
  return out;
}

std::optional<std::pair<std::string, int>> split_host_port(std::string_view hp, int default_port) {
  std::string host;
  int port = default_port;
  const auto c = hp.rfind(':');
  if (c != std::string_view::npos) {
    host = std::string(hp.substr(0, c));
    const auto ps = hp.substr(c + 1);
    const auto [ptr, ec] = std::from_chars(ps.data(), ps.data() + ps.size(), port);
    if (ec != std::errc{} || ptr != ps.data() + ps.size() || port < 1 || port > 65535) {
      return std::nullopt;
    }
  } else {
    host = std::string(hp);
  }
  std::transform(host.begin(), host.end(), host.begin(),
                 [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
  if (host.empty() || host.size() > 253 ||
      !std::all_of(host.begin(), host.end(), [](char ch) { return std::isalnum(static_cast<unsigned char>(ch)) != 0 || ch == '-' || ch == '.'; })) {
    return std::nullopt;
  }
  return std::make_pair(host, port);
}

}  // namespace pl::gate
