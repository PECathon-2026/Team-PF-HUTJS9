// Minimal HTTP/1.1 pieces for the gate (owner: LNX): a blocking client for the
// ollama provider, request parsing for the browsing lane and the UI port.
#pragma once

#include <chrono>
#include <map>
#include <optional>
#include <string>
#include <string_view>

#include "pl/uds.hpp"

namespace pl::gate {

struct HttpResponse {
  int status = 0;
  std::string body;
};

struct HttpRequest {
  std::string method, target, version;
  std::map<std::string, std::string> headers;  // lower-case names
  std::string head;                            // the raw header block, incl. the final CRLFCRLF
  std::string rest;                            // bytes read past the header block
};

// Parses "<METHOD> <target> HTTP/1.x" + headers from `raw`; nullopt if malformed.
[[nodiscard]] std::optional<HttpRequest> parse_request_head(std::string_view raw);

// Reads until CRLFCRLF (max `limit` bytes) and parses; nullopt on error/timeout.
[[nodiscard]] std::optional<HttpRequest> read_request(int fd, std::size_t limit, std::chrono::milliseconds timeout);

[[nodiscard]] Fd tcp_connect(const std::string& host, int port, std::chrono::milliseconds timeout);
[[nodiscard]] Fd tcp_listen(const std::string& addr, int port);

[[nodiscard]] std::optional<HttpResponse> http_post_json(const std::string& host, int port, const std::string& path,
                                                         const std::string& body, std::chrono::milliseconds timeout);

bool write_all(int fd, std::string_view data);
// Copies bytes both ways until either side closes.
void splice_bidirectional(int a, int b);

// Splits "host:port" (default port if absent); host lower-cased. nullopt if malformed.
[[nodiscard]] std::optional<std::pair<std::string, int>> split_host_port(std::string_view hp, int default_port);

}  // namespace pl::gate
