// Chrome DevTools Protocol over --remote-debugging-pipe (owner: LNX).
// Chrome reads commands on fd 3 and writes replies/events on fd 4, NUL-separated JSON.
#pragma once

#include <sys/types.h>

#include <chrono>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace pl::core {

class CdpError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

class Chrome {
 public:
  // Starts Chrome (headless shell) with the pipe transport and the given extra flags.
  Chrome(const std::string& binary, const std::vector<std::string>& flags);
  ~Chrome();
  Chrome(const Chrome&) = delete;
  Chrome& operator=(const Chrome&) = delete;
  Chrome(Chrome&&) = delete;
  Chrome& operator=(Chrome&&) = delete;

  // Sends one command and waits for its reply; throws CdpError on a CDP error or timeout.
  nlohmann::json call(const std::string& method, const nlohmann::json& params, const std::string& session = {},
                      std::chrono::milliseconds timeout = std::chrono::milliseconds{15000});

  // Creates a page target and attaches to it (flattened); returns the session id.
  std::string open_page();

 private:
  pid_t pid_ = -1;
  int to_chrome_ = -1;
  int from_chrome_ = -1;
  long next_id_ = 1;
  std::string buf_;
};

}  // namespace pl::core
