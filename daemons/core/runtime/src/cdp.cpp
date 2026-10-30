// CDP pipe client (owner: LNX). See cdp.hpp.
#include "pl/core/cdp.hpp"

#include <fcntl.h>
#include <poll.h>
#include <csignal>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <cerrno>

#include "pl/channel.hpp"
#include "pl/ids.hpp"

namespace pl::core {

Chrome::Chrome(const std::string& binary, const std::vector<std::string>& flags) {
  std::array<int, 2> cmd{};  // parent writes cmd[1], chrome reads fd 3
  std::array<int, 2> out{};  // chrome writes fd 4, parent reads out[0]
  if (::pipe2(cmd.data(), O_CLOEXEC) != 0 || ::pipe2(out.data(), O_CLOEXEC) != 0) {
    throw CdpError("pipe");
  }
  std::vector<std::string> args{binary, "--remote-debugging-pipe"};
  args.insert(args.end(), flags.begin(), flags.end());
  std::vector<char*> argv;
  argv.reserve(args.size() + 1);
  for (auto& a : args) {
    argv.push_back(a.data());
  }
  argv.push_back(nullptr);
  pid_ = ::fork();
  if (pid_ < 0) {
    throw CdpError("fork");
  }
  if (pid_ == 0) {
    // Child: fds 3/4 must be exactly these pipe ends, without CLOEXEC.
    const int r = ::dup(cmd[0]);
    const int w = ::dup(out[1]);
    if (r < 0 || w < 0 || ::dup2(r, 3) < 0 || ::dup2(w, 4) < 0) {
      ::_exit(127);
    }
    const int devnull = ::open("/dev/null", O_RDWR);
    if (devnull >= 0) {
      (void)::dup2(devnull, 0);
      (void)::dup2(devnull, 1);
    }
    ::execv(argv[0], argv.data());
    ::_exit(127);
  }
  ::close(cmd[0]);
  ::close(out[1]);
  to_chrome_ = cmd[1];
  from_chrome_ = out[0];
}

Chrome::~Chrome() {
  if (to_chrome_ >= 0) {
    ::close(to_chrome_);
  }
  if (from_chrome_ >= 0) {
    ::close(from_chrome_);
  }
  if (pid_ > 0) {
    ::kill(pid_, SIGTERM);
    int status = 0;
    for (int i = 0; i < 50; ++i) {
      if (::waitpid(pid_, &status, WNOHANG) == pid_) {
        return;
      }
      ::usleep(20000);
    }
    ::kill(pid_, SIGKILL);
    (void)::waitpid(pid_, &status, 0);
  }
}

nlohmann::json Chrome::call(const std::string& method, const nlohmann::json& params, const std::string& session,
                            std::chrono::milliseconds timeout) {
  const long id = next_id_++;
  nlohmann::json msg = {{"id", id}, {"method", method}, {"params", params}};
  if (!session.empty()) {
    msg["sessionId"] = session;
  }
  std::string text = msg.dump();
  text.push_back('\0');
  std::string_view rest(text);
  while (!rest.empty()) {
    const auto n = ::write(to_chrome_, rest.data(), rest.size());
    if (n <= 0) {
      secure_wipe(std::as_writable_bytes(std::span(text.data(), text.size())));
      throw CdpError("write to chrome failed");
    }
    rest.remove_prefix(static_cast<std::size_t>(n));
  }
  // Commands may carry plaintext for the instant of typing: wipe our copy.
  secure_wipe(std::as_writable_bytes(std::span(text.data(), text.size())));
  const auto deadline = monotonic_ns() + static_cast<std::uint64_t>(std::chrono::nanoseconds(timeout).count());
  std::array<char, 65536> chunk{};
  for (;;) {
    for (auto nul = buf_.find('\0'); nul != std::string::npos; nul = buf_.find('\0')) {
      auto reply = nlohmann::json::parse(buf_.substr(0, nul), nullptr, false);
      buf_.erase(0, nul + 1);
      if (reply.is_object() && reply.contains("id") && reply["id"] == id) {
        if (reply.contains("error")) {
          throw CdpError(method + ": " + reply["error"].value("message", "error"));
        }
        return reply.value("result", nlohmann::json::object());
      }
      // Events and stale replies are dropped; the shell polls state instead.
    }
    const auto now = monotonic_ns();
    if (now >= deadline) {
      throw CdpError(method + ": timeout");
    }
    pollfd pfd{from_chrome_, POLLIN, 0};
    const auto wait_ms = static_cast<int>((deadline - now) / 1000000U) + 1;
    if (::poll(&pfd, 1, wait_ms) <= 0) {
      continue;
    }
    const auto n = ::read(from_chrome_, chunk.data(), chunk.size());
    if (n <= 0) {
      throw CdpError("chrome closed the pipe");
    }
    buf_.append(chunk.data(), static_cast<std::size_t>(n));
  }
}

std::string Chrome::open_page() {
  const auto t = call("Target.createTarget", {{"url", "about:blank"}});
  const auto a = call("Target.attachToTarget", {{"targetId", t.at("targetId")}, {"flatten", true}});
  return a.at("sessionId").get<std::string>();
}

}  // namespace pl::core
