// core daemon (owner: LNX): Chrome + CDP + capture model + detect/sanitize + vault hand-off + actuator.
//   /run/pl/core.sock   agent <-> core (plain frames, JSON): open / observe / act / end
//   127.0.0.1:3128      loopback forwarder: Chrome's proxy -> /run/pl/gate-web.sock (browsing lane)
// Values detected on the page go to the vault at once (AD-12) over an encrypted channel;
// the agent only ever gets the sanitized page.
#include <poll.h>
#include <sys/prctl.h>
#include <sys/socket.h>

#include <atomic>
#include <csignal>
#include <cstdlib>
#include <mutex>
#include <sstream>
#include <thread>

#include "pl/channel.hpp"
#include "pl/contracts.hpp"
#include "pl/core/actuator.hpp"
#include "pl/core/capture.hpp"
#include "pl/core/cdp.hpp"
#include "pl/gate/http.hpp"
#include "pl/ids.hpp"
#include "pl/log.hpp"
#include "pl/null_detector.hpp"
#include "pl/uds.hpp"

namespace {

using namespace std::chrono_literals;
std::atomic<bool> g_stop{false};
void on_signal(int /*sig*/) { g_stop = true; }

std::string env_or(const char* name, std::string def) {
  const char* v = std::getenv(name);
  return v != nullptr && *v != '\0' ? std::string(v) : def;
}

pl::Logger& logger() {
  static pl::Logger log("core");
  return log;
}

void heartbeat(const std::string& component) {
  pl::MonotonicIds seq;
  while (!g_stop) {
    try {
      pl::FramedSocket s(pl::connect_unix(env_or("PL_GATE_LIVE_SOCK", "/run/pl/gate-live.sock")));
      while (!g_stop) {
        std::array<unsigned char, 16> nonce{};
        randombytes_buf(nonce.data(), nonce.size());
        std::array<char, 33> hex{};
        sodium_bin2hex(hex.data(), hex.size(), nonce.data(), nonce.size());
        s.send_json({{"schema", "liveness.v1"}, {"component", component}, {"kind", "pong"}, {"nonce", hex.data()},
                     {"seq", seq.next()}, {"sent_ns", pl::realtime_ns()}, {"status", "ok"}},
                    nullptr, 1000ms);
        std::this_thread::sleep_for(500ms);
      }
    } catch (const std::exception&) {
      std::this_thread::sleep_for(500ms);
    }
  }
}

void forwarder(int port) {
  auto listener = pl::gate::tcp_listen("127.0.0.1", port);
  while (!g_stop) {
    pollfd pfd{listener.get(), POLLIN, 0};
    if (::poll(&pfd, 1, 500) <= 0) {
      continue;
    }
    pl::Fd c(::accept4(listener.get(), nullptr, nullptr, SOCK_CLOEXEC));
    if (!c.valid()) {
      continue;
    }
    std::thread([fd = std::move(c)]() mutable {
      try {
        auto up = pl::connect_unix(env_or("PL_GATE_WEB_SOCK", "/run/pl/gate-web.sock"));
        pl::gate::splice_bidirectional(fd.get(), up.get());
      } catch (const std::exception&) {
      }
    }).detach();
  }
}

struct Session {
  std::string id;  // ss-<16 hex>
  std::uint64_t num = 0;
  std::unique_ptr<pl::core::CaptureModel> page;
  std::map<std::string, pl::core::VaultRef> placeholders;
  std::map<std::string, int> counters;  // per placeholder type
};

class Core {
 public:
  Core() : registry_(pl::contracts::Registry::load_dir(env_or("PL_SCHEMAS_DIR", "/usr/share/pl/schemas"))) {
    for (const auto& d : split(env_or("PL_ALLOWED_DOMAINS", ""))) {
      allowed_.insert(d);
    }
    std::vector<std::string> flags{"--headless", "--no-first-run", "--no-default-browser-check", "--disable-gpu",
                                   "--disable-dev-shm-usage", "--disable-extensions", "--disable-background-networking",
                                   "--disable-sync", "--metrics-recording-only", "--mute-audio",
                                   "--user-data-dir=/tmp/chrome-profile", "--window-size=1280,900",
                                   "--proxy-server=http://127.0.0.1:" + env_or("PL_FORWARDER_PORT", "3128"),
                                   "--proxy-bypass-list=<-loopback>"};
    if (env_or("PL_CHROME_NO_SANDBOX", "1") == "1") {
      flags.emplace_back("--no-sandbox");  // the container (gVisor/runc, no caps) is the sandbox
    }
    chrome_ = std::make_unique<pl::core::Chrome>(env_or("PL_CHROME", "/opt/chrome/chrome-headless-shell"), flags);
    cdp_session_ = chrome_->open_page();
    (void)chrome_->call("Page.enable", nlohmann::json::object(), cdp_session_);
    (void)chrome_->call("DOM.enable", nlohmann::json::object(), cdp_session_);
    detector_ = pl::detect::default_detector({});
    sanitizer_ = pl::detect::default_sanitizer({});
  }

  nlohmann::json handle(const nlohmann::json& cmd) {
    const std::lock_guard lock(mu_);
    const auto op = cmd.value("op", "");
    if (op == "open") {
      const auto sid = cmd.value("session_id", "");
      if (sid.size() != 19 || sid.rfind("ss-", 0) != 0) {
        return reply("rejected", "C-101");
      }
      end_session();
      session_ = std::make_unique<Session>();
      session_->id = sid;
      session_->num = std::stoull(sid.substr(3), nullptr, 16);
      pl::core::ActionVerdict nav;
      if (!navigate(cmd.value("url", ""))) {
        return reply("rejected", "C-107");
      }
      return observe("ok", "");
    }
    if (!session_) {
      return reply("rejected", "C-100");
    }
    if (op == "observe") {
      return observe("ok", "");
    }
    if (op == "end") {
      end_session();
      return reply("ok", "");
    }
    if (op == "act") {
      return act(cmd.value("action", nlohmann::json::object()));
    }
    return reply("rejected", "C-101");
  }

 private:
  static std::vector<std::string> split(const std::string& s) {
    std::vector<std::string> out;
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, ',')) {
      if (!item.empty()) {
        out.push_back(item);
      }
    }
    return out;
  }

  static nlohmann::json reply(const std::string& status, const std::string& rule) {
    nlohmann::json r = {{"schema", "core_reply.v0"}, {"status", status}};
    if (!rule.empty()) {
      r["rule_id"] = rule;
    }
    return r;
  }

  bool navigate(const std::string& url) {
    nlohmann::json nav = {{"kind", "navigate"}, {"url", url}};
    pl::core::CaptureModel empty;
    if (!pl::core::validate_action(nav, empty, {}, allowed_).ok) {
      return false;
    }
    (void)chrome_->call("Page.navigate", {{"url", url}}, cdp_session_);
    wait_ready();
    return true;
  }

  void wait_ready() {
    for (int i = 0; i < 100; ++i) {
      const auto r = chrome_->call("Runtime.evaluate", {{"expression", "document.readyState"}}, cdp_session_);
      if (r.contains("result") && r["result"].value("value", "") == "complete") {
        break;
      }
      std::this_thread::sleep_for(100ms);
    }
    std::this_thread::sleep_for(150ms);
  }

  std::string current_host() {
    const auto r = chrome_->call("Runtime.evaluate", {{"expression", "location.hostname"}}, cdp_session_);
    auto h = r.contains("result") ? r["result"].value("value", "") : std::string();
    return h.empty() ? std::string("blank") : h;
  }

  std::string vault_store(const pl::detect::Detection& d, std::string_view value) {
    const auto type = std::string(pl::to_string(d.category));
    std::string type_up = type;
    std::transform(type_up.begin(), type_up.end(), type_up.begin(),
                   [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    const int n = ++session_->counters[type_up];
    const std::string ph = "[REDACTED:" + type_up + "#" + std::to_string(n) + "]";
    nlohmann::json binding = {{"session_id", session_->id}, {"placeholder", ph}, {"field_type", type_up},
                              {"site", session_->page->host()}, {"element_id", "n" + std::to_string(d.node_id)}};
    nlohmann::json req = {{"schema", "vault_api.v1"}, {"op", "store"}, {"request_id", pl::format_id("rq", ids_.next())},
                          {"binding", binding}, {"plaintext", std::string(value)}};
    auto& ch = vault();
    ch.send_json(req, nullptr);
    req["plaintext"] = "";
    auto rep = ch.recv_json(registry_, 5000ms);
    if (!rep || (*rep)["op"] != "store.ok") {
      throw std::runtime_error("vault store failed");
    }
    session_->placeholders[ph] = {(*rep)["handle"].get<std::string>(), binding, type_up};
    return ph;
  }

  pl::SecureChannel& vault() {
    if (!vault_) {
      vault_ = std::make_unique<pl::SecureChannel>(pl::connect_unix(env_or("PL_VAULT_SOCK", "/run/pl/vault.sock")),
                                                   pl::SecureChannel::Role::client);
    }
    return *vault_;
  }

  nlohmann::json observe(const std::string& status, const std::string& rule) {
    const auto snap = chrome_->call("DOMSnapshot.captureSnapshot",
                                    {{"computedStyles", nlohmann::json::array()}, {"includeDOMRects", true}},
                                    cdp_session_);
    session_->page = std::make_unique<pl::core::CaptureModel>(pl::core::CaptureModel::from_cdp(snap, current_host()));
    session_->placeholders.clear();
    session_->counters.clear();
    const auto view = session_->page->view(ids_.next(), session_->num);
    const auto found = detector_->detect(view, {session_->num, 0, false});
    pl::detect::SanitizeContext ctx;
    ctx.session_id = session_->num;
    ctx.vault_store = [this](const pl::detect::Detection& d, std::string_view v) { return vault_store(d, v); };
    auto page = sanitizer_->sanitize(view, found, ctx);
    page.message["url_host"] = session_->page->host();
    auto r = reply(status, rule);
    r["page"] = std::move(page.message);
    r["detections"] = found.items.size();
    r["null_detector"] = pl::detect::using_null_detector();
    logger().info("core.observe", {{"nodes", static_cast<std::int64_t>(session_->page->nodes().size())},
                                   {"detections", static_cast<std::int64_t>(found.items.size())}});
    return r;
  }

  nlohmann::json call_on(std::uint32_t node, const std::string& fn, const nlohmann::json& args = nlohmann::json::array()) {
    const auto obj = chrome_->call("DOM.resolveNode", {{"backendNodeId", session_->page->backend_id(node)}}, cdp_session_);
    return chrome_->call("Runtime.callFunctionOn",
                         {{"objectId", obj.at("object").at("objectId")}, {"functionDeclaration", fn}, {"arguments", args}},
                         cdp_session_);
  }

  nlohmann::json act(const nlohmann::json& action) {
    const auto v = pl::core::validate_action(action, *session_->page, session_->placeholders, allowed_);
    if (!v.ok) {
      logger().warn("core.action_rejected", {{"rule", v.rule}});
      return observe("rejected", v.rule);
    }
    const auto kind = action["kind"].get<std::string>();
    if (kind == "done") {
      return reply("ok", "");
    }
    if (kind == "navigate") {
      (void)navigate(action["url"].get<std::string>());
    } else if (kind == "scroll") {
      (void)chrome_->call("Runtime.evaluate",
                          {{"expression", action["direction"] == "down" ? "window.scrollBy(0, 600)" : "window.scrollBy(0, -600)"}},
                          cdp_session_);
    } else if (kind == "click") {
      (void)call_on(v.node, "function(){this.scrollIntoView({block:'center'});this.click();}");
      wait_ready();
    } else if (kind == "select") {
      (void)call_on(v.node,
                    "function(o){for(const opt of this.options||[]){if(opt.text.trim()===o||opt.value===o){this.value=opt.value;"
                    "this.dispatchEvent(new Event('input',{bubbles:true}));this.dispatchEvent(new Event('change',{bubbles:true}));}}}",
                    {{{"value", action["option"]}}});
    } else if (kind == "fill") {
      if (!fill(v, action)) {
        return observe("rejected", "C-109");
      }
    }
    return observe("ok", "");
  }

  bool fill(const pl::core::ActionVerdict& v, const nlohmann::json& action) {
    std::string text;
    if (v.vault != nullptr) {
      // Binding is rebuilt with the CURRENT site: a value stored on one site can't be typed into another.
      auto binding = v.vault->binding;
      binding["site"] = session_->page->host();
      nlohmann::json req = {{"schema", "vault_api.v1"}, {"op", "decrypt"}, {"request_id", pl::format_id("rq", ids_.next())},
                            {"handle", v.vault->handle}, {"binding", binding}};
      auto& ch = vault();
      ch.send_json(req, nullptr);
      auto rep = ch.recv_json(registry_, 5000ms);
      if (!rep || (*rep)["op"] != "decrypt.ok") {
        logger().warn("core.vault_denied", {{"code", rep ? rep->value("error_code", "") : std::string("none")}});
        return false;
      }
      text = (*rep)["plaintext"].get<std::string>();
      (*rep)["plaintext"] = "";
    } else {
      text = action["text"].get<std::string>();
    }
    (void)call_on(v.node, "function(){this.focus();this.value='';}");
    (void)chrome_->call("DOM.focus", {{"backendNodeId", session_->page->backend_id(v.node)}}, cdp_session_);
    (void)chrome_->call("Input.insertText", {{"text", text}}, cdp_session_);
    pl::secure_wipe(std::as_writable_bytes(std::span(text.data(), text.size())));
    (void)call_on(v.node, "function(){this.dispatchEvent(new Event('change',{bubbles:true}));}");
    return true;
  }

  void end_session() {
    if (!session_) {
      return;
    }
    try {
      auto& ch = vault();
      ch.send_json({{"schema", "vault_api.v1"}, {"op", "shred"}, {"request_id", pl::format_id("rq", ids_.next())},
                    {"session_id", session_->id}},
                   nullptr);
      (void)ch.recv_json(registry_, 5000ms);
    } catch (const std::exception&) {
      vault_.reset();
    }
    detector_->on_session_end(session_->num);
    session_.reset();
  }

  std::mutex mu_;
  pl::contracts::Registry registry_;
  std::set<std::string> allowed_;
  std::unique_ptr<pl::core::Chrome> chrome_;
  std::string cdp_session_;
  std::unique_ptr<pl::detect::Detector> detector_;
  std::unique_ptr<pl::detect::Sanitizer> sanitizer_;
  std::unique_ptr<pl::SecureChannel> vault_;
  std::unique_ptr<Session> session_;
  pl::MonotonicIds ids_;
};

void serve_agent(pl::Fd fd, Core& core) {
  try {
    pl::FramedSocket s(std::move(fd), 1U << 24U);
    while (!g_stop) {
      auto f = s.recv(500ms);
      if (!f) {
        if (s.timed_out()) {
          continue;
        }
        return;
      }
      nlohmann::json out;
      try {
        out = core.handle(pl::parse_json_bounded(*f));
      } catch (const std::exception& e) {
        logger().error("core.command_failed", {});
        out = {{"schema", "core_reply.v0"}, {"status", "error"}, {"rule_id", "C-199"}};
      }
      s.send_json(out, nullptr, 10000ms);
    }
  } catch (const std::exception&) {
  }
}

}  // namespace

int main() {
  (void)::prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
  (void)std::signal(SIGTERM, on_signal);
  (void)std::signal(SIGINT, on_signal);
  (void)std::signal(SIGPIPE, SIG_IGN);
  if (sodium_init() < 0) {
    return 1;
  }
  std::thread(forwarder, std::stoi(env_or("PL_FORWARDER_PORT", "3128"))).detach();
  std::thread(heartbeat, std::string("core")).detach();
  Core core;
  auto listener = pl::listen_unix(env_or("PL_CORE_SOCK", "/run/pl/core.sock"));
  logger().info("core.started", {{"null_detector", pl::detect::using_null_detector()}});
  while (!g_stop) {
    if (auto c = pl::accept_unix(listener, 500ms)) {
      std::thread(serve_agent, std::move(*c), std::ref(core)).detach();
    }
  }
  return 0;
}
