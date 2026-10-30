// gate daemon (owner: LNX). The only networked PrivacyLens container (AD-05).
//   /run/pl/gate-ai.sock    AI lane: gate_ai_request.v1 -> gate_ai_response.v1 (agent)
//   /run/pl/gate-live.sock  watchdog: liveness.v1 pongs from core, vault, agent
//   /run/pl/gate-web.sock   browsing lane: HTTP proxy (CONNECT + absolute-form) for core's forwarder
//   0.0.0.0:8787 (published on 127.0.0.1 only): dashboard/dist, /api/egress, /api/stream (SSE), /api/kill
#include <poll.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <condition_variable>
#include <csignal>
#include <cstdlib>
#include <deque>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <thread>

#include "pl/contracts.hpp"
#include "pl/gate/ai_lane.hpp"
#include "pl/gate/http.hpp"
#include "pl/log.hpp"
#include "pl/uds.hpp"

namespace {

using namespace std::chrono_literals;
namespace fs = std::filesystem;

std::atomic<bool> g_stop{false};
void on_signal(int /*sig*/) { g_stop = true; }

std::string env_or(const char* name, std::string def) {
  const char* v = std::getenv(name);
  return v != nullptr && *v != '\0' ? std::string(v) : def;
}

std::vector<std::string> split_csv(const std::string& s) {
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

pl::Logger& logger() {
  static pl::Logger log("gate");
  return log;
}

// Recent egress records + SSE fan-out ("what the AI sees").
class EgressHub {
 public:
  void publish(const nlohmann::json& rec) {
    {
      const std::lock_guard lock(mu_);
      recent_.push_back(rec);
      if (recent_.size() > 500) {
        recent_.pop_front();
      }
      ++seq_;
    }
    cv_.notify_all();
    forward_to_ledger(rec);
  }
  [[nodiscard]] nlohmann::json snapshot() const {
    const std::lock_guard lock(mu_);
    return nlohmann::json(recent_);
  }
  // Blocks until something newer than `seen` exists; returns the new items.
  std::vector<nlohmann::json> wait_after(std::size_t& seen) {
    std::unique_lock lock(mu_);
    cv_.wait_for(lock, 15s, [&] { return seq_ > seen || g_stop.load(); });
    std::vector<nlohmann::json> out;
    const std::size_t fresh = std::min<std::size_t>(seq_ - seen, recent_.size());
    for (std::size_t i = recent_.size() - fresh; i < recent_.size(); ++i) {
      out.push_back(recent_[i]);
    }
    seen = seq_;
    return out;
  }
  [[nodiscard]] std::size_t seq() const {
    const std::lock_guard lock(mu_);
    return seq_;
  }

 static void forward_to_ledger(const nlohmann::json& rec) {
    // Best effort until WIN-B's ledger is wired in: the record is also kept here.
    try {
      pl::FramedSocket s(pl::connect_unix(env_or("PL_LEDGER_SOCK", "/run/pl/ledger.sock")));
      s.send_json(rec, nullptr, 500ms);
    } catch (const std::exception&) {
      // ledger not up
    }
  }
 private:
  mutable std::mutex mu_;
  std::condition_variable cv_;
  std::deque<nlohmann::json> recent_;
  std::size_t seq_ = 0;
};

struct Gate {
  pl::contracts::Registry registry;
  pl::gate::Liveness liveness;
  std::unique_ptr<pl::gate::AiLane> lane;
  EgressHub hub;
  std::set<std::string> allowed_domains;
  std::string dashboard_dir;
  pl::MonotonicIds ids;
};

void serve_ai(pl::Fd fd, Gate& g) {
  try {
    pl::FramedSocket s(std::move(fd));
    while (!g_stop) {
      auto frame = s.recv(500ms);
      if (!frame) {
        if (s.timed_out()) {
          continue;
        }
        return;
      }
      nlohmann::json req;
      try {
        req = pl::parse_json_bounded(*frame);
      } catch (const std::exception&) {
        req = nullptr;  // schema check below blocks it
      }
      auto r = g.lane->process(req);
      g.hub.publish(r.egress);
      s.send_json(r.response, nullptr);
      logger().info("egress.decision", {{"verdict", r.egress.value("verdict", "")},
                                        {"rule", r.response.value("rule_id", "")}});
    }
  } catch (const std::exception&) {
  }
}

void serve_live(pl::Fd fd, Gate& g) {
  try {
    pl::FramedSocket s(std::move(fd));
    while (!g_stop) {
      auto m = s.recv_json(g.registry, 3000ms);
      if (!m) {
        if (s.timed_out()) {
          continue;
        }
        return;
      }
      if ((*m)["schema"] == "liveness.v1") {
        g.liveness.beat((*m)["component"].get<std::string>(), pl::realtime_ns());
      }
    }
  } catch (const std::exception&) {
  }
}

void browsing_record(Gate& g, const std::string& host, int port, bool sent) {
  nlohmann::json rec = {{"schema", "egress_record.v1"}, {"record_id", pl::format_id("eg", g.ids.next())},
                        {"ts_ns", pl::realtime_ns()},   {"lane", "browsing"},
                        {"verdict", sent ? "sent" : "blocked"},
                        {"decision_id", pl::format_id("dc", g.ids.next())},
                        {"destination", {{"host", host}, {"port", port}}},
                        {"bytes_out", 0},
                        {"checks", {{{"check", "domain"}, {"result", sent ? "pass" : "fail"}}}}};
  if (!sent) {
    rec["checks"][0]["rule_id"] = "G-301";
  }
  if (!pl::validate_dispatch(g.registry, rec).ok) {
    rec["destination"]["host"] = "invalid";
  }
  g.hub.publish(rec);
}

void serve_web(pl::Fd fd, Gate& g) {
  auto req = pl::gate::read_request(fd.get(), 64 * 1024, 10s);
  if (!req) {
    return;
  }
  std::optional<std::pair<std::string, int>> hp;
  bool connect = req->method == "CONNECT";
  std::string forward;
  if (connect) {
    hp = pl::gate::split_host_port(req->target, 443);
  } else if (req->target.rfind("http://", 0) == 0) {
    const auto rest = std::string_view(req->target).substr(7);
    const auto slash = rest.find('/');
    hp = pl::gate::split_host_port(rest.substr(0, slash), 80);
    const std::string path = slash == std::string_view::npos ? "/" : std::string(rest.substr(slash));
    // Origin-form request line; drop proxy headers; force close so each request is checked.
    std::string head = req->method + " " + path + " " + req->version + "\r\n";
    std::istringstream hs(req->head.substr(req->head.find("\r\n") + 2));
    std::string line;
    while (std::getline(hs, line) && line != "\r") {
      std::string lower = line;
      std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
      if (lower.rfind("proxy-", 0) == 0 || lower.rfind("connection:", 0) == 0 || lower.rfind("keep-alive", 0) == 0) {
        continue;
      }
      head += line + "\n";
    }
    head += "Connection: close\r\n\r\n";
    forward = head + req->rest;
  }
  const bool allowed = hp && !g.lane->killed() && g.allowed_domains.contains(hp->first);
  browsing_record(g, hp ? hp->first : "invalid", hp ? hp->second : 1, allowed);
  if (!allowed) {
    (void)pl::gate::write_all(fd.get(), "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    return;
  }
  auto up = pl::gate::tcp_connect(hp->first, hp->second, 10s);
  if (!up.valid()) {
    (void)pl::gate::write_all(fd.get(), "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    return;
  }
  if (connect) {
    if (!pl::gate::write_all(fd.get(), "HTTP/1.1 200 Connection Established\r\n\r\n")) {
      return;
    }
    if (!req->rest.empty() && !pl::gate::write_all(up.get(), req->rest)) {
      return;
    }
  } else if (!pl::gate::write_all(up.get(), forward)) {
    return;
  }
  pl::gate::splice_bidirectional(fd.get(), up.get());
}

std::string content_type(const fs::path& p) {
  const auto e = p.extension().string();
  if (e == ".html") return "text/html; charset=utf-8";
  if (e == ".js") return "text/javascript";
  if (e == ".css") return "text/css";
  if (e == ".svg") return "image/svg+xml";
  if (e == ".png") return "image/png";
  if (e == ".json") return "application/json";
  if (e == ".woff2") return "font/woff2";
  return "application/octet-stream";
}

void respond(int fd, int status, std::string_view type, std::string_view body) {
  const char* reason = status == 200 ? "OK" : status == 404 ? "Not Found" : status == 403 ? "Forbidden" : "Bad Request";
  std::string head = "HTTP/1.1 " + std::to_string(status) + " " + reason + "\r\nContent-Type: " + std::string(type) +
                     "\r\nContent-Length: " + std::to_string(body.size()) +
                     "\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n";
  (void)pl::gate::write_all(fd, head);
  (void)pl::gate::write_all(fd, body);
}

void relay_ledger_stream(int fd, Gate& g) {
  // SSE: our own egress records, plus WIN-B's ledger metadata stream when it is up.
  (void)pl::gate::write_all(fd, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-store\r\n"
                                "Connection: close\r\n\r\n");
  std::atomic<bool> done{false};
  std::thread ledger([&] {
    try {
      pl::FramedSocket s(pl::connect_unix(env_or("PL_LEDGER_STREAM_SOCK", "/run/pl/ledger-stream.sock")));
      while (!done && !g_stop) {
        auto f = s.recv(1000ms);
        if (!f) {
          if (s.timed_out()) {
            continue;
          }
          return;
        }
        auto m = pl::parse_json_bounded(*f);
        if (!pl::gate::write_all(fd, "event: ledger\ndata: " + m.dump() + "\n\n")) {
          return;
        }
      }
    } catch (const std::exception&) {
    }
  });
  std::size_t seen = 0;
  for (const auto& rec : g.hub.snapshot()) {
    if (!pl::gate::write_all(fd, "event: egress\ndata: " + rec.dump() + "\n\n")) {
      done = true;
    }
  }
  seen = g.hub.seq();
  while (!done && !g_stop) {
    auto fresh = g.hub.wait_after(seen);
    if (fresh.empty() && !pl::gate::write_all(fd, ": keep-alive\n\n")) {
      break;
    }
    for (const auto& rec : fresh) {
      if (!pl::gate::write_all(fd, "event: egress\ndata: " + rec.dump() + "\n\n")) {
        done = true;
        break;
      }
    }
  }
  done = true;
  ledger.join();
}

void serve_ui(pl::Fd fd, Gate& g) {
  auto req = pl::gate::read_request(fd.get(), 16 * 1024, 10s);
  if (!req) {
    return;
  }
  // Only same-origin requests from the local dashboard may change state.
  const auto host = req->headers.contains("host") ? req->headers["host"] : "";
  if (host != "127.0.0.1:8787" && host != "localhost:8787" && host.rfind("gate:", 0) != 0) {
    respond(fd.get(), 403, "text/plain", "forbidden host");
    return;
  }
  const std::string path = req->target.substr(0, req->target.find('?'));
  if (req->method == "POST" && path == "/api/kill") {
    g.lane->kill();
    logger().warn("gate.kill_switch", {});
    nlohmann::json ev = {{"schema", "event.v1"}, {"event_id", pl::format_id("ev", g.ids.next())},
                         {"ts_ns", pl::realtime_ns()}, {"component", "gate"}, {"type", "gate.kill_switch"}};
    EgressHub::forward_to_ledger(ev);
    respond(fd.get(), 200, "application/json", R"({"killed":true})");
    return;
  }
  if (req->method != "GET") {
    respond(fd.get(), 400, "text/plain", "bad method");
    return;
  }
  if (path == "/api/egress") {
    respond(fd.get(), 200, "application/json", g.hub.snapshot().dump());
    return;
  }
  if (path == "/api/status") {
    const auto now = pl::realtime_ns();
    nlohmann::json st = {{"killed", g.lane->killed()}};
    for (const char* c : {"core", "vault", "agent", "ledger"}) {
      st["live"][c] = g.liveness.alive(c, now);
    }
    respond(fd.get(), 200, "application/json", st.dump());
    return;
  }
  if (path == "/api/stream") {
    relay_ledger_stream(fd.get(), g);
    return;
  }
  // Static dashboard; no traversal outside the dist directory.
  const fs::path root = fs::weakly_canonical(g.dashboard_dir);
  fs::path file = fs::weakly_canonical(root / (path == "/" ? "index.html" : path.substr(1)));
  const auto rel = file.lexically_relative(root);
  if (rel.empty() || rel.native().rfind("..", 0) == 0) {
    respond(fd.get(), 404, "text/plain", "not found");
    return;
  }
  std::error_code ec;
  if (!fs::is_regular_file(file, ec)) {
    file = root / "index.html";  // SPA fallback
    if (!fs::is_regular_file(file, ec)) {
      respond(fd.get(), 404, "text/plain", "dashboard not built (make dashboard)");
      return;
    }
  }
  std::ifstream in(file, std::ios::binary);
  const std::string body((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  respond(fd.get(), 200, content_type(file), body);
}

template <typename F>
void accept_loop(pl::Fd listener, Gate& g, F handler, bool is_tcp) {
  while (!g_stop) {
    if (is_tcp) {
      pollfd pfd{listener.get(), POLLIN, 0};
      if (::poll(&pfd, 1, 500) <= 0) {
        continue;
      }
      pl::Fd c(::accept4(listener.get(), nullptr, nullptr, SOCK_CLOEXEC));
      if (c.valid()) {
        std::thread(handler, std::move(c), std::ref(g)).detach();
      }
    } else if (auto c = pl::accept_unix(listener, 500ms)) {
      std::thread(handler, std::move(*c), std::ref(g)).detach();
    }
  }
}

pl::gate::CanaryRegistry load_canaries(const std::string& dir) {
  pl::gate::CanaryRegistry reg;
  std::error_code ec;
  if (!fs::is_directory(dir, ec)) {
    return reg;
  }
  for (const auto& e : fs::recursive_directory_iterator(dir, ec)) {
    if (e.path().extension() != ".json") {
      continue;
    }
    std::ifstream in(e.path());
    auto j = nlohmann::json::parse(in, nullptr, false);
    if (!j.is_object() || !j.contains("canaries") || !j["canaries"].is_array()) {
      continue;
    }
    for (const auto& c : j["canaries"]) {
      if (c.is_string()) {
        reg.add(c.get<std::string>());
      } else if (c.is_object() && c.contains("value") && c["value"].is_string()) {
        reg.add(c["value"].get<std::string>());
      }
    }
  }
  return reg;
}

}  // namespace

int main() {
  (void)::prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
  (void)std::signal(SIGTERM, on_signal);
  (void)std::signal(SIGINT, on_signal);
  (void)std::signal(SIGPIPE, SIG_IGN);
  Gate g{pl::contracts::Registry::load_dir(env_or("PL_SCHEMAS_DIR", "/usr/share/pl/schemas")), pl::gate::Liveness{},
         nullptr, {}, {}, env_or("PL_DASHBOARD_DIR", "/srv/dashboard"), {}};
  pl::gate::GateConfig cfg;
  cfg.allowed_providers.clear();
  for (const auto& p : split_csv(env_or("PL_GATE_PROVIDERS", "replay"))) {
    cfg.allowed_providers.insert(p);
  }
  cfg.required_live = split_csv(env_or("PL_GATE_REQUIRE_LIVE", "core,vault"));
  cfg.local_only = env_or("PL_LOCAL_ONLY", "1") == "1";
  for (const auto& d : split_csv(env_or("PL_ALLOWED_DOMAINS", ""))) {
    g.allowed_domains.insert(d);
  }
  g.lane = std::make_unique<pl::gate::AiLane>(cfg, g.registry, g.liveness);
  auto replay = std::make_shared<pl::gate::ReplayProvider>(env_or("PL_REPLAY_DIR", "/etc/pl/replay"));
  g.lane->add_provider("replay", replay);
  g.lane->add_provider("ollama", std::make_shared<pl::gate::OllamaProvider>(env_or("PL_OLLAMA_HOST", "ollama"), 11434));
  auto canaries = load_canaries(env_or("PL_CANARY_DIR", "/etc/pl/canaries"));
  const auto n_canaries = canaries.values().size();
  g.lane->set_canaries(std::move(canaries));

  std::vector<std::thread> loops;
  loops.emplace_back(accept_loop<decltype(&serve_ai)>, pl::listen_unix(env_or("PL_GATE_AI_SOCK", "/run/pl/gate-ai.sock")),
                     std::ref(g), &serve_ai, false);
  loops.emplace_back(accept_loop<decltype(&serve_live)>,
                     pl::listen_unix(env_or("PL_GATE_LIVE_SOCK", "/run/pl/gate-live.sock")), std::ref(g), &serve_live,
                     false);
  loops.emplace_back(accept_loop<decltype(&serve_web)>,
                     pl::listen_unix(env_or("PL_GATE_WEB_SOCK", "/run/pl/gate-web.sock")), std::ref(g), &serve_web,
                     false);
  loops.emplace_back(accept_loop<decltype(&serve_ui)>,
                     pl::gate::tcp_listen(env_or("PL_UI_ADDR", "0.0.0.0"), std::stoi(env_or("PL_UI_PORT", "8787"))),
                     std::ref(g), &serve_ui, true);
  logger().info("gate.started", {{"cassettes", static_cast<std::int64_t>(replay->cassettes())},
                                 {"canaries", static_cast<std::int64_t>(n_canaries)},
                                 {"domains", static_cast<std::int64_t>(g.allowed_domains.size())}});
  for (auto& t : loops) {
    t.join();
  }
  return 0;
}
