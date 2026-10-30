// Gate AI lane (owner: LNX): every check of spec §8 that Sprint 1 builds, in a
// fixed order, failing closed. The response to the agent and the egress record
// (the exact payload that left, "what the AI sees") come out together.
#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "pl/gate/scanner.hpp"
#include "pl/ids.hpp"
#include "pl/validate.hpp"

namespace pl::gate {

class Provider {
 public:
  Provider() = default;
  Provider(const Provider&) = delete;
  Provider& operator=(const Provider&) = delete;
  Provider(Provider&&) = delete;
  Provider& operator=(Provider&&) = delete;
  virtual ~Provider() = default;
  // Model text, or nullopt on any provider error (the lane then answers "error").
  [[nodiscard]] virtual std::optional<std::string> complete(const nlohmann::json& request) = 0;
  [[nodiscard]] virtual std::string host() const = 0;
  [[nodiscard]] virtual int port() const = 0;
};

// Deterministic recorded responses (AD-13). Cassettes use WIN's pl.replay.v1
// format; the request's `model` names the cassette. Steps are served in order
// per (session, cassette); a step with request_sha256 must match the request.
class ReplayProvider final : public Provider {
 public:
  explicit ReplayProvider(const std::filesystem::path& dir);
  void add_cassette(const std::string& name, const nlohmann::json& cassette);
  [[nodiscard]] std::optional<std::string> complete(const nlohmann::json& request) override;
  [[nodiscard]] std::string host() const override { return "replay"; }
  [[nodiscard]] int port() const override { return 1; }
  [[nodiscard]] std::size_t cassettes() const { return cassettes_.size(); }

 private:
  std::mutex mu_;
  std::map<std::string, nlohmann::json> cassettes_;
  std::map<std::pair<std::string, std::string>, std::size_t> cursor_;
};

// Ollama on the internal llm network: POST /api/chat, non-streaming.
class OllamaProvider final : public Provider {
 public:
  OllamaProvider(std::string host, int port) : host_(std::move(host)), port_(port) {}
  [[nodiscard]] std::optional<std::string> complete(const nlohmann::json& request) override;
  [[nodiscard]] std::string host() const override { return host_; }
  [[nodiscard]] int port() const override { return port_; }

 private:
  std::string host_;
  int port_;
};

// Watchdog state: components push liveness.v1 pongs; missing for > window = dead.
class Liveness {
 public:
  explicit Liveness(std::chrono::milliseconds window = std::chrono::milliseconds{2000}) : window_(window) {}
  void beat(const std::string& component, std::uint64_t now_ns);
  [[nodiscard]] bool alive(const std::string& component, std::uint64_t now_ns) const;

 private:
  std::chrono::milliseconds window_;
  mutable std::mutex mu_;
  std::map<std::string, std::uint64_t> last_;
};

struct GateConfig {
  std::set<std::string> allowed_providers{"replay"};
  bool local_only = true;                               // anthropic etc. refused
  std::vector<std::string> required_live{"core", "vault"};  // watchdog set
};

struct LaneResult {
  nlohmann::json response;  // gate_ai_response.v1 to the agent
  nlohmann::json egress;    // egress_record.v1 to the ledger / dashboard
};

class AiLane {
 public:
  AiLane(GateConfig cfg, const MessageValidator& validator, Liveness& liveness)
      : cfg_(std::move(cfg)), validator_(validator), liveness_(liveness) {}

  void add_provider(const std::string& name, std::shared_ptr<Provider> p) { providers_[name] = std::move(p); }
  void set_canaries(CanaryRegistry r) {
    const std::lock_guard lock(mu_);
    canaries_ = std::move(r);
  }
  void kill() noexcept { killed_ = true; }
  [[nodiscard]] bool killed() const noexcept { return killed_; }

  [[nodiscard]] LaneResult process(const nlohmann::json& request);

 private:
  GateConfig cfg_;
  const MessageValidator& validator_;
  Liveness& liveness_;
  std::map<std::string, std::shared_ptr<Provider>> providers_;
  std::mutex mu_;
  CanaryRegistry canaries_;
  std::atomic<bool> killed_{false};
  MonotonicIds ids_{};
};

// Canonical sha256 hex of the outgoing messages (as recorded in egress_record).
[[nodiscard]] std::string payload_sha256(const nlohmann::json& messages);

}  // namespace pl::gate
