// Gate AI lane (owner: LNX). See ai_lane.hpp.
#include "pl/gate/ai_lane.hpp"

#include <sodium.h>

#include <fstream>
#include <stdexcept>

#include "pl/gate/http.hpp"

namespace pl::gate {
namespace {

std::string sha256_hex(std::string_view s) {
  std::array<unsigned char, crypto_hash_sha256_BYTES> h{};
  crypto_hash_sha256(h.data(), reinterpret_cast<const unsigned char*>(s.data()), s.size());
  std::string out(h.size() * 2 + 1, '\0');
  sodium_bin2hex(out.data(), out.size(), h.data(), h.size());
  out.pop_back();
  return out;
}

std::string canonical_messages(const nlohmann::json& messages) {
  // Same canonical form as WIN's replay.request_hash: sorted keys, compact, UTF-8.
  return messages.dump(-1, ' ', false, nlohmann::json::error_handler_t::strict);
}

}  // namespace

std::string payload_sha256(const nlohmann::json& messages) { return sha256_hex(canonical_messages(messages)); }

ReplayProvider::ReplayProvider(const std::filesystem::path& dir) {
  std::error_code ec;
  if (!std::filesystem::is_directory(dir, ec)) {
    return;
  }
  for (const auto& e : std::filesystem::recursive_directory_iterator(dir, ec)) {
    if (e.path().extension() != ".json") {
      continue;
    }
    std::ifstream in(e.path());
    auto j = nlohmann::json::parse(in, nullptr, false);
    if (j.is_object() && j.value("format", "") == "pl.replay.v1" && j.contains("name") && j.contains("steps")) {
      add_cassette(j["name"].get<std::string>(), j);
    }
  }
}

void ReplayProvider::add_cassette(const std::string& name, const nlohmann::json& cassette) {
  const std::lock_guard lock(mu_);
  cassettes_[name] = cassette;
}

std::optional<std::string> ReplayProvider::complete(const nlohmann::json& request) {
  const std::lock_guard lock(mu_);
  const auto name = request.at("model").get<std::string>();
  const auto it = cassettes_.find(name);
  if (it == cassettes_.end()) {
    return std::nullopt;
  }
  const auto& steps = it->second.at("steps");
  auto& pos = cursor_[{request.at("session_id").get<std::string>(), name}];
  if (pos >= steps.size()) {
    return std::nullopt;  // exhausted
  }
  const auto& step = steps.at(pos);
  if (step.contains("request_sha256") && step["request_sha256"] != payload_sha256(request.at("messages"))) {
    return std::nullopt;  // the prompt drifted from the recording
  }
  ++pos;
  return step.at("response").get<std::string>();
}

std::optional<std::string> OllamaProvider::complete(const nlohmann::json& request) {
  nlohmann::json body = {{"model", request.at("model")}, {"messages", request.at("messages")}, {"stream", false},
                         {"options", {{"temperature", request.value("temperature", 0.0)}, {"seed", 7}}}};
  auto resp = http_post_json(host_, port_, "/api/chat", body.dump(), std::chrono::seconds{120});
  if (!resp || resp->status != 200) {
    return std::nullopt;
  }
  auto j = nlohmann::json::parse(resp->body, nullptr, false);
  if (!j.is_object() || !j.contains("message") || !j["message"].contains("content")) {
    return std::nullopt;
  }
  return j["message"]["content"].get<std::string>();
}

void Liveness::beat(const std::string& component, std::uint64_t now_ns) {
  const std::lock_guard lock(mu_);
  last_[component] = now_ns;
}

bool Liveness::alive(const std::string& component, std::uint64_t now_ns) const {
  const std::lock_guard lock(mu_);
  const auto it = last_.find(component);
  if (it == last_.end() || it->second > now_ns) {
    return false;
  }
  return now_ns - it->second <= static_cast<std::uint64_t>(std::chrono::nanoseconds(window_).count());
}

LaneResult AiLane::process(const nlohmann::json& request) {
  const auto now = realtime_ns();
  const std::string decision_id = format_id("dc", ids_.next());
  nlohmann::json checks = nlohmann::json::array();
  const std::string request_id =
      request.is_object() && request.contains("request_id") && request["request_id"].is_string()
          ? request["request_id"].get<std::string>()
          : std::string("rq-0000000000000000");
  std::string provider_name = "replay";
  nlohmann::json egress = {{"schema", "egress_record.v1"}, {"record_id", format_id("eg", ids_.next())},
                           {"ts_ns", now},       {"lane", "ai"},
                           {"decision_id", decision_id}, {"bytes_out", 0}};

  auto block = [&](std::string_view check, std::string_view rule) {
    checks.push_back({{"check", check}, {"result", "fail"}, {"rule_id", rule}});
    egress["verdict"] = "blocked";
    egress["checks"] = checks;
    egress["request_id"] = request_id;
    egress["destination"] = {{"host", "blocked"}, {"port", 1}};
    LaneResult r;
    r.response = {{"schema", "gate_ai_response.v1"}, {"request_id", request_id}, {"status", "blocked"},
                  {"decision_id", decision_id}, {"rule_id", rule}};
    r.egress = egress;
    return r;
  };
  auto pass = [&](std::string_view check) { checks.push_back({{"check", check}, {"result", "pass"}}); };

  // 1. schema
  if (!validate_dispatch(validator_, request).ok || request.value("schema", "") != "gate_ai_request.v1") {
    return block("schema", "G-001");
  }
  pass("schema");
  egress["session_id"] = request["session_id"];
  // 2. kill switch
  if (killed_) {
    return block("kill_switch", "G-002");
  }
  pass("kill_switch");
  // 3. watchdog
  for (const auto& c : cfg_.required_live) {
    if (!liveness_.alive(c, now)) {
      return block("liveness", "G-003");
    }
  }
  pass("liveness");
  // 4. taint: only public leaves
  if (request["taint"] != "public") {
    return block("taint", "G-004");
  }
  pass("taint");
  // 5. allow-list
  provider_name = request["provider"].get<std::string>();
  const auto prov = providers_.find(provider_name);
  if (!cfg_.allowed_providers.contains(provider_name) || prov == providers_.end()) {
    return block("allow_list", "G-005");
  }
  pass("allow_list");
  if (cfg_.local_only && provider_name == "anthropic") {
    return block("local_only", "G-006");
  }
  pass("local_only");
  // 6. independent re-check + 7. canary over every outgoing string
  std::size_t bytes_out = 0;
  bool recheck_hit = false;
  bool canary_hit = false;
  std::string rule = "G-100";
  {
    const std::lock_guard lock(mu_);
    for (const auto& m : request["messages"]) {
      const auto& text = m["content"].get_ref<const std::string&>();
      bytes_out += text.size();
      for (const auto& f : scan(text, canaries_)) {
        const bool canary = f.kind == FindingKind::canary_token || f.kind == FindingKind::canary_listed;
        if (canary && !canary_hit) {
          canary_hit = true;
          if (!recheck_hit) {
            rule = std::string(f.rule_id());
          }
        }
        if (!canary && !recheck_hit) {
          recheck_hit = true;
          rule = std::string(f.rule_id());
        }
      }
    }
  }
  if (request.contains("images") && !request["images"].empty()) {
    // No gate OCR yet (Sprint 2): images can't be re-checked, so they don't leave.
    checks.push_back({{"check", "recheck_ocr"}, {"result", "fail"}, {"rule_id", "G-110"}});
    return block("recheck_text", "G-110");
  }
  if (recheck_hit) {
    return block("recheck_text", rule);
  }
  pass("recheck_text");
  if (canary_hit) {
    return block("canary", rule);
  }
  pass("canary");

  // Everything passed: send.
  egress["destination"] = {{"provider", provider_name}, {"host", prov->second->host()}, {"port", prov->second->port()}};
  egress["request_id"] = request_id;
  egress["payload"] = {{"messages", request["messages"]}, {"image_count", 0}};
  egress["payload_sha256"] = payload_sha256(request["messages"]);
  egress["bytes_out"] = bytes_out;
  const auto t0 = monotonic_ns();
  auto text = prov->second->complete(request);
  const auto latency = monotonic_ns() - t0;
  egress["verdict"] = "sent";
  egress["checks"] = checks;
  LaneResult r;
  if (!text) {
    egress["bytes_in"] = 0;
    r.response = {{"schema", "gate_ai_response.v1"}, {"request_id", request_id}, {"status", "error"},
                  {"decision_id", decision_id}, {"rule_id", "G-007"}, {"latency_ns", latency}};
  } else {
    egress["bytes_in"] = text->size();
    r.response = {{"schema", "gate_ai_response.v1"}, {"request_id", request_id}, {"status", "ok"},
                  {"decision_id", decision_id}, {"content", *text}, {"latency_ns", latency}};
  }
  r.egress = egress;
  return r;
}

}  // namespace pl::gate
