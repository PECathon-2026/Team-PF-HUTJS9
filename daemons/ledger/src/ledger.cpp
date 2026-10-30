#include "ledger/ledger.hpp"

#include <algorithm>
#include <array>

#include "pl/ids.hpp"

namespace pl::ledger {

namespace {

constexpr std::array<std::string_view, 11> kAllowed = {
    "event.v1",          "decision_record.v1",    "egress_record.v1",
    "liveness.v1",       "isolation_counters.v1", "capability_report.v1",
    "attestation.v1",    "merkle_proof.v1",       "pipeline_timing.v1",
    "approval_token.v1", "browsing_policy.v1"};

std::string_view kind_of(std::string_view schema_id) {
  const auto dot = schema_id.rfind(".v");
  return dot == std::string_view::npos ? schema_id : schema_id.substr(0, dot);
}

}  // namespace

bool schema_allowed(std::string_view schema_id) noexcept {
  return std::ranges::any_of(kAllowed, [&](std::string_view a) { return a == schema_id; });
}

Ledger::Ledger(LedgerConfig cfg, const MessageValidator& validator)
    : cfg_(std::move(cfg)), validator_(validator), writer_(cfg_.segments) {}

std::uint64_t Ledger::store(std::string_view kind, const nlohmann::json& record) {
  std::uint64_t seq = 0;
  const std::string line = writer_.append(kind, record, realtime_ns(), &seq);
  nlohmann::json stored = nlohmann::json::parse(line);
  nlohmann::json const msg = {{"type", "entry"},
                              {"seq", stored["seq"]},
                              {"ts_ns", stored["ts_ns"]},
                              {"kind", stored["kind"]},
                              {"record", stored["record"]}};
  ring_sizes_.push_back(line.size());
  ring_bytes_ += line.size();
  ring_.push_back(msg);
  while (ring_.size() > cfg_.backlog_entries || (ring_bytes_ > cfg_.backlog_bytes && ring_.size() > 1)) {
    ring_bytes_ -= ring_sizes_.front();
    ring_sizes_.pop_front();
    ring_.pop_front();
  }
  if (sink_) {
    sink_(msg);
  }
  return seq;
}

IngestResult Ledger::reject(RejectCode code) {
  const std::string rule(rule_id(code));
  const std::string detail(detail_code(code));
  const bool is_canary = code == RejectCode::canary || code == RejectCode::canary_prefix;
  nlohmann::json const rec = {
      {"schema", "decision_record.v1"},
      {"decision_id", format_id("dec", ids_.next())},
      {"ts_ns", realtime_ns()},
      {"component", "ledger"},
      {"subject", "ingest"},
      {"verdict", "block"},
      {"rule_id", rule},
      {"evidence", nlohmann::json::array({{{"kind", is_canary ? "canary" : "format"}, {"detail_code", detail}}})},
  };
  ++rejected_;
  ++by_rule_[rule];
  IngestResult r;
  r.rule_id = rule;
  r.code = detail;
  if (const auto v = validator_.validate("decision_record.v1", rec); v.ok) {
    r.seq = store("decision_record", rec);
  }
  return r;
}

IngestResult Ledger::reject_unparsed(RejectCode code) { return reject(code); }

IngestResult Ledger::ingest(const nlohmann::json& message) {
  if (!message.is_object()) {
    return reject(RejectCode::schema_invalid);
  }
  if (auto rej = scan_message(message)) {
    return reject(rej->code);
  }
  const auto it = message.find("schema");
  if (it == message.end() || !it->is_string() || !schema_allowed(it->get_ref<const std::string&>())) {
    return reject(RejectCode::unknown_schema);
  }
  const std::string schema = it->get<std::string>();
  if (!validator_.validate(schema, message).ok) {
    return reject(RejectCode::schema_invalid);
  }
  IngestResult r;
  r.accepted = true;
  r.seq = store(kind_of(schema), message);
  ++accepted_;
  ++by_schema_[schema];
  return r;
}

std::vector<nlohmann::json> Ledger::subscribe_burst() const {
  std::vector<nlohmann::json> out;
  out.push_back({{"type", "hello"}, {"stream", "ledger.stream.v0"}, {"next_seq", writer_.next_seq()}});
  for (const auto& m : ring_) {
    out.push_back(m);
  }
  out.push_back(stats_message());
  return out;
}

nlohmann::json Ledger::stats_message() const {
  return {
      {"type", "stats"},         {"accepted", accepted_},       {"rejected", rejected_},         {"by_rule", by_rule_},
      {"by_schema", by_schema_}, {"head", writer_.head_hash()}, {"next_seq", writer_.next_seq()}};
}

}  // namespace pl::ledger
