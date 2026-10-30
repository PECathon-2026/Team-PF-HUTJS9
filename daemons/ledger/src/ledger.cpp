#include "ledger/ledger.hpp"

#include <algorithm>
#include <sodium.h>
#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <cstdio>
#include <fstream>

#include <fcntl.h>

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

namespace {

Signer load_or_create_signer(const std::filesystem::path& dir) {
  const auto keyfile = dir / "ledger.key";
  SeedKey seed{};
  std::string hex;
  if (std::ifstream in(keyfile); in && std::getline(in, hex) && hex.size() == 64) {
    std::size_t len = 0;
    if (sodium_hex2bin(seed.data(), seed.size(), hex.c_str(), hex.size(), nullptr, &len, nullptr) != 0 ||
        len != seed.size()) {
      throw std::runtime_error("ledger: unreadable signing key " + keyfile.string());
    }
  } else {
    randombytes_buf(seed.data(), seed.size());
    std::string out(seed.size() * 2 + 1, '\0');
    sodium_bin2hex(out.data(), out.size(), seed.data(), seed.size());
    out.resize(seed.size() * 2);
    const int fd = ::open(keyfile.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) {
      throw std::runtime_error("ledger: cannot create signing key " + keyfile.string());
    }
    out += "\n";
    const bool ok = ::write(fd, out.data(), out.size()) == static_cast<ssize_t>(out.size());
    ::close(fd);
    sodium_memzero(out.data(), out.size());
    if (!ok) {
      throw std::runtime_error("ledger: cannot write signing key");
    }
  }
  Signer s = Signer::from_seed(seed);
  sodium_memzero(seed.data(), seed.size());
  std::string pub(s.pk.size() * 2 + 1, '\0');
  sodium_bin2hex(pub.data(), pub.size(), s.pk.data(), s.pk.size());
  pub.resize(s.pk.size() * 2);
  std::ofstream(dir / "ledger.pub", std::ios::trunc) << pub << "\n";
  return s;
}

}  // namespace

Ledger::Ledger(LedgerConfig cfg, const MessageValidator& validator)
    : cfg_(std::move(cfg)), validator_(validator), writer_(cfg_.segments), signer_(load_or_create_signer(cfg_.segments.dir)) {
  if (sodium_init() < 0) {
    throw std::runtime_error("sodium_init failed");
  }
  for (const auto& line : read_all_lines(cfg_.segments.dir)) {
    tree_.append(line);
  }
  // Heads already signed for the recovered entries need no new signature.
  if (std::ifstream in(cfg_.segments.dir / "sth.jsonl"); in) {
    std::string l;
    while (std::getline(in, l)) {
      const auto j = nlohmann::json::parse(l, nullptr, false);
      if (j.is_object() && j.contains("tree_size") && j["tree_size"].is_number_unsigned()) {
        if (j["tree_size"].get<std::uint64_t>() >= last_sth_size_) {
          last_sth_size_ = j["tree_size"].get<std::uint64_t>();
          last_sth_msg_ = sth_stream_message(j);
        }
      }
    }
  }
}

nlohmann::json Ledger::sth_stream_message(nlohmann::json sth) const {
  sth["type"] = "sth";
  std::string h(signer_.pk.size() * 2 + 1, '\0');
  sodium_bin2hex(h.data(), h.size(), signer_.pk.data(), signer_.pk.size());
  h.resize(signer_.pk.size() * 2);
  sth["public_key"] = h;
  return sth;
}

std::optional<nlohmann::json> Ledger::publish_sth() {
  if (tree_.size() == 0 || tree_.size() == last_sth_size_) {
    return std::nullopt;
  }
  nlohmann::json sth = make_sth(signer_, tree_.size(), tree_.root(), realtime_ns());
  std::ofstream(cfg_.segments.dir / "sth.jsonl", std::ios::app) << sth.dump() << "\n";
  last_sth_size_ = tree_.size();
  last_sth_msg_ = sth_stream_message(sth);
  return last_sth_msg_;
}

std::uint64_t Ledger::store(std::string_view kind, const nlohmann::json& record) {
  std::uint64_t seq = 0;
  const std::string line = writer_.append(kind, record, realtime_ns(), &seq);
  nlohmann::json stored = nlohmann::json::parse(line);
  nlohmann::json const msg = {{"type", "entry"},
                              {"seq", stored["seq"]},
                              {"ts_ns", stored["ts_ns"]},
                              {"kind", stored["kind"]},
                              {"record", stored["record"]},
                              {"line", line}};  // exact bytes of the entry, so clients can recompute its leaf hash
  tree_.append(line);
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
  if (last_sth_msg_) {
    out.push_back(*last_sth_msg_);
  }
  out.push_back(stats_message());
  return out;
}

nlohmann::json Ledger::stats_message() const {
  return {
      {"type", "stats"},         {"accepted", accepted_},       {"rejected", rejected_},         {"by_rule", by_rule_},
      {"by_schema", by_schema_}, {"head", writer_.head_hash()}, {"next_seq", writer_.next_seq()},
      {"tree_size", tree_.size()},  {"root", to_hex(tree_.root())},   {"key_id", signer_.key_id()}};
}

}  // namespace pl::ledger
