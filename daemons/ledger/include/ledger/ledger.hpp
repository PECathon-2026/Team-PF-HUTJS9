// Ledger core: validate, scan, append, publish (owner: WIN-B, spec §11).
//
// ingest() is the only way a message gets onto the bus. Order of checks (all
// fail-closed): bounded-depth scan for banned field names and canaries, schema
// allow-list (metadata and sanitized zones only), full contract validation.
// A rejected message is never stored; instead the ledger records its own
// decision_record (component "ledger", verdict "block", rule LG-00x) that holds
// only the rule ID and a detail code, never the offending content.
#pragma once

#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <vector>

#include "ledger/merkle.hpp"
#include "ledger/reject.hpp"
#include "ledger/segment.hpp"
#include "pl/ids.hpp"
#include "pl/validate.hpp"

namespace pl::ledger {

struct LedgerConfig {
  SegmentConfig segments;
  std::size_t backlog_entries = 1000;
  std::size_t backlog_bytes = std::size_t{32} * 1024 * 1024;
};

struct IngestResult {
  bool accepted = false;
  std::uint64_t seq = 0;  // seq of the stored entry (accepted) or of the ledger's own rejection record
  std::string rule_id;    // set when rejected
  std::string code;       // set when rejected
};

[[nodiscard]] bool schema_allowed(std::string_view schema_id) noexcept;

class Ledger {
 public:
  using Sink = std::function<void(const nlohmann::json& stream_message)>;

  Ledger(LedgerConfig cfg, const MessageValidator& validator);

  void set_sink(Sink sink) { sink_ = std::move(sink); }
  IngestResult ingest(const nlohmann::json& message);
  // Records a rejection for input that never parsed as a message (bad frame, malformed JSON).
  IngestResult reject_unparsed(RejectCode code);

  // Stream messages for a new subscriber: hello first, then the retained entries.
  [[nodiscard]] std::vector<nlohmann::json> subscribe_burst() const;
  [[nodiscard]] nlohmann::json stats_message() const;
  [[nodiscard]] std::uint64_t next_seq() const noexcept { return writer_.next_seq(); }

  // Merkle log over the entries (leaf i = entry seq i+1). The signing key is created on first start in
  // <dir>/ledger.key (mode 0600, seed hex); the public key is written to <dir>/ledger.pub.
  [[nodiscard]] const MerkleTree& tree() const noexcept { return tree_; }
  [[nodiscard]] const PublicKey& public_key() const noexcept { return signer_.pk; }
  // When the tree grew since the last signed head: signs it, appends it to <dir>/sth.jsonl and returns the
  // stream message {"type":"sth", ...sth}.
  std::optional<nlohmann::json> publish_sth();

 private:
  [[nodiscard]] nlohmann::json sth_stream_message(nlohmann::json sth) const;
  IngestResult reject(RejectCode code);
  std::uint64_t store(std::string_view kind, const nlohmann::json& record);

  LedgerConfig cfg_;
  const MessageValidator& validator_;
  SegmentWriter writer_;
  MerkleTree tree_;
  Signer signer_;
  std::uint64_t last_sth_size_ = 0;
  std::optional<nlohmann::json> last_sth_msg_;
  MonotonicIds ids_;
  Sink sink_;
  std::deque<nlohmann::json> ring_;
  std::deque<std::size_t> ring_sizes_;
  std::size_t ring_bytes_ = 0;
  std::uint64_t accepted_ = 0;
  std::uint64_t rejected_ = 0;
  std::map<std::string, std::uint64_t> by_rule_;
  std::map<std::string, std::uint64_t> by_schema_;
};

}  // namespace pl::ledger
