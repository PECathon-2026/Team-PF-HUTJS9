// Offline audit of a ledger directory (owner: WIN-B). Used by the `pl-audit` CLI and tests.
#pragma once

#include <cstdint>
#include <filesystem>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <vector>

#include "ledger/merkle.hpp"

namespace pl::ledger {

struct AuditReport {
  bool ok = false;
  std::uint64_t entries = 0;
  std::uint64_t heads = 0;
  bool entry0_is_attestation = false;
  std::string root_hex;  // recomputed root over all entries
  std::vector<std::string> errors;
};

// Checks: hash chain and seq continuity; every signed tree head verifies under `pk` and matches the root
// recomputed from the entries; consecutive heads are consistent (RFC 9162 consistency proofs).
[[nodiscard]] AuditReport audit_verify(const std::filesystem::path& dir, const PublicKey& pk);
// Inclusion proof for entry `seq` against the newest signed head covering it (unsigned computation; the head is
// the signed one stored in sth.jsonl). nullopt when no stored head covers the entry.
[[nodiscard]] std::optional<nlohmann::json> audit_inclusion_proof(const std::filesystem::path& dir, std::uint64_t seq);
// Consistency proof between two stored heads' sizes.
[[nodiscard]] std::optional<nlohmann::json> audit_consistency_proof(const std::filesystem::path& dir, std::uint64_t first,
                                                                    std::uint64_t second);
[[nodiscard]] std::optional<PublicKey> read_public_key(const std::filesystem::path& file);

}  // namespace pl::ledger
