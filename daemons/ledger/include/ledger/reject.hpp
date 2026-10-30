// Metadata-only reject rules for the ledger bus (owner: WIN-B, spec §11).
//
// A message is rejected (fail-closed) when any object key anywhere in it is a
// banned value-carrying name, or when any string (key or value) contains a
// PLCANARY token. Rejections report a stable code and the JSON path of the
// first offence, never the offending value.
#pragma once

#include <optional>
#include <string>
#include <string_view>

#include <nlohmann/json.hpp>

namespace pl::ledger {

enum class RejectCode : unsigned char { banned_field, canary, canary_prefix, too_deep, unknown_schema, schema_invalid, oversize };

struct Rejection {
  RejectCode code;
  std::string path;  // JSON pointer built from keys of the offending message; "" for whole-message errors
};

[[nodiscard]] std::string_view detail_code(RejectCode c) noexcept;  // "banned_field", "canary", ...
[[nodiscard]] std::string_view rule_id(RejectCode c) noexcept;      // "LG-001", ...

[[nodiscard]] bool is_banned_field(std::string_view key) noexcept;  // case-insensitive

// Canary token: PLCANARY-<16 Crockford base32>-<2 digits>, check = (base-32
// value of the 16 chars) mod 97, zero padded to 2 digits.
inline constexpr std::string_view kCanaryPrefix = "PLCANARY-";
[[nodiscard]] int canary_check_digits(std::string_view body16);  // -1 when body16 is not 16 Crockford chars
[[nodiscard]] std::string make_canary(std::string_view body16);  // for tests and tooling; throws on bad body

enum class CanaryHit : unsigned char { none, prefix_only, valid };
// Case-insensitive; Crockford aliases (O->0, I/L->1) are tolerated so a mutated token still hits.
[[nodiscard]] CanaryHit scan_canary(std::string_view s) noexcept;

inline constexpr unsigned kMaxScanDepth = 32;

// First offence in `msg`, or nullopt when the message is clean.
[[nodiscard]] std::optional<Rejection> scan_message(const nlohmann::json& msg);

}  // namespace pl::ledger
