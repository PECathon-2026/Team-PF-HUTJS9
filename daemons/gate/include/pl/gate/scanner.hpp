// Gate's independent re-check (owner: LNX; AD-11: written from the spec, shares
// nothing with core/detect). Finds values that must never leave on the AI lane.
#pragma once

#include <cstdint>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace pl::gate {

enum class FindingKind : std::uint8_t { card, aadhaar, pan, api_key, private_key, canary_token, canary_listed };

struct Finding {
  FindingKind kind;
  std::size_t begin = 0, end = 0;  // byte offsets in the scanned text (never the value itself in logs)
  [[nodiscard]] std::string_view rule_id() const noexcept;  // G-1xx: recheck, G-2xx: canary
};

// Canary registry: format-valued canaries (cards, Aadhaar, keys) listed per page,
// compared after removing separators and case-folding.
class CanaryRegistry {
 public:
  void add(std::string_view value);
  [[nodiscard]] bool empty() const noexcept { return normalised_.empty(); }
  [[nodiscard]] const std::set<std::string>& values() const noexcept { return normalised_; }

 private:
  std::set<std::string> normalised_;
};

[[nodiscard]] std::string normalise_for_canary(std::string_view s);

// Self-checking token PLCANARY-<16 Crockford base32>-<2 digits>, check = value mod 97.
[[nodiscard]] bool is_valid_canary_token(std::string_view body16, std::string_view check2);

[[nodiscard]] bool luhn_ok(std::string_view digits) noexcept;
[[nodiscard]] bool verhoeff_ok(std::string_view digits) noexcept;

// Every finding in `text`. Placeholders ([REDACTED:TYPE#n]) are skipped.
[[nodiscard]] std::vector<Finding> scan(std::string_view text, const CanaryRegistry& canaries);

}  // namespace pl::gate
