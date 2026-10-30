// Pattern detection with check-digit validation (spec §4). Owner: WIN.
//
// Candidates come from two places:
//  - a hand-written digit-run scanner (cards, Aadhaar, phones, accounts, OTPs, PINs),
//    which tries every run of separator-delimited digit groups;
//  - one Hyperscan (Vectorscan-compatible) multi-pattern database for the
//    letter-shaped types (PAN, IFSC, email, UPI, API keys, JWT, canary, IPv4).
// Every candidate must then pass its validator (Luhn + issuer range, Verhoeff +
// first digit 2-9, PAN holder letter, ...). Ranges are in NORMALISED bytes.
#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "pl/taint.hpp"

namespace pl::detect {

// Rule numbers (decision records cite them as D-NN).
enum Rule : std::uint32_t {
  kRuleCard = 1, kRuleAadhaar = 2, kRulePan = 3, kRuleIfsc = 4, kRuleUpi = 5, kRuleEmail = 6, kRulePhone = 7,
  kRuleApiKey = 8, kRuleJwt = 9, kRuleCanary = 10, kRuleIp = 11, kRulePassword = 12, kRuleOtp = 13,
  kRuleAutocomplete = 14, kRuleBankAccount = 15, kRulePinCode = 16, kRuleLabel = 17,
};

struct Hit {
  std::size_t begin = 0, end = 0;  // normalised bytes
  TaintCategory category = TaintCategory::secret;
  std::uint32_t rule = 0;
  bool checksum = false;            // confirmed by a check digit
};

// Context that unlocks types which are only sensitive with a label nearby (spec §4).
struct ScanContext {
  bool otp = false;           // an OTP field signal is present
  bool account_label = false;  // "account", "A/c", "खाता" ...
  bool pin_label = false;      // "PIN code", "postal", "पिन"
};

// Validators (exposed for tests).
[[nodiscard]] bool luhn_ok(std::string_view digits) noexcept;
[[nodiscard]] bool verhoeff_ok(std::string_view digits) noexcept;
[[nodiscard]] bool card_iin_ok(std::string_view digits) noexcept;
[[nodiscard]] bool pan_ok(std::string_view s) noexcept;
[[nodiscard]] bool ifsc_ok(std::string_view s) noexcept;
[[nodiscard]] bool canary_ok(std::string_view s) noexcept;
[[nodiscard]] bool ipv4_ok(std::string_view s) noexcept;

class Scanner {
 public:
  Scanner();  // compiles the Hyperscan database once
  ~Scanner();
  Scanner(const Scanner&) = delete;
  Scanner& operator=(const Scanner&) = delete;
  Scanner(Scanner&&) = delete;
  Scanner& operator=(Scanner&&) = delete;

  // All validated hits in `text`, non-overlapping, leftmost-longest per family.
  [[nodiscard]] std::vector<Hit> scan(std::string_view text, const ScanContext& ctx) const;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace pl::detect
