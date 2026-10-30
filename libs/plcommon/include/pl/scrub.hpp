// Log scrubber (owner: LNX, spec §11 "Log scrubber").
//
// Independent PII patterns (not shared with WIN's detectors), replaced by type
// tags. Deliberately aggressive: logs need no numbers or tokens in free text.
//   [KEY]     known key/token prefixes (sk-, ghp_, github_pat_, AKIA, hf_, xox?-, AIza ...) + 8 token chars
//   [JWT]     eyJ<b64url>.<b64url>.<b64url>
//   [EMAIL]   local@domain.tld
//   [PAN]     AAAAA9999A at word boundaries
//   [CARD]    13-19 digits passing Luhn
//   [AADHAAR] 12 digits, first 2-9, passing Verhoeff
//   [NUMBER]  any other run of >= 6 digits
// Digit runs may be split by up to two separator characters (" .-/_\t") at a time.
// Python twin: plpy.scrub. Both are tested against testdata/scrubber_vectors.json.
#pragma once

#include <string>
#include <string_view>

namespace pl {

[[nodiscard]] std::string scrub(std::string_view s);

// Check digits, exposed for tests and for other LNX code (the gate has its own).
[[nodiscard]] bool luhn_valid(std::string_view digits) noexcept;
[[nodiscard]] bool verhoeff_valid(std::string_view digits) noexcept;

}  // namespace pl
