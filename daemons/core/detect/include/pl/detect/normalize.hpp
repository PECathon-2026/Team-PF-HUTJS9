// Text clean-up before scanning (spec §4 "Text clean-up"). Owner: WIN.
//
// Maps look-alikes to ASCII (full-width forms, native decimal digits, common
// Cyrillic/Greek homoglyphs, exotic spaces) and drops invisible and bidi-control
// characters, while remembering, for every output byte, which source bytes it
// came from. Detections found in the normalised text are reported as byte ranges
// of the ORIGINAL string, so sanitize replaces exactly what's on the page.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace pl::detect {

struct Normalized {
  std::string text;                  // normalised UTF-8
  std::vector<std::uint32_t> begin;  // begin[i]: source byte where output byte i's code point starts
  std::vector<std::uint32_t> end;    // end[i]:   source byte just after that code point

  // Source byte range for normalised bytes [b, e). Requires b < e <= text.size().
  [[nodiscard]] std::uint32_t source_begin(std::size_t b) const { return begin[b]; }
  [[nodiscard]] std::uint32_t source_end(std::size_t e) const { return end[e - 1]; }
};

[[nodiscard]] Normalized normalize(std::string_view utf8);

// True for characters that render as nothing (zero-width, bidi controls, soft hyphen...).
[[nodiscard]] bool is_invisible(char32_t cp) noexcept;

}  // namespace pl::detect
