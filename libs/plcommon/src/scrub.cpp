#include "pl/scrub.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <utility>

namespace pl {

namespace {

constexpr std::size_t kTokenMin = 8;
constexpr std::size_t kCardMin = 13;
constexpr std::size_t kCardMax = 19;
constexpr std::size_t kAadhaarLen = 12;
constexpr std::size_t kNumberMin = 6;  // catches 6-digit OTPs and PINs
constexpr std::size_t kMaxSeparator = 2;

constexpr std::array<std::string_view, 16> kKeyPrefixes = {
    "github_pat_", "sk-ant-", "sk-proj-", "sk-", "ghp_", "gho_", "ghu_", "ghs_",
    "ghr_",        "AKIA",    "ASIA",     "hf_", "xoxb-", "xoxp-", "xoxa-", "AIza"};

bool is_digit(char c) noexcept { return c >= '0' && c <= '9'; }
bool is_upper(char c) noexcept { return c >= 'A' && c <= 'Z'; }
bool is_alpha(char c) noexcept { return is_upper(c) || (c >= 'a' && c <= 'z'); }
bool is_alnum(char c) noexcept { return is_alpha(c) || is_digit(c); }
bool is_token(char c) noexcept { return is_alnum(c) || c == '_' || c == '-'; }
bool is_local(char c) noexcept { return is_alnum(c) || c == '.' || c == '_' || c == '%' || c == '+' || c == '-'; }
bool is_domain(char c) noexcept { return is_alnum(c) || c == '.' || c == '-'; }

bool word_start(std::string_view s, std::size_t i) noexcept { return i == 0 || !is_token(s[i - 1]); }

std::size_t run(std::string_view s, std::size_t i, bool (*pred)(char) noexcept) noexcept {
  std::size_t j = i;
  while (j < s.size() && pred(s[j])) {
    ++j;
  }
  return j;
}

// Each matcher returns the end of a match starting at i.
std::optional<std::size_t> match_key(std::string_view s, std::size_t i) noexcept {
  if (!word_start(s, i)) {
    return std::nullopt;
  }
  for (const auto prefix : kKeyPrefixes) {
    if (s.substr(i).starts_with(prefix)) {
      const std::size_t end = run(s, i + prefix.size(), is_token);
      if (end - (i + prefix.size()) >= kTokenMin) {
        return end;
      }
    }
  }
  return std::nullopt;
}

bool is_b64url(char c) noexcept { return is_alnum(c) || c == '_' || c == '-'; }

std::optional<std::size_t> match_jwt(std::string_view s, std::size_t i) noexcept {
  if (!word_start(s, i) || !s.substr(i).starts_with("eyJ")) {
    return std::nullopt;
  }
  std::size_t j = run(s, i, is_b64url);
  for (int part = 0; part < 2; ++part) {
    if (j >= s.size() || s[j] != '.') {
      return std::nullopt;
    }
    const std::size_t k = run(s, j + 1, is_b64url);
    if (k == j + 1 && part == 0) {
      return std::nullopt;
    }
    j = k;
  }
  return j;
}

std::optional<std::size_t> match_pan(std::string_view s, std::size_t i) noexcept {
  constexpr std::size_t kLen = 10;
  if (!word_start(s, i) || s.size() - i < kLen) {
    return std::nullopt;
  }
  for (std::size_t k = 0; k < kLen; ++k) {
    const char c = s[i + k];
    const bool ok = (k < 5 || k == 9) ? is_upper(c) : is_digit(c);
    if (!ok) {
      return std::nullopt;
    }
  }
  if (i + kLen < s.size() && is_token(s[i + kLen])) {
    return std::nullopt;
  }
  return i + kLen;
}

std::optional<std::size_t> match_email(std::string_view s, std::size_t i) noexcept {
  if (!is_local(s[i]) || (i > 0 && is_local(s[i - 1]))) {
    return std::nullopt;
  }
  const std::size_t at = run(s, i, is_local);
  if (at >= s.size() || s[at] != '@') {
    return std::nullopt;
  }
  std::size_t end = run(s, at + 1, is_domain);
  while (end > at + 1 && (s[end - 1] == '.' || s[end - 1] == '-')) {
    --end;  // trailing punctuation belongs to the sentence
  }
  const std::string_view domain = s.substr(at + 1, end - at - 1);
  const std::size_t dot = domain.rfind('.');
  if (dot == std::string_view::npos || dot == 0) {
    return std::nullopt;
  }
  const std::string_view tld = domain.substr(dot + 1);
  if (tld.size() < 2) {
    return std::nullopt;
  }
  for (const char c : tld) {
    if (!is_alpha(c)) {
      return std::nullopt;
    }
  }
  return end;
}

using Matcher = std::optional<std::size_t> (*)(std::string_view, std::size_t) noexcept;
// Tried in order at each position; the first match wins.
constexpr std::array<std::pair<Matcher, std::string_view>, 4> kMatchers = {{
    {match_key, "[KEY]"}, {match_jwt, "[JWT]"}, {match_pan, "[PAN]"}, {match_email, "[EMAIL]"}}};

struct DigitRun {
  std::size_t end;
  std::string digits;
};

bool is_separator(char c) noexcept { return c == ' ' || c == '-' || c == '.' || c == '/' || c == '_' || c == '\t'; }

// Digits joined by runs of up to kMaxSeparator separator characters (" .-/_\t").
DigitRun digit_run(std::string_view s, std::size_t i) {
  DigitRun r{i, {}};
  std::size_t j = i;
  while (j < s.size()) {
    if (is_digit(s[j])) {
      r.digits.push_back(s[j]);
      r.end = ++j;
      continue;
    }
    std::size_t k = j;
    while (k < s.size() && k - j < kMaxSeparator && is_separator(s[k])) {
      ++k;
    }
    if (k == j || k >= s.size() || !is_digit(s[k])) {
      break;
    }
    j = k;
  }
  return r;
}

}  // namespace

bool luhn_valid(std::string_view digits) noexcept {
  if (digits.empty()) {
    return false;
  }
  unsigned sum = 0;
  bool dbl = false;
  for (std::size_t k = digits.size(); k-- > 0;) {
    if (!is_digit(digits[k])) {
      return false;
    }
    auto d = static_cast<unsigned>(digits[k] - '0');
    if (dbl) {
      d *= 2;
      if (d > 9) {
        d -= 9;
      }
    }
    sum += d;
    dbl = !dbl;
  }
  return sum % 10 == 0;
}

bool verhoeff_valid(std::string_view digits) noexcept {
  static constexpr std::array<std::array<std::uint8_t, 10>, 10> d{{{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
                                                                   {1, 2, 3, 4, 0, 6, 7, 8, 9, 5},
                                                                   {2, 3, 4, 0, 1, 7, 8, 9, 5, 6},
                                                                   {3, 4, 0, 1, 2, 8, 9, 5, 6, 7},
                                                                   {4, 0, 1, 2, 3, 9, 5, 6, 7, 8},
                                                                   {5, 9, 8, 7, 6, 0, 4, 3, 2, 1},
                                                                   {6, 5, 9, 8, 7, 1, 0, 4, 3, 2},
                                                                   {7, 6, 5, 9, 8, 2, 1, 0, 4, 3},
                                                                   {8, 7, 6, 5, 9, 3, 2, 1, 0, 4},
                                                                   {9, 8, 7, 6, 5, 4, 3, 2, 1, 0}}};
  static constexpr std::array<std::array<std::uint8_t, 10>, 8> p{{{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
                                                                  {1, 5, 7, 6, 2, 8, 3, 0, 9, 4},
                                                                  {5, 8, 0, 3, 7, 9, 6, 1, 4, 2},
                                                                  {8, 9, 1, 6, 0, 4, 3, 5, 2, 7},
                                                                  {9, 4, 5, 3, 1, 2, 6, 8, 7, 0},
                                                                  {4, 2, 8, 6, 5, 7, 3, 9, 0, 1},
                                                                  {2, 7, 9, 3, 8, 0, 6, 4, 1, 5},
                                                                  {7, 0, 4, 6, 9, 1, 3, 2, 5, 8}}};
  if (digits.empty()) {
    return false;
  }
  std::uint8_t c = 0;
  std::size_t pos = 0;
  for (std::size_t k = digits.size(); k-- > 0; ++pos) {
    if (!is_digit(digits[k])) {
      return false;
    }
    const auto digit = static_cast<std::size_t>(digits[k] - '0');
    c = d.at(c).at(p.at(pos % 8).at(digit));
  }
  return c == 0;
}

std::string scrub(std::string_view s) {
  std::string out;
  out.reserve(s.size());
  std::size_t i = 0;
  while (i < s.size()) {
    std::size_t end = i;  // end of a match; == i means no match
    std::string_view tag;
    for (const auto& [matcher, name] : kMatchers) {
      if (const auto m = matcher(s, i); m.has_value()) {
        end = *m;
        tag = name;
        break;
      }
    }
    if (tag.empty() && is_digit(s[i]) && (i == 0 || !is_digit(s[i - 1]))) {
      const DigitRun r = digit_run(s, i);
      const std::size_t n = r.digits.size();
      if (n >= kCardMin && n <= kCardMax && luhn_valid(r.digits)) {
        tag = "[CARD]";
      } else if (n == kAadhaarLen && r.digits[0] >= '2' && verhoeff_valid(r.digits)) {
        tag = "[AADHAAR]";
      } else if (n >= kNumberMin) {
        tag = "[NUMBER]";
      }
      if (tag.empty()) {
        out.append(s.substr(i, r.end - i));
        i = r.end;
        continue;
      }
      end = r.end;
    }
    if (!tag.empty()) {
      out.append(tag);
      i = end;
    } else {
      out.push_back(s[i]);
      ++i;
    }
  }
  return out;
}

}  // namespace pl
