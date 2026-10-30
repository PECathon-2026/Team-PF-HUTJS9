// Gate scanner (owner: LNX). Hand-written matchers, no shared code with detect (AD-11).
#include "pl/gate/scanner.hpp"

#include <array>
#include <cctype>
#include <ranges>

namespace pl::gate {
namespace {

bool is_digit(char c) noexcept { return c >= '0' && c <= '9'; }
bool is_upper(char c) noexcept { return c >= 'A' && c <= 'Z'; }
bool is_alnum(char c) noexcept { return std::isalnum(static_cast<unsigned char>(c)) != 0; }
bool is_sep(char c) noexcept { return c == ' ' || c == '-' || c == '.' || c == '_' || c == '/' || c == '\t'; }

// Crockford base32 digit value, -1 if not a canonical digit (I, L, O, U excluded).
int crockford(char c) noexcept {
  static constexpr std::string_view kAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
  const auto pos = kAlphabet.find(c);
  return pos == std::string_view::npos ? -1 : static_cast<int>(pos);
}

// Ranges covered by placeholders, so "[REDACTED:CARD#1]" is never itself a finding.
std::vector<std::pair<std::size_t, std::size_t>> placeholder_ranges(std::string_view t) {
  std::vector<std::pair<std::size_t, std::size_t>> out;
  static constexpr std::string_view kOpen = "[REDACTED:";
  for (std::size_t p = t.find(kOpen); p != std::string_view::npos; p = t.find(kOpen, p + 1)) {
    const auto close = t.find(']', p);
    if (close == std::string_view::npos || close - p > 40) {
      continue;
    }
    out.emplace_back(p, close + 1);
  }
  return out;
}

bool inside(const std::vector<std::pair<std::size_t, std::size_t>>& rs, std::size_t b) {
  for (const auto& [lo, hi] : rs) {
    if (b >= lo && b < hi) {
      return true;
    }
  }
  return false;
}

// Digit runs allowing single separators between digits; yields (begin, end, digits).
struct DigitRun {
  std::size_t begin, end;
  std::string digits;
};

std::vector<DigitRun> digit_runs(std::string_view t) {
  std::vector<DigitRun> out;
  std::size_t i = 0;
  while (i < t.size()) {
    if (!is_digit(t[i])) {
      ++i;
      continue;
    }
    DigitRun r{i, i, {}};
    std::size_t j = i;
    while (j < t.size()) {
      if (is_digit(t[j])) {
        r.digits.push_back(t[j]);
        r.end = ++j;
      } else if (is_sep(t[j]) && j + 1 < t.size() && is_digit(t[j + 1]) && r.digits.size() < 19) {
        ++j;
      } else {
        break;
      }
    }
    out.push_back(std::move(r));
    i = j;
  }
  return out;
}

}  // namespace

std::string_view Finding::rule_id() const noexcept {
  switch (kind) {
    case FindingKind::card: return "G-101";
    case FindingKind::aadhaar: return "G-102";
    case FindingKind::pan: return "G-103";
    case FindingKind::api_key: return "G-104";
    case FindingKind::private_key: return "G-105";
    case FindingKind::canary_token: return "G-201";
    case FindingKind::canary_listed: return "G-202";
  }
  return "G-100";
}

bool luhn_ok(std::string_view digits) noexcept {
  int sum = 0;
  bool dbl = false;
  for (char digit : std::ranges::reverse_view(digits)) {
    int d = digit - '0';
    if (dbl) {
      d *= 2;
      if (d > 9) {
        d -= 9;
      }
    }
    sum += d;
    dbl = !dbl;
  }
  return !digits.empty() && sum % 10 == 0;
}

bool verhoeff_ok(std::string_view digits) noexcept {
  static constexpr std::array<std::array<int, 10>, 10> kD = {{{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
                                                             {1, 2, 3, 4, 0, 6, 7, 8, 9, 5},
                                                             {2, 3, 4, 0, 1, 7, 8, 9, 5, 6},
                                                             {3, 4, 0, 1, 2, 8, 9, 5, 6, 7},
                                                             {4, 0, 1, 2, 3, 9, 5, 6, 7, 8},
                                                             {5, 9, 8, 7, 6, 0, 4, 3, 2, 1},
                                                             {6, 5, 9, 8, 7, 1, 0, 4, 3, 2},
                                                             {7, 6, 5, 9, 8, 2, 1, 0, 4, 3},
                                                             {8, 7, 6, 5, 9, 3, 2, 1, 0, 4},
                                                             {9, 8, 7, 6, 5, 4, 3, 2, 1, 0}}};
  static constexpr std::array<std::array<int, 10>, 8> kP = {{{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
                                                            {1, 5, 7, 6, 2, 8, 3, 0, 9, 4},
                                                            {5, 8, 0, 3, 7, 9, 6, 1, 4, 2},
                                                            {8, 9, 1, 6, 0, 4, 3, 5, 2, 7},
                                                            {9, 4, 5, 3, 1, 2, 6, 8, 7, 0},
                                                            {4, 2, 8, 6, 5, 7, 3, 9, 0, 1},
                                                            {2, 7, 9, 3, 8, 0, 6, 4, 1, 5},
                                                            {7, 0, 4, 6, 9, 1, 3, 2, 5, 8}}};
  int c = 0;
  std::size_t i = 0;
  for (auto it = digits.rbegin(); it != digits.rend(); ++it, ++i) {
    const auto d = static_cast<std::size_t>(*it - '0');
    c = kD.at(static_cast<std::size_t>(c)).at(static_cast<std::size_t>(kP.at(i % 8).at(d)));
  }
  return !digits.empty() && c == 0;
}

std::string normalise_for_canary(std::string_view s) {
  std::string out;
  for (const char c : s) {
    if (is_alnum(c)) {
      out.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
    }
  }
  return out;
}

void CanaryRegistry::add(std::string_view value) {
  auto n = normalise_for_canary(value);
  if (n.size() >= 6) {  // too-short canaries would match everywhere
    normalised_.insert(std::move(n));
  }
}

bool is_valid_canary_token(std::string_view body16, std::string_view check2) {
  if (body16.size() != 16 || check2.size() != 2 || !is_digit(check2[0]) || !is_digit(check2[1])) {
    return false;
  }
  int v = 0;
  for (const char c : body16) {
    const int d = crockford(c);
    if (d < 0) {
      return false;
    }
    v = (v * 32 + d) % 97;
  }
  return v == (check2[0] - '0') * 10 + (check2[1] - '0');
}

std::vector<Finding> scan(std::string_view t, const CanaryRegistry& canaries) {
  std::vector<Finding> out;
  const auto ph = placeholder_ranges(t);

  for (const auto& r : digit_runs(t)) {
    if (inside(ph, r.begin)) {
      continue;
    }
    const auto n = r.digits.size();
    if (n >= 13 && n <= 19 && luhn_ok(r.digits)) {
      out.push_back({FindingKind::card, r.begin, r.end});
    } else if (n == 12 && r.digits[0] >= '2' && verhoeff_ok(r.digits)) {
      out.push_back({FindingKind::aadhaar, r.begin, r.end});
    }
  }

  // PAN: 5 letters, 4 digits, 1 letter, word-bounded.
  for (std::size_t i = 0; i + 10 <= t.size(); ++i) {
    if (i > 0 && is_alnum(t[i - 1])) {
      continue;
    }
    bool ok = true;
    for (std::size_t k = 0; k < 10 && ok; ++k) {
      ok = k < 5 || k == 9 ? is_upper(t[i + k]) : is_digit(t[i + k]);
    }
    if (ok && (i + 10 == t.size() || !is_alnum(t[i + 10])) && !inside(ph, i)) {
      out.push_back({FindingKind::pan, i, i + 10});
    }
  }

  // API keys by well-known prefix followed by a long token.
  static constexpr std::array<std::string_view, 9> kPrefixes = {"sk-",  "sk_live_", "pk_live_", "AKIA", "ghp_",
                                                                "gho_", "xoxb-",    "xoxp-",    "AIza"};
  for (const auto pre : kPrefixes) {
    for (auto p = t.find(pre); p != std::string_view::npos; p = t.find(pre, p + 1)) {
      if (p > 0 && is_alnum(t[p - 1])) {
        continue;
      }
      std::size_t e = p + pre.size();
      while (e < t.size() && (is_alnum(t[e]) || t[e] == '_' || t[e] == '-')) {
        ++e;
      }
      if (e - p - pre.size() >= 16 && !inside(ph, p)) {
        out.push_back({FindingKind::api_key, p, e});
      }
    }
  }
  if (const auto p = t.find("PRIVATE KEY-----"); p != std::string_view::npos) {
    out.push_back({FindingKind::private_key, p, p + 16});
  }

  // Self-checking canary tokens.
  static constexpr std::string_view kCanary = "PLCANARY-";
  for (auto p = t.find(kCanary); p != std::string_view::npos; p = t.find(kCanary, p + 1)) {
    const auto b = p + kCanary.size();
    if (b + 19 <= t.size() && t[b + 16] == '-' && is_valid_canary_token(t.substr(b, 16), t.substr(b + 17, 2))) {
      out.push_back({FindingKind::canary_token, p, b + 19});
    }
  }

  // Listed canaries, separator- and case-insensitive.
  if (!canaries.empty()) {
    std::string norm;
    std::vector<std::size_t> pos;  // norm index -> text offset
    for (std::size_t i = 0; i < t.size(); ++i) {
      if (is_alnum(t[i])) {
        norm.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(t[i]))));
        pos.push_back(i);
      }
    }
    for (const auto& c : canaries.values()) {
      for (auto p = norm.find(c); p != std::string::npos; p = norm.find(c, p + 1)) {
        out.push_back({FindingKind::canary_listed, pos[p], pos[p + c.size() - 1] + 1});
      }
    }
  }
  return out;
}

}  // namespace pl::gate
