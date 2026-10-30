#include "pl/detect/scanner.hpp"

#include <hs/hs.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <stdexcept>
#include <string>

namespace pl::detect {
namespace {

bool is_digit(char c) { return c >= '0' && c <= '9'; }
bool is_alnum(char c) { return std::isalnum(static_cast<unsigned char>(c)) != 0; }

constexpr std::array<std::array<int, 10>, 10> kD{{
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, {1, 2, 3, 4, 0, 6, 7, 8, 9, 5}, {2, 3, 4, 0, 1, 7, 8, 9, 5, 6},
    {3, 4, 0, 1, 2, 8, 9, 5, 6, 7}, {4, 0, 1, 2, 3, 9, 5, 6, 7, 8}, {5, 9, 8, 7, 6, 0, 4, 3, 2, 1},
    {6, 5, 9, 8, 7, 1, 0, 4, 3, 2}, {7, 6, 5, 9, 8, 2, 1, 0, 4, 3}, {8, 7, 6, 5, 9, 3, 2, 1, 0, 4},
    {9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
}};
constexpr std::array<std::array<int, 10>, 8> kP{{
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, {1, 5, 7, 6, 2, 8, 3, 0, 9, 4}, {5, 8, 0, 3, 7, 9, 6, 1, 4, 2},
    {8, 9, 1, 6, 0, 4, 3, 5, 2, 7}, {9, 4, 5, 3, 1, 2, 6, 8, 7, 0}, {4, 2, 8, 6, 5, 7, 3, 9, 0, 1},
    {2, 7, 9, 3, 8, 0, 6, 4, 1, 5}, {7, 0, 4, 6, 9, 1, 3, 2, 5, 8},
}};

struct Iin {
  std::string_view lo, hi;
  std::size_t len;
};
// Public issuer ranges: same table as ml/gen/values.py (RuPay before Discover's "65").
constexpr std::array<Iin, 12> kIin{{
    {"508500", "508999", 16}, {"606985", "607984", 16}, {"608001", "608500", 16}, {"652150", "653149", 16},
    {"4", "4", 16}, {"51", "55", 16}, {"2221", "2720", 16}, {"34", "34", 15}, {"37", "37", 15},
    {"6011", "6011", 16}, {"644", "649", 16}, {"65", "65", 16},
}};

// ---- Hyperscan families --------------------------------------------------------
enum Family : unsigned { kPan = 1, kIfsc, kEmail, kUpi, kSk, kGhp, kAkia, kJwt, kCanary, kIp };

struct Pattern {
  const char* expr;
  Family id;
};
constexpr std::array<Pattern, 10> kPatterns{{
    {"[A-Z]{3}[PCHFATBLJG][A-Z][0-9]{4}[A-Z]", kPan},
    {"[A-Z]{4}0[A-Z0-9]{6}", kIfsc},
    {"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\\.[A-Za-z0-9-]+)+", kEmail},
    {"[A-Za-z0-9][A-Za-z0-9._-]+@[A-Za-z][A-Za-z0-9]+", kUpi},
    {"sk-[A-Za-z0-9_-]{20,}", kSk},
    {"ghp_[A-Za-z0-9]{36}", kGhp},
    {"AKIA[A-Z2-7]{16}", kAkia},
    {"eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{4,}\\.[A-Za-z0-9_-]{8,}", kJwt},
    {"PLCANARY-[0-9A-HJKMNP-TV-Z]{16}-[0-9]{2}", kCanary},
    {"[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}", kIp},
}};

struct Raw {
  unsigned id;
  std::size_t from, to;
};

int on_match(unsigned id, unsigned long long from, unsigned long long to, unsigned /*flags*/, void* ctx) {
  static_cast<std::vector<Raw>*>(ctx)->push_back({id, static_cast<std::size_t>(from), static_cast<std::size_t>(to)});
  return 0;
}

}  // namespace

bool luhn_ok(std::string_view d) noexcept {
  if (d.size() < 2) {
    return false;
  }
  int sum = 0;
  bool dbl = false;
  for (auto it = d.rbegin(); it != d.rend(); ++it) {
    if (!is_digit(*it)) {
      return false;
    }
    int n = *it - '0';
    if (dbl) {
      n = n * 2 > 9 ? n * 2 - 9 : n * 2;
    }
    sum += n;
    dbl = !dbl;
  }
  return sum % 10 == 0;
}

bool verhoeff_ok(std::string_view d) noexcept {
  if (d.size() < 2) {
    return false;
  }
  int c = 0;
  std::size_t i = 0;
  for (auto it = d.rbegin(); it != d.rend(); ++it, ++i) {
    if (!is_digit(*it)) {
      return false;
    }
    const auto digit = static_cast<std::size_t>(*it - '0');
    c = kD.at(static_cast<std::size_t>(c)).at(static_cast<std::size_t>(kP.at(i % 8).at(digit)));
  }
  return c == 0;
}

bool card_iin_ok(std::string_view d) noexcept {
  return std::any_of(kIin.begin(), kIin.end(), [&](const Iin& r) {
    if (d.size() != r.len) {
      return false;
    }
    const auto pre = d.substr(0, r.lo.size());
    return pre >= r.lo && pre <= r.hi;
  });
}

bool pan_ok(std::string_view s) noexcept {
  if (s.size() != 10) {
    return false;
  }
  for (std::size_t i = 0; i < 10; ++i) {
    const bool want_digit = i >= 5 && i <= 8;
    const char c = s[i];
    if (want_digit ? !is_digit(c) : (c < 'A' || c > 'Z')) {
      return false;
    }
  }
  return std::string_view("PCHFATBLJG").find(s[3]) != std::string_view::npos && s.substr(5, 4) != "0000";
}

bool ifsc_ok(std::string_view s) noexcept {
  if (s.size() != 11 || s[4] != '0') {
    return false;
  }
  for (std::size_t i = 0; i < 4; ++i) {
    if (s[i] < 'A' || s[i] > 'Z') {
      return false;
    }
  }
  return std::all_of(s.begin() + 5, s.end(), [](char c) { return is_digit(c) || (c >= 'A' && c <= 'Z'); });
}

bool canary_ok(std::string_view s) noexcept {
  // PLCANARY-<16 Crockford base32>-<NN>, NN = (base-32 value) mod 97.
  static constexpr std::string_view kAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
  if (s.size() != 9 + 16 + 3 || s.substr(0, 9) != "PLCANARY-" || s[25] != '-') {
    return false;
  }
  unsigned mod = 0;
  for (std::size_t i = 9; i < 25; ++i) {
    const auto p = kAlphabet.find(s[i]);
    if (p == std::string_view::npos) {
      return false;
    }
    mod = (mod * 32U + static_cast<unsigned>(p)) % 97U;
  }
  if (!is_digit(s[26]) || !is_digit(s[27])) {
    return false;
  }
  return static_cast<unsigned>((s[26] - '0') * 10 + (s[27] - '0')) == mod;
}

bool ipv4_ok(std::string_view s) noexcept {
  int parts = 0;
  std::size_t i = 0;
  while (i <= s.size()) {
    std::size_t j = i;
    int v = 0;
    while (j < s.size() && is_digit(s[j])) {
      v = v * 10 + (s[j] - '0');
      ++j;
    }
    if (j == i || j - i > 3 || v > 255 || (j - i > 1 && s[i] == '0')) {
      return false;
    }
    ++parts;
    if (j == s.size()) {
      break;
    }
    if (s[j] != '.') {
      return false;
    }
    i = j + 1;
  }
  return parts == 4;
}

struct Scanner::Impl {
  hs_database_t* db = nullptr;
  hs_scratch_t* scratch = nullptr;
};

Scanner::Scanner() : impl_(std::make_unique<Impl>()) {
  std::array<const char*, kPatterns.size()> exprs{};
  std::array<unsigned, kPatterns.size()> flags{};
  std::array<unsigned, kPatterns.size()> ids{};
  for (std::size_t i = 0; i < kPatterns.size(); ++i) {
    exprs.at(i) = kPatterns.at(i).expr;
    flags.at(i) = HS_FLAG_SOM_LEFTMOST;
    ids.at(i) = kPatterns.at(i).id;
  }
  hs_compile_error_t* err = nullptr;
  if (hs_compile_multi(exprs.data(), flags.data(), ids.data(), static_cast<unsigned>(kPatterns.size()), HS_MODE_BLOCK,
                       nullptr, &impl_->db, &err) != HS_SUCCESS) {
    const std::string msg = err != nullptr ? err->message : "unknown";
    hs_free_compile_error(err);
    throw std::runtime_error("detect: hyperscan compile failed: " + msg);
  }
  if (hs_alloc_scratch(impl_->db, &impl_->scratch) != HS_SUCCESS) {
    hs_free_database(impl_->db);
    throw std::runtime_error("detect: hyperscan scratch allocation failed");
  }
}

Scanner::~Scanner() {
  hs_free_scratch(impl_->scratch);
  hs_free_database(impl_->db);
}

namespace {

// Digit runs: groups of digits separated by single separators (space . - /).
// Try every window of consecutive groups; keep validated, non-overlapping windows,
// preferring the more specific type (card > Aadhaar > phone > context types).
void scan_digits(std::string_view t, const ScanContext& ctx, std::vector<Hit>& out) {
  std::size_t i = 0;
  while (i < t.size()) {
    if (!is_digit(t[i]) || (i > 0 && (is_alnum(t[i - 1]) && !is_digit(t[i - 1])))) {
      ++i;
      continue;
    }
    struct Group {
      std::size_t b, e;
    };
    std::vector<Group> groups;
    std::size_t j = i;
    while (j < t.size() && is_digit(t[j])) {
      std::size_t k = j;
      while (k < t.size() && is_digit(t[k])) {
        ++k;
      }
      groups.push_back({j, k});
      if (k + 1 < t.size() && (t[k] == ' ' || t[k] == '.' || t[k] == '-' || t[k] == '/') && is_digit(t[k + 1])) {
        j = k + 1;
      } else {
        j = k;
        break;
      }
    }
    const bool letter_after = j < t.size() && is_alnum(t[j]) && !is_digit(t[j]);
    std::vector<Hit> found;
    for (std::size_t a = 0; a < groups.size(); ++a) {
      std::string digits;
      for (std::size_t b = a; b < groups.size(); ++b) {
        digits.append(t.substr(groups[b].b, groups[b].e - groups[b].b));
        if (digits.size() > 19) {
          break;
        }
        if (b + 1 == groups.size() && letter_after) {
          continue;  // digits glued to letters (an ID like "A12345678B") aren't a bare number
        }
        const std::size_t n = digits.size();
        Hit h{groups[a].b, groups[b].e, TaintCategory::secret, 0, false};
        // "+91..." is explicitly a phone number, even when the 12 digits also pass Verhoeff
        // (about 1 in 10 do): context beats the checksum here.
        const bool intl_phone = groups[a].b > 0 && t[groups[a].b - 1] == '+' && n == 12 && digits.starts_with("91") &&
                                digits[2] >= '6';
        if (intl_phone) {
          h.begin = groups[a].b - 1;  // include the '+'
          h.category = TaintCategory::phone, h.rule = kRulePhone, h.checksum = true;
        } else if (n >= 13 && n <= 19 && luhn_ok(digits) && card_iin_ok(digits)) {
          h.category = TaintCategory::card, h.rule = kRuleCard, h.checksum = true;
        } else if (n == 12 && digits[0] >= '2' && verhoeff_ok(digits)) {
          h.category = TaintCategory::aadhaar, h.rule = kRuleAadhaar, h.checksum = true;
        } else if ((n == 10 && digits[0] >= '6') || (n == 11 && digits[0] == '0' && digits[1] >= '6') ||
                   (n == 12 && digits.starts_with("91") && digits[2] >= '6') ||
                   (n == 13 && digits.starts_with("091") && digits[3] >= '6')) {
          h.category = TaintCategory::phone, h.rule = kRulePhone;
          if (groups[a].b > 0 && t[groups[a].b - 1] == '+') h.begin = groups[a].b - 1;
        } else if (ctx.account_label && n >= 9 && n <= 18 && digits[0] != '0') {
          h.category = TaintCategory::bank_account, h.rule = kRuleBankAccount;
        } else if (ctx.otp && (n == 6 || n == 4 || n == 8)) {
          h.category = TaintCategory::otp, h.rule = kRuleOtp;
        } else if (ctx.pin_label && n == 6 && digits[0] != '0') {
          h.category = TaintCategory::pin_code, h.rule = kRulePinCode;
        } else {
          continue;
        }
        found.push_back(h);
      }
    }
    // Priority: checksum-confirmed first, then longer.
    std::sort(found.begin(), found.end(), [](const Hit& x, const Hit& y) {
      if (x.checksum != y.checksum) {
        return x.checksum;
      }
      return (x.end - x.begin) > (y.end - y.begin);
    });
    std::vector<Hit> kept;
    for (const auto& h : found) {
      if (std::none_of(kept.begin(), kept.end(), [&](const Hit& k) { return h.begin < k.end && k.begin < h.end; })) {
        kept.push_back(h);
      }
    }
    out.insert(out.end(), kept.begin(), kept.end());
    i = std::max(j, i + 1);
  }
}

}  // namespace

std::vector<Hit> Scanner::scan(std::string_view text, const ScanContext& ctx) const {
  std::vector<Hit> out;
  scan_digits(text, ctx, out);
  std::vector<Raw> raw;
  if (!text.empty() &&
      hs_scan(impl_->db, text.data(), static_cast<unsigned>(text.size()), 0, impl_->scratch, on_match, &raw) !=
          HS_SUCCESS) {
    throw std::runtime_error("detect: hyperscan scan failed");
  }
  // Leftmost-longest per family: merge overlapping matches of the same family.
  std::sort(raw.begin(), raw.end(), [](const Raw& a, const Raw& b) {
    return a.id != b.id ? a.id < b.id : (a.from != b.from ? a.from < b.from : a.to > b.to);
  });
  std::vector<Raw> merged;
  for (const auto& r : raw) {
    if (!merged.empty() && merged.back().id == r.id && r.from < merged.back().to) {
      merged.back().to = std::max(merged.back().to, r.to);
    } else {
      merged.push_back(r);
    }
  }
  for (const auto& r : merged) {
    const bool left_ok = r.from == 0 || !is_alnum(text[r.from - 1]);
    const bool right_ok = r.to >= text.size() || !is_alnum(text[r.to]);
    const auto s = text.substr(r.from, r.to - r.from);
    Hit h{r.from, r.to, TaintCategory::secret, 0, false};
    switch (static_cast<Family>(r.id)) {
      case kPan:
        if (!left_ok || !right_ok || !pan_ok(s)) {
          continue;
        }
        h.category = TaintCategory::pan, h.rule = kRulePan;
        break;
      case kIfsc:
        if (!left_ok || !right_ok || !ifsc_ok(s)) {
          continue;
        }
        h.category = TaintCategory::ifsc, h.rule = kRuleIfsc;
        break;
      case kEmail:
        h.category = TaintCategory::email, h.rule = kRuleEmail;
        break;
      case kUpi:
        // A handle@provider with a dotless provider; "a@b.com" is an email (handled above).
        if (r.to < text.size() && (text[r.to] == '.' || text[r.to] == '-')) {
          continue;
        }
        h.category = TaintCategory::upi_id, h.rule = kRuleUpi;
        break;
      case kSk:
      case kGhp:
      case kAkia:
        h.category = TaintCategory::api_key, h.rule = kRuleApiKey;
        break;
      case kJwt:
        h.category = TaintCategory::api_key, h.rule = kRuleJwt;
        break;
      case kCanary:
        if (!canary_ok(s)) {
          continue;
        }
        h.category = TaintCategory::secret, h.rule = kRuleCanary, h.checksum = true;
        break;
      case kIp:
        if (!left_ok || !right_ok || !ipv4_ok(s)) {
          continue;
        }
        h.category = TaintCategory::ip_address, h.rule = kRuleIp;
        break;
    }
    out.push_back(h);
  }
  // Drop hits fully inside a larger hit (e.g. a UPI-shaped run inside an email, a phone inside a card).
  std::vector<Hit> result;
  for (const auto& h : out) {
    const bool inside = std::any_of(out.begin(), out.end(), [&](const Hit& o) {
      return &o != &h && o.begin <= h.begin && h.end <= o.end && (o.end - o.begin) > (h.end - h.begin);
    });
    if (!inside) {
      result.push_back(h);
    }
  }
  std::sort(result.begin(), result.end(), [](const Hit& a, const Hit& b) { return a.begin < b.begin; });
  return result;
}

}  // namespace pl::detect
