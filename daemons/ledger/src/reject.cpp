#include "ledger/reject.hpp"

#include <array>
#include <cctype>
#include <stdexcept>

namespace pl::ledger {

namespace {

constexpr std::string_view kAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
constexpr std::array<std::string_view, 5> kBanned = {"value", "raw", "text_raw", "secret", "plaintext"};

char upper(char c) noexcept { return static_cast<char>(std::toupper(static_cast<unsigned char>(c))); }

// Crockford value of c (aliases tolerated), or -1.
int crockford(char c) noexcept {
  c = upper(c);
  if (c == 'O') {
    c = '0';
  }
  if (c == 'I' || c == 'L') {
    c = '1';
  }
  const auto pos = kAlphabet.find(c);
  return pos == std::string_view::npos ? -1 : static_cast<int>(pos);
}

bool iequals_prefix(std::string_view s, std::size_t at, std::string_view prefix) noexcept {
  if (s.size() - at < prefix.size()) {
    return false;
  }
  for (std::size_t i = 0; i < prefix.size(); ++i) {
    if (upper(s[at + i]) != prefix[i]) {
      return false;
    }
  }
  return true;
}

std::string escape_pointer(std::string_view key) {
  std::string out;
  for (const char c : key) {
    if (c == '~') {
      out += "~0";
    } else if (c == '/') {
      out += "~1";
    } else {
      out += c;
    }
  }
  return out;
}

std::optional<Rejection> scan_node(const nlohmann::json& j, const std::string& path, unsigned depth) {
  if (depth > kMaxScanDepth) {
    return Rejection{RejectCode::too_deep, path};
  }
  if (j.is_string()) {
    switch (scan_canary(j.get_ref<const std::string&>())) {
      case CanaryHit::valid:
        return Rejection{RejectCode::canary, path};
      case CanaryHit::prefix_only:
        return Rejection{RejectCode::canary_prefix, path};
      case CanaryHit::none:
        break;
    }
  } else if (j.is_object()) {
    for (const auto& [k, v] : j.items()) {
      // A key that is itself a canary is never echoed into the path.
      if (is_banned_field(k)) {
        return Rejection{RejectCode::banned_field, path + "/" + escape_pointer(k)};
      }
      if (const auto h = scan_canary(k); h != CanaryHit::none) {
        return Rejection{h == CanaryHit::valid ? RejectCode::canary : RejectCode::canary_prefix, path + "/?"};
      }
      if (auto r = scan_node(v, path + "/" + escape_pointer(k), depth + 1)) {
        return r;
      }
    }
  } else if (j.is_array()) {
    std::size_t i = 0;
    for (const auto& v : j) {
      if (auto r = scan_node(v, path + "/" + std::to_string(i++), depth + 1)) {
        return r;
      }
    }
  }
  return std::nullopt;
}

}  // namespace

std::string_view detail_code(RejectCode c) noexcept {
  switch (c) {
    case RejectCode::banned_field:
      return "banned_field";
    case RejectCode::canary:
      return "canary";
    case RejectCode::canary_prefix:
      return "canary_prefix";
    case RejectCode::too_deep:
      return "too_deep";
    case RejectCode::unknown_schema:
      return "unknown_schema";
    case RejectCode::schema_invalid:
      return "schema_invalid";
    case RejectCode::oversize:
      return "oversize";
  }
  return "unknown";
}

std::string_view rule_id(RejectCode c) noexcept {
  switch (c) {
    case RejectCode::banned_field:
      return "LG-001";
    case RejectCode::canary:
    case RejectCode::canary_prefix:
      return "LG-002";
    case RejectCode::schema_invalid:
    case RejectCode::unknown_schema:
      return "LG-003";
    case RejectCode::too_deep:
    case RejectCode::oversize:
      return "LG-004";
  }
  return "LG-999";
}

bool is_banned_field(std::string_view key) noexcept {
  for (const auto b : kBanned) {
    if (key.size() != b.size()) {
      continue;
    }
    bool eq = true;
    for (std::size_t i = 0; i < b.size(); ++i) {
      if (std::tolower(static_cast<unsigned char>(key[i])) != b[i]) {
        eq = false;
        break;
      }
    }
    if (eq) {
      return true;
    }
  }
  return false;
}

int canary_check_digits(std::string_view body16) {
  if (body16.size() != 16) {
    return -1;
  }
  unsigned acc = 0;
  for (const char c : body16) {
    const int v = crockford(c);
    if (v < 0) {
      return -1;
    }
    acc = (acc * 32U + static_cast<unsigned>(v)) % 97U;
  }
  return static_cast<int>(acc);
}

std::string make_canary(std::string_view body16) {
  const int check = canary_check_digits(body16);
  if (check < 0) {
    throw std::invalid_argument("canary body must be 16 Crockford base32 characters");
  }
  std::string out(kCanaryPrefix);
  for (const char c : body16) {
    out += upper(c);
  }
  out += '-';
  out += static_cast<char>('0' + check / 10);
  out += static_cast<char>('0' + check % 10);
  return out;
}

CanaryHit scan_canary(std::string_view s) noexcept {
  CanaryHit best = CanaryHit::none;
  std::size_t at = 0;
  while (at + kCanaryPrefix.size() <= s.size()) {
    if (!iequals_prefix(s, at, kCanaryPrefix)) {
      ++at;
      continue;
    }
    best = CanaryHit::prefix_only;
    const std::size_t body = at + kCanaryPrefix.size();
    if (s.size() - body >= 19 && s[body + 16] == '-' && std::isdigit(static_cast<unsigned char>(s[body + 17])) != 0 &&
        std::isdigit(static_cast<unsigned char>(s[body + 18])) != 0) {
      const int want = canary_check_digits(s.substr(body, 16));
      const int got = (s[body + 17] - '0') * 10 + (s[body + 18] - '0');
      if (want >= 0 && want == got) {
        return CanaryHit::valid;
      }
    }
    at = body;
  }
  return best;
}

std::optional<Rejection> scan_message(const nlohmann::json& msg) { return scan_node(msg, "", 0); }

}  // namespace pl::ledger
