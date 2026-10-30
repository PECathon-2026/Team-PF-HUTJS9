// Gate scanner tests (owner: LNX). All values are synthetic test values.
#include <string>

#include <gtest/gtest.h>

#include "pl/gate/scanner.hpp"

namespace {

using pl::gate::CanaryRegistry;
using pl::gate::FindingKind;
using pl::gate::scan;

std::string make_canary(const std::string& body) {
  static const std::string kAlpha = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
  int v = 0;
  for (char const c : body) {
    v = (v * 32 + static_cast<int>(kAlpha.find(c))) % 97;
  }
  std::string chk = std::to_string(v);
  if (chk.size() == 1) {
    chk = "0" + chk;
  }
  return "PLCANARY-" + body + "-" + chk;
}

bool has(const std::string& text, FindingKind k, const CanaryRegistry& reg = {}) {
  for (const auto& f : scan(text, reg)) {
    if (f.kind == k) {
      return true;
    }
  }
  return false;
}

TEST(GateScanner, Luhn) {
  EXPECT_TRUE(pl::gate::luhn_ok("4111111111111111"));
  EXPECT_FALSE(pl::gate::luhn_ok("4111111111111112"));
  EXPECT_TRUE(has("pay with 4111 1111 1111 1111 now", FindingKind::card));
  EXPECT_TRUE(has("pay with 4111-1111-1111-1111", FindingKind::card));
  EXPECT_FALSE(has("order 4111111111111112", FindingKind::card));
}

TEST(GateScanner, VerhoeffAadhaar) {
  // 2341 2341 2346 is a synthetic Verhoeff-valid number.
  EXPECT_TRUE(pl::gate::verhoeff_ok("234123412346"));
  EXPECT_FALSE(pl::gate::verhoeff_ok("234123412347"));
  EXPECT_TRUE(has("id 2341 2341 2346", FindingKind::aadhaar));
  EXPECT_FALSE(has("id 2341 2341 2347", FindingKind::aadhaar));
}

TEST(GateScanner, PanAndKeys) {
  EXPECT_TRUE(has("PAN ABCDE1234F here", FindingKind::pan));
  EXPECT_FALSE(has("XABCDE1234F", FindingKind::pan));
  EXPECT_TRUE(has("key sk-TESTabcdefghijklmnop0123", FindingKind::api_key));
  EXPECT_TRUE(has(std::string("AKI") + "ATESTTESTTESTTEST", FindingKind::api_key));  // split: synthetic, not a key
  EXPECT_FALSE(has("sk-short", FindingKind::api_key));
  EXPECT_TRUE(has(std::string("-----BEGIN PRIVATE") + " KEY-----", FindingKind::private_key));
}

TEST(GateScanner, PlaceholdersAreNotFindings) {
  EXPECT_TRUE(scan("fill [REDACTED:CARD#1] and [REDACTED:AADHAAR#22]", {}).empty());
}

TEST(GateScanner, CanaryTokenSelfCheck) {
  const auto tok = make_canary("0123456789ABCDEF");
  EXPECT_TRUE(has("see " + tok + " ok", FindingKind::canary_token));
  std::string bad = tok;
  bad.back() = bad.back() == '0' ? '1' : '0';
  EXPECT_FALSE(has(bad, FindingKind::canary_token));
  EXPECT_FALSE(pl::gate::is_valid_canary_token("0123456789ABCDEI", "00"));  // I is not Crockford
}

TEST(GateScanner, ListedCanariesIgnoreSeparatorsAndCase) {
  CanaryRegistry reg;
  reg.add("nimbus-key-7Q2X9");
  reg.add("abc");  // too short, ignored
  EXPECT_TRUE(has("the token is NIMBUS KEY 7q2x9.", FindingKind::canary_listed, reg));
  EXPECT_FALSE(has("abc abc", FindingKind::canary_listed, reg));
}

}  // namespace
