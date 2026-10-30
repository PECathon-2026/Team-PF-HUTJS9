#include <gtest/gtest.h>

#include "ledger/reject.hpp"

using namespace pl::ledger;

TEST(Canary, KnownAnswerCheckDigits) {
  EXPECT_EQ(canary_check_digits("0123456789ABCDEF"), 19);
  EXPECT_EQ(canary_check_digits("ZZZZZZZZZZZZZZZZ"), 34);
  EXPECT_EQ(canary_check_digits("7QK3M9WX2HT5R8VN"), 20);
  EXPECT_EQ(canary_check_digits("00000000000000A0"), 29);
  EXPECT_EQ(canary_check_digits("SHORT"), -1);
  EXPECT_EQ(canary_check_digits("0123456789ABCDEU"), -1);  // U is not Crockford
}

TEST(Canary, MakeAndScan) {
  EXPECT_EQ(make_canary("7QK3M9WX2HT5R8VN"), "PLCANARY-7QK3M9WX2HT5R8VN-20");
  EXPECT_EQ(make_canary("0123456789ABCDEF"), "PLCANARY-0123456789ABCDEF-19");
  EXPECT_THROW((void)make_canary("nope"), std::invalid_argument);
  EXPECT_EQ(scan_canary("card is PLCANARY-7QK3M9WX2HT5R8VN-20 ok"), CanaryHit::valid);
  EXPECT_EQ(scan_canary("plcanary-7qk3m9wx2ht5r8vn-20"), CanaryHit::valid);         // case-insensitive
  EXPECT_EQ(scan_canary("PLCANARY-7QK3M9WX2HT5R8VN-21"), CanaryHit::prefix_only);  // bad check
  EXPECT_EQ(scan_canary("PLCANARY-"), CanaryHit::prefix_only);
  EXPECT_EQ(scan_canary("PLCANARY-OOOOOOOOOOOOOOO0-00"), CanaryHit::valid);  // O -> 0 alias, value 0 -> check 00
  EXPECT_EQ(scan_canary("hello PLCANAR-7QK3M9WX2HT5R8VN-20"), CanaryHit::none);
  EXPECT_EQ(scan_canary(""), CanaryHit::none);
}

TEST(Reject, BannedFieldNames) {
  for (const char* k : {"value", "raw", "text_raw", "secret", "plaintext", "VALUE", "Secret"}) {
    nlohmann::json m = {{"schema", "event.v1"}, {"nested", {{"deep", {{k, "x"}}}}}};
    const auto r = scan_message(m);
    ASSERT_TRUE(r.has_value()) << k;
    EXPECT_EQ(r->code, RejectCode::banned_field);
    EXPECT_EQ(rule_id(r->code), "LG-001");
  }
  nlohmann::json ok = {{"schema", "event.v1"}, {"values", 1}, {"rawness", 2}};
  EXPECT_FALSE(scan_message(ok).has_value());
}

TEST(Reject, BannedInsideArrays) {
  nlohmann::json m = {{"a", nlohmann::json::array({1, {{"plaintext", "x"}}})}};
  const auto r = scan_message(m);
  ASSERT_TRUE(r.has_value());
  EXPECT_EQ(r->code, RejectCode::banned_field);
  EXPECT_EQ(r->path, "/a/1/plaintext");
}

TEST(Reject, CanaryInValueKeyAndNested) {
  const std::string c = make_canary("7QK3M9WX2HT5R8VN");
  nlohmann::json v = {{"payload", {{"messages", nlohmann::json::array({{{"content", "pay with " + c}}})}}}};
  auto r = scan_message(v);
  ASSERT_TRUE(r.has_value());
  EXPECT_EQ(r->code, RejectCode::canary);
  EXPECT_EQ(rule_id(r->code), "LG-002");
  EXPECT_EQ(r->path.find("PLCANARY"), std::string::npos);

  nlohmann::json k = {{c, 1}};
  r = scan_message(k);
  ASSERT_TRUE(r.has_value());
  EXPECT_EQ(r->path, "/?");  // the key is never echoed
}

TEST(Reject, DepthBound) {
  nlohmann::json j = "x";
  for (int i = 0; i < 40; ++i) j = nlohmann::json{{"a", j}};
  const auto r = scan_message(j);
  ASSERT_TRUE(r.has_value());
  EXPECT_EQ(r->code, RejectCode::too_deep);
}

TEST(Reject, CleanMessagePasses) {
  nlohmann::json m = {{"schema", "event.v1"}, {"placeholder", "[REDACTED:CARD#3]"}, {"score", 0.5}};
  EXPECT_FALSE(scan_message(m).has_value());
}
