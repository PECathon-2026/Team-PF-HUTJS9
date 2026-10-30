// detect v1 known-answer tests. Values are synthetic: public test cards
// (4111..., 5555...4444) and numbers generated with valid check digits.
#include <gtest/gtest.h>

#include <algorithm>
#include <string>

#include "page_builder.hpp"
#include "pl/detect/detect.hpp"
#include "pl/detect/normalize.hpp"
#include "pl/detect/scanner.hpp"

namespace pl::detect {
namespace {

using test::PageBuilder;

DetectionSet run(PageBuilder& b) {
  auto d = make_detector({});
  return d->detect(b.build(), DetectContext{});
}

bool has(const DetectionSet& s, TaintCategory c, std::uint32_t node) {
  return std::any_of(s.items.begin(), s.items.end(), [&](const Detection& d) { return d.category == c && d.node_id == node; });
}

std::string u8(std::initializer_list<char32_t> cps) {
  std::string s;
  for (char32_t cp : cps) {
    if (cp < 0x80) {
      s.push_back(static_cast<char>(cp));
    } else if (cp < 0x800) {
      s.push_back(static_cast<char>(0xC0 | (cp >> 6)));
      s.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
      s.push_back(static_cast<char>(0xE0 | (cp >> 12)));
      s.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
      s.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
  }
  return s;
}

TEST(WinValidators, KnownAnswers) {
  EXPECT_TRUE(luhn_ok("79927398713"));
  EXPECT_FALSE(luhn_ok("79927398710"));
  EXPECT_TRUE(verhoeff_ok("2363"));
  EXPECT_FALSE(verhoeff_ok("2364"));
  EXPECT_TRUE(card_iin_ok("4111111111111111"));
  EXPECT_FALSE(card_iin_ok("9111111111111111"));
  EXPECT_TRUE(pan_ok("ABCPD1234E"));
  EXPECT_FALSE(pan_ok("ABCXD1234E"));  // X is not a holder type
  EXPECT_TRUE(ifsc_ok("SBIN0ABC123"));
  EXPECT_FALSE(ifsc_ok("SBIN1ABC123"));
  EXPECT_TRUE(ipv4_ok("192.0.2.10"));
  EXPECT_FALSE(ipv4_ok("192.0.2.300"));
  // PLCANARY check: base-32 value mod 97. "0000000000000001" -> 1 -> "01".
  EXPECT_TRUE(canary_ok("PLCANARY-0000000000000001-01"));
  EXPECT_FALSE(canary_ok("PLCANARY-0000000000000001-02"));
}

TEST(WinNormalize, MapsLookalikesAndKeepsSourceOffsets) {
  // Full-width "41" + zero-width space + "11"
  const std::string s = u8({0xFF14, 0xFF11, 0x200B, '1', '1'});
  const Normalized n = normalize(s);
  EXPECT_EQ(n.text, "4111");
  EXPECT_EQ(n.source_begin(0), 0U);
  EXPECT_EQ(n.source_end(4), s.size());
  EXPECT_EQ(normalize(u8({0x0966 + 4, 0x0966 + 2})).text, "42");  // Devanagari digits
  EXPECT_EQ(normalize(u8({0x0410, 0x0412})).text, "AB");          // Cyrillic look-alikes
}

TEST(WinDetect, CardInInputWithLuhnAndRange) {
  PageBuilder b;
  const auto id = b.add({.tag = "input", .input = "4111 1111 1111 1111", .ax_name = "Card number"});
  const auto s = run(b);
  ASSERT_TRUE(has(s, TaintCategory::card, id));
}

TEST(WinDetect, NonLuhnOrderNumberIsNotRedacted) {
  PageBuilder b;
  b.add({.text = "Order no. 4219910283914533"});
  EXPECT_TRUE(run(b).items.empty());
}

TEST(WinDetect, AadhaarPanEmailUpiPhoneIfscInText) {
  PageBuilder b;
  // 234567890124 is Verhoeff-valid (computed), first digit 2.
  const auto a = b.add({.text = "Aadhaar 2345 6789 0124, PAN ABCPD1234E, mail priya.s@example.com"});
  const auto c = b.add({.text = "UPI priya.99@okaxis, call +91 98765 43210, IFSC SBIN0ABC123"});
  const auto s = run(b);
  EXPECT_TRUE(has(s, TaintCategory::aadhaar, a));
  EXPECT_TRUE(has(s, TaintCategory::pan, a));
  EXPECT_TRUE(has(s, TaintCategory::email, a));
  EXPECT_TRUE(has(s, TaintCategory::upi_id, c));
  EXPECT_TRUE(has(s, TaintCategory::phone, c));
  EXPECT_TRUE(has(s, TaintCategory::ifsc, c));
  // The email's local part must not also be reported as a UPI handle.
  EXPECT_EQ(std::count_if(s.items.begin(), s.items.end(), [&](const Detection& d) { return d.node_id == a && d.category == TaintCategory::upi_id; }), 0);
}

TEST(WinDetect, ByteRangesPointAtTheOriginalText) {
  PageBuilder b;
  const std::string text = "Card: " + u8({0xFF14}) + "111" + u8({0x200B}) + "111111111111";
  const auto id = b.add({.text = text});
  const auto p = b.build();
  const auto s = make_detector({})->detect(p, {});
  ASSERT_EQ(s.items.size(), 1U);
  const auto& d = s.items[0];
  EXPECT_EQ(d.node_id, id);
  EXPECT_EQ(d.category, TaintCategory::card);
  EXPECT_EQ(b.str(d.string_index).substr(d.begin, d.end - d.begin), text.substr(6));
}

TEST(WinDetect, PasswordAndOtpFieldsAreStructural) {
  PageBuilder b;
  const auto pw = b.add({.tag = "input", .input = "hunter2!", .attrs = {{"type", "password"}}, .flags = kVisible | kPasswordField});
  const auto otp = b.add({.tag = "input", .input = "482913", .attrs = {{"autocomplete", "one-time-code"}}});
  const auto cvv = b.add({.tag = "input", .input = "123", .ax_name = "CVV"});
  const auto s = run(b);
  EXPECT_TRUE(has(s, TaintCategory::password, pw));
  EXPECT_TRUE(has(s, TaintCategory::otp, otp));
  EXPECT_TRUE(has(s, TaintCategory::card, cvv));
}

TEST(WinDetect, PlusNinetyOneIsAPhoneEvenIfVerhoeffPasses) {
  PageBuilder b;
  const auto id = b.add({.text = "Call +91 98765 43210"});  // 919876543210 also passes Verhoeff
  const auto s = run(b);
  ASSERT_EQ(s.items.size(), 1U);
  EXPECT_TRUE(has(s, TaintCategory::phone, id));
}

TEST(WinDetect, SixDigitsAreOnlyAnOtpWithAnOtpSignal) {
  PageBuilder b;
  b.add({.text = "Delivery in 482913 seconds"});
  EXPECT_TRUE(run(b).items.empty());
}

TEST(WinDetect, AttributesAndUrlQueryAreScanned) {
  PageBuilder b;
  const auto btn = b.add({.tag = "button", .attrs = {{"aria-label", "Send OTP to +91 98765 43210"}}});
  const auto a = b.add({.tag = "a", .attrs = {{"href", "reset?email=priya.s%40example.com"}}});
  const auto img = b.add({.tag = "img", .attrs = {{"alt", "Cheque ABCPD1234E"}}});
  const auto div = b.add({.tag = "div", .attrs = {{"data-vpa", "priya.99@okaxis"}}});
  const auto s = run(b);
  EXPECT_TRUE(has(s, TaintCategory::phone, btn));
  EXPECT_TRUE(has(s, TaintCategory::email, a));
  EXPECT_TRUE(has(s, TaintCategory::pan, img));
  EXPECT_TRUE(has(s, TaintCategory::upi_id, div));
  for (const auto& d : s.items) {
    if (d.node_id == a) {
      EXPECT_EQ(b.str(d.string_index).substr(d.begin, d.end - d.begin), "priya.s%40example.com");
    }
  }
}

TEST(WinDetect, SplitSpansAreRejoinedByGeometry) {
  PageBuilder b;
  const auto s1 = b.add({.text = "5555", .bounds = {10, 100, 40, 18}});
  const auto s2 = b.add({.text = "5555", .bounds = {55, 100, 40, 18}});
  const auto s3 = b.add({.text = "5555", .bounds = {100, 100, 40, 18}});
  const auto s4 = b.add({.text = "4444", .bounds = {145, 100, 40, 18}});
  b.add({.text = "1234", .bounds = {10, 300, 40, 18}});  // other line: not joined
  const auto s = run(b);
  for (auto id : {s1, s2, s3, s4}) EXPECT_TRUE(has(s, TaintCategory::card, id)) << id;
  EXPECT_EQ(s.items.size(), 4U);
}

TEST(WinDetect, CanaryTokensAndKeys) {
  PageBuilder b;
  const auto c = b.add({.text = "token=PLCANARY-0000000000000001-01"});
  const auto k = b.add({.text = std::string("AK") + "IA" + "ABCDEFGHIJKLMNOP"});  // synthetic; split so scanners skip it
  const auto s = run(b);
  EXPECT_TRUE(has(s, TaintCategory::secret, c));
  EXPECT_TRUE(has(s, TaintCategory::api_key, k));
}

TEST(WinDetect, TaintLabelFollowsCategory) {
  Detection d;
  d.category = TaintCategory::card;
  EXPECT_TRUE(taint_of(d).has(TaintCategory::card));
  EXPECT_FALSE(taint_of(d).allows_egress());
}

}  // namespace
}  // namespace pl::detect
