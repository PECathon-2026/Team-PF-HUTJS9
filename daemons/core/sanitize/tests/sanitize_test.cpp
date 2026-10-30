// sanitize v1 tests: values go to the vault and never into the output.
#include <gtest/gtest.h>

#include <map>
#include <string>
#include <vector>

#include "../../detect/tests/page_builder.hpp"
#include "pl/sanitize/sanitize.hpp"

namespace pl::detect {
namespace {

using test::PageBuilder;

struct FakeVault {
  std::map<std::string, std::string> stored;  // placeholder -> value (test only)
  int n = 0;
  std::string store(const Detection& d, std::string_view v) {
    std::string cat(to_string(d.category));
    for (auto& ch : cat) ch = static_cast<char>(ch >= 'a' && ch <= 'z' ? ch - 32 : ch);
    const std::string ph = "[REDACTED:" + cat + "#" + std::to_string(++n) + "]";
    stored[ph] = std::string(v);
    return ph;
  }
};

TEST(WinSanitize, ValuesGoToTheVaultAndOnlyPlaceholdersRemain) {
  PageBuilder b;
  b.add({.tag = "input", .input = "4111 1111 1111 1111", .ax_name = "Card number", .ax_role = "textbox",
         .bounds = {100, 200, 300, 36}});
  b.add({.tag = "button", .ax_name = "Send OTP to +91 98765 43210", .ax_role = "button"});
  b.add({.tag = "a", .text = "Forgot password?", .attrs = {{"href", "reset?email=priya.s%40example.com#x"}}});
  b.add({.tag = "input", .input = "hunter2!", .ax_name = "Password", .attrs = {{"type", "password"}},
         .flags = kVisible | kPasswordField});
  const auto page = b.build();
  const auto found = make_detector({})->detect(page, {});
  FakeVault vault;
  SanitizeContext ctx;
  ctx.vault_store = [&](const Detection& d, std::string_view v) { return vault.store(d, v); };
  const auto out = make_sanitizer({})->sanitize(page, found, ctx);
  const std::string msg = out.message.dump();

  EXPECT_EQ(out.message["schema"], "sanitized_page.v1");
  for (const auto& [ph, value] : vault.stored) {
    EXPECT_EQ(msg.find(value), std::string::npos) << "leaked a stored value";
  }
  for (const char* secret : {"4111", "98765", "priya", "hunter2", "%40"}) {
    EXPECT_EQ(msg.find(secret), std::string::npos) << secret;
  }
  EXPECT_NE(msg.find("[REDACTED:CARD#"), std::string::npos);
  EXPECT_NE(msg.find("Send OTP to [REDACTED:PHONE#"), std::string::npos) << msg;
  EXPECT_EQ(vault.stored.size(), 4U);
  // href keeps only the path.
  bool saw_href = false;
  for (const auto& e : out.message["elements"]) {
    if (e.contains("href")) {
      EXPECT_EQ(e["href"], "reset");
      saw_href = true;
    }
    if (e["name"] == "Card number") {
      EXPECT_EQ(e["data_type"], "CARD");
    }
  }
  EXPECT_TRUE(saw_href);
}

TEST(WinSanitize, VaultFailureStillRemovesTheText) {
  PageBuilder b;
  b.add({.tag = "button", .ax_name = "Call +91 98765 43210", .ax_role = "button"});
  const auto page = b.build();
  const auto found = make_detector({})->detect(page, {});
  SanitizeContext ctx;
  ctx.vault_store = [](const Detection&, std::string_view) -> std::string { throw std::runtime_error("vault down"); };
  const auto out = make_sanitizer({})->sanitize(page, found, ctx);
  const std::string msg = out.message.dump();
  EXPECT_EQ(msg.find("98765"), std::string::npos);
  EXPECT_NE(msg.find("[REDACTED]"), std::string::npos);
}

TEST(WinSanitize, ScreenshotBoxesAreSolidAndCoverTheField) {
  PageBuilder b;
  b.add({.tag = "input", .input = "4111111111111111", .ax_name = "Card number", .bounds = {10, 10, 50, 20}});
  auto page = b.build();
  std::vector<std::byte> rgba(100 * 60 * 4, std::byte{200});
  page.screenshot = {rgba, 100, 60, 400};
  const auto found = make_detector({})->detect(page, {});
  SanitizeContext ctx;
  ctx.vault_store = [](const Detection&, std::string_view) { return std::string("[REDACTED:CARD#1]"); };
  const auto out = make_sanitizer({})->sanitize(page, found, ctx);
  ASSERT_GT(out.redacted_png.size(), 8U);
  EXPECT_EQ(static_cast<unsigned char>(out.redacted_png[1]), 'P');  // PNG signature
  const auto& box = out.message["redactions"][0]["box"];
  EXPECT_LE(box[0].get<double>(), 10.0 - 4.0);
  EXPECT_EQ(static_cast<int>(box[2].get<double>()) % 32, 0);  // fixed width steps: length doesn't leak
}

}  // namespace
}  // namespace pl::detect
