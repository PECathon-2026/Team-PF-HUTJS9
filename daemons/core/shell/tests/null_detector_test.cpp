#include "pl/null_detector.hpp"

#include <gtest/gtest.h>

#include <array>
#include <string>
#include <vector>

namespace {

using namespace pl::detect;

struct Page {
  std::vector<std::string_view> strings = {"input", "Card number", "4111 1111 1111 1111", "autocomplete", "cc-number", ""};
  std::array<AttrRef, 1> attrs{{{3, 4}}};
  std::vector<Node> nodes;
  PageSnapshot snap;
  Page() {
    nodes.push_back(Node{.node_id = 0, .parent = kNone, .tag = 0, .attrs = {}, .text = 1, .input_text = kNone, .bounds = {},
                         .ax_role = kNone, .ax_name = kNone, .flags = kVisible});
    nodes.push_back(Node{.node_id = 1, .parent = 0, .tag = 0, .attrs = attrs, .text = 5, .input_text = 2, .bounds = {1, 2, 3, 4},
                         .ax_role = kNone, .ax_name = 1, .flags = kVisible | kEditable});
    snap.strings = strings;
    snap.nodes = nodes;
  }
};

TEST(NullDetector, FlagsEveryNonEmptyString) {
  Page p;
  NullDetector d;
  const auto found = d.detect(p.snap, {});
  // node 0: text; node 1: input_text, ax_name, attribute value (empty text skipped)
  ASSERT_EQ(found.items.size(), 4U);
  for (const auto& det : found.items) {
    EXPECT_EQ(det.category, pl::TaintCategory::secret);
    EXPECT_EQ(det.source, Source::fallback);
    EXPECT_EQ(det.begin, 0U);
    EXPECT_EQ(det.end, p.strings[static_cast<std::size_t>(det.string_index)].size());
  }
  EXPECT_TRUE(found.complete);
}

TEST(NullDetector, IgnoresOutOfRangeIndices) {
  Page p;
  p.nodes[0].text = 99;
  NullDetector d;
  EXPECT_EQ(d.detect(p.snap, {}).items.size(), 3U);
}

TEST(NullSanitizer, OutputCarriesNoPageText) {
  Page p;
  NullDetector d;
  NullSanitizer s;
  std::vector<std::string> stored;
  SanitizeContext ctx{.session_id = 1, .vault_store = [&](const Detection& /*det*/, std::string_view v) {
                        stored.emplace_back(v);
                        return "[REDACTED:SECRET#" + std::to_string(stored.size()) + "]";
                      }};
  const auto page = s.sanitize(p.snap, d.detect(p.snap, {}), ctx);
  const std::string dumped = page.message.dump();
  for (const auto& str : p.strings) {
    if (str.size() > 3) {
      EXPECT_EQ(dumped.find(str), std::string::npos) << str;
    }
  }
  EXPECT_EQ(stored.size(), 4U);
  EXPECT_EQ(page.message["elements"][1]["element_id"], "n1");
  EXPECT_EQ(page.message["elements"][1]["placeholders"].size(), 3U);
  EXPECT_TRUE(page.redacted_png.empty());
}

TEST(NullSanitizer, VaultFailureStillRedacts) {
  Page p;
  NullDetector d;
  NullSanitizer s;
  SanitizeContext ctx{.session_id = 1, .vault_store = [](const Detection&, std::string_view) -> std::string { throw std::runtime_error("down"); }};
  const auto page = s.sanitize(p.snap, d.detect(p.snap, {}), ctx);
  EXPECT_EQ(page.message["elements"][0]["placeholders"][0], "[REDACTED:SECRET#0]");
  EXPECT_EQ(page.message.dump().find("4111"), std::string::npos);
}

// Regression (Phase 0 review): sparse node ids and a misbehaving vault_store.
TEST(NullSanitizer, SparseNodeIdsAndBadPlaceholders) {
  Page p;
  p.nodes[1].node_id = 7;
  NullDetector d;
  NullSanitizer s;
  SanitizeContext ctx{.session_id = 1, .vault_store = [](const Detection&, std::string_view v) { return std::string(v); }};
  const auto page = s.sanitize(p.snap, d.detect(p.snap, {}), ctx);
  EXPECT_EQ(page.message["elements"][1]["element_id"], "n7");
  EXPECT_EQ(page.message["elements"][1]["placeholders"].size(), 3U);
  EXPECT_EQ(page.message.dump().find("4111"), std::string::npos);  // echoed value rejected
  SanitizeContext good{.session_id = 1, .vault_store = [](const Detection&, std::string_view) { return std::string("[REDACTED:CARD#42]"); }};
  EXPECT_EQ(s.sanitize(p.snap, d.detect(p.snap, {}), good).message["elements"][0]["placeholders"][0], "[REDACTED:CARD#42]");
}

TEST(NullDetector, DefaultsAreNullUntilWinLinks) {
#ifdef PL_HAVE_WIN_DETECT
  EXPECT_FALSE(using_null_detector());
#else
  EXPECT_TRUE(using_null_detector());
#endif
  auto det = default_detector({});
  auto san = default_sanitizer({});
  ASSERT_NE(det, nullptr);
  ASSERT_NE(san, nullptr);
  det->on_navigation(1);
  det->on_session_end(1);
}

}  // namespace
