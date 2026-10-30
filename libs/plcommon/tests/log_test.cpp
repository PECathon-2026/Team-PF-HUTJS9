#include "pl/log.hpp"

#include <gtest/gtest.h>

#include <vector>

#include <nlohmann/json.hpp>

namespace {

struct Capture {
  std::vector<std::string> lines;
  pl::LogSink sink() {
    return [this](std::string_view l) { lines.emplace_back(l); };
  }
};

TEST(Log, StructuredLineWithScrubbedStrings) {
  Capture cap;
  pl::Logger log("vault", cap.sink(), pl::LogLevel::debug);
  log.info("store.ok", {{"field_type", std::string("CARD")}, {"count", std::int64_t{3}}, {"ok", true}, {"score", 0.5},
                        {"note", std::string("user typed 4111 1111 1111 1111 into mail a@b.co")}});
  ASSERT_EQ(cap.lines.size(), 1U);
  const auto j = nlohmann::json::parse(cap.lines[0]);
  EXPECT_EQ(j["component"], "vault");
  EXPECT_EQ(j["event"], "store.ok");
  EXPECT_EQ(j["level"], "info");
  EXPECT_EQ(j["fields"]["count"], 3);
  EXPECT_EQ(j["fields"]["ok"], true);
  EXPECT_EQ(j["fields"]["note"], "user typed [CARD] into mail [EMAIL]");
  EXPECT_FALSE(j.contains("dropped_fields"));
  EXPECT_EQ(cap.lines[0].find("4111"), std::string::npos);
}

TEST(Log, BannedAndInvalidFieldNamesDropped) {
  Capture cap;
  pl::Logger log("gate", cap.sink());
  log.warn("x", {{"value", std::string("leak")}, {"plaintext", std::string("leak")}, {"Bad Name", std::int64_t{1}},
                 {"a.b", std::int64_t{1}}, {"kept", std::int64_t{2}}});
  const auto j = nlohmann::json::parse(cap.lines.at(0));
  EXPECT_EQ(j["dropped_fields"], 4);
  EXPECT_EQ(j["fields"].size(), 1U);
  EXPECT_EQ(cap.lines[0].find("leak"), std::string::npos);
}

TEST(Log, FreeTextEventNameReplaced) {
  Capture cap;
  pl::Logger log("core", cap.sink());
  log.error("card 4111111111111111 failed");
  EXPECT_EQ(nlohmann::json::parse(cap.lines.at(0))["event"], "invalid_event_name");
}

TEST(Log, LevelFilterAndTruncation) {
  Capture cap;
  pl::Logger log("core", cap.sink(), pl::LogLevel::warn);
  log.debug("d");
  log.info("i");
  log.warn("w", {{"long", std::string(1000, 'a')}, {"huge", std::string(5000, 'a')}});
  ASSERT_EQ(cap.lines.size(), 1U);
  const auto fields = nlohmann::json::parse(cap.lines[0])["fields"];
  EXPECT_EQ(fields["long"].get<std::string>().size(), pl::kMaxLogString);
  EXPECT_EQ(fields["huge"], " [TRUNCATED]");  // one >4 KiB token: dropped whole, never cut
}

TEST(Log, TruncationKeepsUtf8Valid) {
  Capture cap;
  pl::Logger log("core", cap.sink());
  std::string s(pl::kMaxLogString - 1, 'a');
  s += "\xC3\xA9tail";  // two-byte sequence straddles the limit
  log.info("t", {{"s", s}});
  const auto out = nlohmann::json::parse(cap.lines.at(0))["fields"]["s"].get<std::string>();
  EXPECT_EQ(out.size(), pl::kMaxLogString - 1);
}

// Regression (Phase 0 review): values straddling the length limit are scrubbed whole.
TEST(Log, ScrubsBeforeTruncating) {
  Capture cap;
  pl::Logger log("core", cap.sink());
  for (const std::string tail : {"john.doe@example.com", "4111111111111111", "sk-ant-abcdefghijklmnop"}) {
    cap.lines.clear();
    log.info("t", {{"s", std::string(pl::kMaxLogString - 6, 'a') + " " + tail}});
    const auto out = nlohmann::json::parse(cap.lines.at(0))["fields"]["s"].get<std::string>();
    EXPECT_EQ(out.find(tail.substr(0, 5)), std::string::npos) << out.substr(out.size() - 10);
  }
  cap.lines.clear();
  log.info("t", {{"s", std::string(pl::kMaxLogScan + 10, 'b') + " 4111111111111111"}});
  EXPECT_EQ(cap.lines.at(0).find("4111"), std::string::npos);
}

TEST(Log, NamesWithLongDigitRunsRejected) {
  Capture cap;
  pl::Logger log("core", cap.sink());
  log.info("card.4111111111111111", {{"f123456", std::int64_t{1}}});
  const auto j = nlohmann::json::parse(cap.lines.at(0));
  EXPECT_EQ(j["event"], "invalid_event_name");
  EXPECT_EQ(j["dropped_fields"], 1);
  EXPECT_THROW(pl::Logger("core123456"), std::invalid_argument);
}

TEST(Log, RejectsBadComponentAndKnowsBannedNames) {
  EXPECT_THROW(pl::Logger("Bad Component"), std::invalid_argument);
  EXPECT_TRUE(pl::is_banned_field("secret"));
  EXPECT_FALSE(pl::is_banned_field("secrets"));
  EXPECT_TRUE(pl::is_identifier("a.b_c", 8));
  EXPECT_FALSE(pl::is_identifier("", 8));
  EXPECT_FALSE(pl::is_identifier("1abc", 8));
}

TEST(Log, StderrSinkDoesNotThrow) {
  pl::Logger log("core");
  EXPECT_NO_THROW(log.info("stderr.ok"));
}

}  // namespace
