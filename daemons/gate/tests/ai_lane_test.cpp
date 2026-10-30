// AI lane tests (owner: LNX): fail-closed order, egress record shape, replay determinism.
#include <gtest/gtest.h>

#include "pl/contracts.hpp"
#include "pl/gate/ai_lane.hpp"
#include "pl/ids.hpp"

namespace {

using pl::gate::AiLane;
using pl::gate::GateConfig;
using pl::gate::Liveness;
using pl::gate::ReplayProvider;

const pl::contracts::Registry& reg() {
  static const auto r = pl::contracts::Registry::load_dir(PL_CONTRACTS_DIR "/schemas");
  return r;
}

nlohmann::json request(const std::string& content, const std::string& taint = "public") {
  return {{"schema", "gate_ai_request.v1"}, {"request_id", "rq-0000000000000001"}, {"session_id", "ss-0000000000000001"},
          {"provider", "replay"},          {"model", "login-happy"},                {"taint", taint},
          {"messages", {{{"role", "user"}, {"content", content}}}},                   {"max_tokens", 256}};
}

struct Fixture : ::testing::Test {
  Liveness live;
  std::unique_ptr<AiLane> lane;
  void SetUp() override {
    lane = std::make_unique<AiLane>(GateConfig{}, reg(), live);
    auto rp = std::make_shared<ReplayProvider>("/nonexistent");
    rp->add_cassette("login-happy", {{"format", "pl.replay.v1"},
                                     {"name", "login-happy"},
                                     {"steps", {{{"response", R"({"kind":"done"})"}}, {{"response", "second"}}}}});
    lane->add_provider("replay", rp);
    beat();
  }
  void beat() {
    live.beat("core", pl::realtime_ns());
    live.beat("vault", pl::realtime_ns());
  }
  static void expect_valid(const pl::gate::LaneResult& r) {
    EXPECT_TRUE(reg().validate("gate_ai_response.v1", r.response).ok) << r.response.dump();
    EXPECT_TRUE(reg().validate("egress_record.v1", r.egress).ok) << r.egress.dump();
  }
};

TEST_F(Fixture, SendsCleanRequestAndRecordsExactPayload) {
  auto r = lane->process(request("Log in with [REDACTED:PASSWORD#1]"));
  expect_valid(r);
  EXPECT_EQ(r.response["status"], "ok");
  EXPECT_EQ(r.response["content"], R"({"kind":"done"})");
  EXPECT_EQ(r.egress["verdict"], "sent");
  EXPECT_EQ(r.egress["payload"]["messages"][0]["content"], "Log in with [REDACTED:PASSWORD#1]");
  EXPECT_EQ(r.egress["payload_sha256"], pl::gate::payload_sha256(request("Log in with [REDACTED:PASSWORD#1]")["messages"]));
  // Replay is ordered per session.
  EXPECT_EQ(lane->process(request("x")).response["content"], "second");
}

TEST_F(Fixture, BlocksCardAndNeverRecordsIt) {
  auto r = lane->process(request("card 4111 1111 1111 1111"));
  expect_valid(r);
  EXPECT_EQ(r.response["status"], "blocked");
  EXPECT_EQ(r.response["rule_id"], "G-101");
  EXPECT_EQ(r.egress["verdict"], "blocked");
  EXPECT_FALSE(r.egress.contains("payload"));
  EXPECT_EQ(r.egress.dump().find("4111"), std::string::npos);
  EXPECT_EQ(r.response.dump().find("4111"), std::string::npos);
}

TEST_F(Fixture, BlocksListedCanary) {
  pl::gate::CanaryRegistry c;
  c.add("ZEPHYR-PLANT-0042");
  lane->set_canaries(std::move(c));
  auto r = lane->process(request("note: zephyr plant 0042"));
  expect_valid(r);
  EXPECT_EQ(r.response["rule_id"], "G-202");
}

TEST_F(Fixture, FailsClosedOnSchemaTaintLivenessKillAndAllowList) {
  auto bad = request("hi");
  bad["extra"] = 1;
  EXPECT_EQ(lane->process(bad).response["rule_id"], "G-001");
  EXPECT_EQ(lane->process(nlohmann::json("garbage")).response["rule_id"], "G-001");
  EXPECT_EQ(lane->process(request("hi", "personal")).response["rule_id"], "G-004");
  auto other = request("hi");
  other["provider"] = "anthropic";
  EXPECT_EQ(lane->process(other).response["rule_id"], "G-005");
  auto img = request("hi");
  img["images"] = {{{"media_type", "image/png"}, {"data_b64", "AAAA"}}};
  EXPECT_EQ(lane->process(img).response["rule_id"], "G-110");
  Liveness stale(std::chrono::milliseconds{1});
  AiLane l2(GateConfig{}, reg(), stale);
  stale.beat("core", 1);
  stale.beat("vault", 1);
  auto r = l2.process(request("hi"));
  expect_valid(r);
  EXPECT_EQ(r.response["rule_id"], "G-003");
  lane->kill();
  EXPECT_EQ(lane->process(request("hi")).response["rule_id"], "G-002");
}

TEST_F(Fixture, ProviderErrorIsReportedNotInvented) {
  auto r = request("hi");
  r["model"] = "no-such-cassette";
  auto out = lane->process(r);
  expect_valid(out);
  EXPECT_EQ(out.response["status"], "error");
  EXPECT_FALSE(out.response.contains("content"));
}

}  // namespace
