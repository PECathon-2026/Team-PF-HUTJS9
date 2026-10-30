#include <gtest/gtest.h>
#include <sys/socket.h>
#include <unistd.h>

#include <filesystem>
#include <fstream>

#include "pl/contracts.hpp"
#include "ledger/ledger.hpp"
#include "ledger/server.hpp"

using namespace pl::ledger;
namespace fs = std::filesystem;

namespace {

fs::path tmpdir(const char* name) {
  const fs::path p = fs::temp_directory_path() / (std::string("pl-ledger-test-") + name + "-" + std::to_string(::getpid()));
  fs::remove_all(p);
  return p;
}

nlohmann::json fixture(const char* rel) {
  std::ifstream in(fs::path(PL_CONTRACTS_DIR) / "fixtures" / rel);
  return nlohmann::json::parse(in);
}

const pl::contracts::Registry& registry() {
  static const auto r = pl::contracts::Registry::load_dir(fs::path(PL_CONTRACTS_DIR) / "schemas");
  return r;
}

LedgerConfig cfg(const fs::path& dir) {
  LedgerConfig c;
  c.segments = {dir, 1U << 20, false};
  return c;
}

}  // namespace

TEST(Ledger, AcceptsContractFixtures) {
  const auto dir = tmpdir("accept");
  Ledger l(cfg(dir), registry());
  EXPECT_TRUE(l.ingest(fixture("event.v1/valid/detection.json")).accepted);
  EXPECT_TRUE(l.ingest(fixture("egress_record.v1/valid/ai-sent.json")).accepted);
  EXPECT_TRUE(l.ingest(fixture("decision_record.v1/valid/gate-block.json")).accepted);
  EXPECT_TRUE(verify_segments(dir).ok);
  fs::remove_all(dir);
}

TEST(Ledger, RejectsBannedFieldAndRecordsDecision) {
  const auto dir = tmpdir("banned");
  Ledger l(cfg(dir), registry());
  auto ev = fixture("event.v1/valid/detection.json");
  ev["value"] = "4111111111111111";
  const auto r = l.ingest(ev);
  EXPECT_FALSE(r.accepted);
  EXPECT_EQ(r.rule_id, "LG-001");
  EXPECT_EQ(r.code, "banned_field");
  // Only the ledger's own decision record was stored, with no trace of the value.
  const auto lines = read_all_lines(dir);
  ASSERT_EQ(lines.size(), 1U);
  EXPECT_EQ(lines[0].find("4111"), std::string::npos);
  const auto e = nlohmann::json::parse(lines[0]);
  EXPECT_EQ(e["kind"], "decision_record");
  EXPECT_EQ(e["record"]["rule_id"], "LG-001");
  EXPECT_EQ(e["record"]["verdict"], "block");
  EXPECT_TRUE(registry().validate("decision_record.v1", e["record"]).ok);
  fs::remove_all(dir);
}

TEST(Ledger, RejectsPlantedCanaryEvenInsideEgressPayload) {
  const auto dir = tmpdir("canary");
  Ledger l(cfg(dir), registry());
  auto eg = fixture("egress_record.v1/valid/ai-sent.json");
  const std::string canary = make_canary("7QK3M9WX2HT5R8VN");
  eg["payload"]["messages"][0]["content"] = "use " + canary;
  const auto r = l.ingest(eg);
  EXPECT_FALSE(r.accepted);
  EXPECT_EQ(r.rule_id, "LG-002");
  for (const auto& line : read_all_lines(dir)) EXPECT_EQ(line.find("7QK3M9"), std::string::npos);
  fs::remove_all(dir);
}

TEST(Ledger, RejectsUnknownAndRawZoneSchemasAndInvalidMessages) {
  const auto dir = tmpdir("schema");
  Ledger l(cfg(dir), registry());
  EXPECT_EQ(l.ingest({{"schema", "page_snapshot.v1"}}).code, "unknown_schema");
  EXPECT_EQ(l.ingest({{"schema", "vault_api.v1"}}).code, "unknown_schema");
  EXPECT_EQ(l.ingest({{"hello", 1}}).code, "unknown_schema");
  EXPECT_EQ(l.ingest(nlohmann::json::array()).code, "schema_invalid");
  auto ev = fixture("event.v1/valid/detection.json");
  ev["free_text"] = "hello";  // closed shape
  EXPECT_EQ(l.ingest(ev).code, "schema_invalid");
  fs::remove_all(dir);
}

TEST(Ledger, StatsAndBurst) {
  const auto dir = tmpdir("stats");
  Ledger l(cfg(dir), registry());
  (void)l.ingest(fixture("event.v1/valid/detection.json"));
  (void)l.ingest({{"schema", "vault_api.v1"}});
  const auto stats = l.stats_message();
  EXPECT_EQ(stats["accepted"], 1);
  EXPECT_EQ(stats["rejected"], 1);
  EXPECT_EQ(stats["by_rule"]["LG-003"], 1);
  const auto burst = l.subscribe_burst();
  EXPECT_EQ(burst.front()["type"], "hello");
  EXPECT_EQ(burst.back()["type"], "stats");
  EXPECT_EQ(burst.size(), 4U);  // hello + 2 entries + stats
  fs::remove_all(dir);
}

namespace {
// Next message, skipping periodic stats unless want_stats.
nlohmann::json recv_msg(pl::FramedSocket& s, bool want_stats = false) {
  for (;;) {
    const auto p = s.recv(std::chrono::milliseconds(1000));
    EXPECT_TRUE(p.has_value());
    if (!p) return {};
    auto m = pl::parse_json_bounded(*p);
    if (want_stats || m["type"] != "stats") return m;
  }
}
}  // namespace

TEST(Server, IngestAckAndStreamOverUds) {
  const auto dir = tmpdir("server");
  fs::create_directories(dir);
  Ledger l(cfg(dir / "seg"), registry());
  Server s(l, (dir / "in.sock").string(), (dir / "out.sock").string());

  pl::FramedSocket sub(pl::connect_unix((dir / "out.sock").string()));
  s.step(50);
  EXPECT_EQ(recv_msg(sub)["type"], "hello");
  EXPECT_EQ(recv_msg(sub, true)["type"], "stats");
  EXPECT_EQ(s.subscribers(), 1U);

  pl::FramedSocket in(pl::connect_unix((dir / "in.sock").string()));
  in.send(std::as_bytes(std::span(std::string_view(fixture("event.v1/valid/detection.json").dump()))));
  s.step(50);  // accept
  s.step(50);  // read + ack
  auto ack = recv_msg(in);
  EXPECT_EQ(ack["ok"], true);
  EXPECT_EQ(ack["seq"], 1);
  auto entry = recv_msg(sub);
  EXPECT_EQ(entry["type"], "entry");
  EXPECT_EQ(entry["kind"], "event");

  auto bad = fixture("event.v1/valid/detection.json");
  bad["secret"] = "x";
  in.send(std::as_bytes(std::span(std::string_view(bad.dump()))));
  s.step(50);
  ack = recv_msg(in);
  EXPECT_EQ(ack["ok"], false);
  EXPECT_EQ(ack["rule_id"], "LG-001");
  EXPECT_EQ(recv_msg(sub)["kind"], "decision_record");
  fs::remove_all(dir);
}
