#include "pl/contracts.hpp"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>

namespace {

namespace fs = std::filesystem;
using nlohmann::json;

const json kSchema = json::parse(R"({
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "schema": {"const": "t.v1"},
    "n": {"type": "integer", "minimum": 0},
    "id": {"type": "string", "format": "uuid"},
    "kind": {"$ref": "#/$defs/kind"}
  },
  "required": ["schema", "n"],
  "additionalProperties": false,
  "$defs": {"kind": {"enum": ["a", "b"]}}
})");

TEST(Registry, ValidatesAndReportsPathsWithoutValues) {
  pl::contracts::Registry reg;
  reg.add("t.v1", kSchema);
  EXPECT_TRUE(reg.has("t.v1"));
  EXPECT_TRUE(reg.validate("t.v1", {{"schema", "t.v1"}, {"n", 1}, {"kind", "a"}}).ok);
  const auto bad = reg.validate("t.v1", {{"schema", "t.v1"}, {"n", -5}, {"kind", "SECRET-VALUE-4111"}});
  EXPECT_FALSE(bad.ok);
  ASSERT_FALSE(bad.errors.empty());
  for (const auto& e : bad.errors) {
    EXPECT_EQ(e.find("SECRET-VALUE-4111"), std::string::npos) << e;
    EXPECT_EQ(e.find("-5"), std::string::npos) << e;
  }
  EXPECT_FALSE(reg.validate("t.v1", {{"schema", "t.v1"}, {"n", 1}, {"extra", 1}}).ok);
  EXPECT_FALSE(reg.validate("t.v1", {{"schema", "t.v1"}, {"n", 1}, {"id", "not-a-uuid"}}).ok);
  EXPECT_TRUE(reg.validate("t.v1", {{"schema", "t.v1"}, {"n", 1}, {"id", "123e4567-e89b-12d3-a456-426614174000"}}).ok);
}

// Regression (Phase 0 review): a long string in a patterned field must fail
// validation, not overflow the stack inside the regex engine.
TEST(Registry, LongStringInPatternedFieldDoesNotCrash) {
  pl::contracts::Registry reg;
  reg.add("p.v1", json::parse(R"({"type": "object", "properties": {"c": {"type": "string", "maxLength": 32,
    "pattern": "^[a-z]+\\.[a-z]+$"}, "h": {"type": "string", "maxLength": 253,
    "pattern": "^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$"}}})"));
  const std::string longest(std::size_t{4} << 20U, 'a');
  EXPECT_FALSE(reg.validate("p.v1", {{"c", longest}}).ok);
  std::string host;
  for (int k = 0; k < 400000; ++k) {
    host += "a.";
  }
  host += "a";
  EXPECT_FALSE(reg.validate("p.v1", {{"h", host}}).ok);
}

TEST(Registry, UnknownSchemaFailsClosed) {
  const pl::contracts::Registry reg;
  EXPECT_FALSE(reg.validate("nope.v1", json::object()).ok);
  EXPECT_FALSE(pl::validate_dispatch(reg, {{"schema", "nope.v1"}}).ok);
}

TEST(Registry, RejectsBadSchemaAndUnsupportedFormat) {
  pl::contracts::Registry reg;
  EXPECT_ANY_THROW(reg.add("bad.v1", json::parse(R"({"type": 5})")));
  reg.add("f.v1", json::parse(R"({"type": "string", "format": "email"})"));
  EXPECT_FALSE(reg.validate("f.v1", "a@b.co").ok);  // only portable formats are accepted
}

TEST(Registry, MoveKeepsSchemas) {
  pl::contracts::Registry a;
  a.add("t.v1", kSchema);
  pl::contracts::Registry b = std::move(a);
  EXPECT_EQ(b.ids(), std::vector<std::string>{"t.v1"});
}

TEST(Registry, LoadDirRejectsBadFileNames) {
  const auto dir = fs::temp_directory_path() / ("pl-contracts-" + std::to_string(::testing::UnitTest::GetInstance()->random_seed()));
  fs::create_directories(dir);
  std::ofstream(dir / "Bad-Name.json") << "{}";
  EXPECT_THROW((void)pl::contracts::Registry::load_dir(dir), std::runtime_error);
  fs::remove_all(dir);
}

// Every fixture in contracts/fixtures: valid ones pass, invalid ones fail.
// The Python checker runs the same files (make test-contracts), so the two engines must agree.
TEST(ContractFixtures, AllFixturesAgree) {
  const fs::path root = PL_CONTRACTS_DIR;
  const auto reg = pl::contracts::Registry::load_dir(root / "schemas");
  std::size_t checked = 0;
  for (const auto& id : reg.ids()) {
    for (const std::string kind : {"valid", "invalid"}) {
      const auto dir = root / "fixtures" / id / kind;
      ASSERT_TRUE(fs::is_directory(dir)) << dir;
      for (const auto& f : fs::directory_iterator(dir)) {
        std::ifstream in(f.path());
        const auto r = reg.validate(id, json::parse(in));
        if (kind == "valid") {
          EXPECT_TRUE(r.ok) << f.path() << ": " << (r.errors.empty() ? "" : r.errors.front());
        } else {
          EXPECT_FALSE(r.ok) << f.path() << " should fail";
        }
        ++checked;
      }
    }
  }
  EXPECT_GE(reg.ids().size(), 18U);
  EXPECT_GT(checked, reg.ids().size());
}

}  // namespace
