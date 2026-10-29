#include "pl/scrub.hpp"

#include <gtest/gtest.h>

#include <fstream>

#include <nlohmann/json.hpp>

namespace {

TEST(Scrub, SharedVectors) {
  std::ifstream in(PL_TESTDATA_DIR "/scrubber_vectors.json");
  ASSERT_TRUE(in) << "missing scrubber_vectors.json";
  const auto doc = nlohmann::json::parse(in);
  std::size_t n = 0;
  for (const auto& v : doc.at("vectors")) {
    std::string input;
    if (v.at("input").is_array()) {
      for (const auto& part : v.at("input")) {
        input += part.get<std::string>();
      }
    } else {
      input = v.at("input").get<std::string>();
    }
    EXPECT_EQ(pl::scrub(input), v.at("expected").get<std::string>()) << v.at("name").get<std::string>();
    ++n;
  }
  EXPECT_GE(n, 20U);
}

TEST(Scrub, Luhn) {
  EXPECT_TRUE(pl::luhn_valid("4111111111111111"));
  EXPECT_TRUE(pl::luhn_valid("0"));
  EXPECT_FALSE(pl::luhn_valid("4111111111111112"));
  EXPECT_FALSE(pl::luhn_valid(""));
  EXPECT_FALSE(pl::luhn_valid("41a1"));
}

TEST(Scrub, Verhoeff) {
  EXPECT_TRUE(pl::verhoeff_valid("2363"));  // classic example: 236 + check digit 3
  EXPECT_FALSE(pl::verhoeff_valid("2364"));
  EXPECT_FALSE(pl::verhoeff_valid(""));
  EXPECT_FALSE(pl::verhoeff_valid("23x3"));
}

TEST(Scrub, NeverLeavesLongDigitRuns) {
  // Whatever the digits, no output contains 8 consecutive digits.
  for (unsigned seed = 1; seed < 2000; ++seed) {
    std::string s = "x ";
    unsigned r = seed;
    for (int k = 0; k < 24; ++k) {
      r = r * 1664525U + 1013904223U;
      const unsigned pick = (r >> 24U) % 12;
      s.push_back(pick < 10 ? static_cast<char>('0' + pick) : (pick == 10 ? ' ' : '-'));
    }
    const std::string out = pl::scrub(s);
    int run = 0;
    for (const char c : out) {
      run = (c >= '0' && c <= '9') ? run + 1 : 0;
      ASSERT_LT(run, 8) << out;
    }
  }
}

}  // namespace
