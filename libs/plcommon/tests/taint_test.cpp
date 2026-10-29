#include "pl/taint.hpp"

#include <gtest/gtest.h>
#include <rapidcheck/gtest.h>

namespace {

using pl::TaintCategory;
using pl::TaintLabel;
using pl::TaintLevel;

constexpr auto kCats = static_cast<unsigned>(TaintCategory::count_);

TaintLabel gen_label(unsigned bits, unsigned extra_level) {
  TaintLabel l;
  for (unsigned k = 0; k < kCats; ++k) {
    if (((bits >> k) & 1U) != 0) {
      l = l.join(TaintLabel::of(static_cast<TaintCategory>(k)));
    }
  }
  return l.join(TaintLabel::at(static_cast<TaintLevel>(extra_level % 5)));
}

TEST(Taint, BottomIsPublicAndAllowsEgress) {
  EXPECT_TRUE(TaintLabel{}.allows_egress());
  EXPECT_FALSE(TaintLabel::at(TaintLevel::internal).allows_egress());
  EXPECT_FALSE(TaintLabel::of(TaintCategory::email).allows_egress());
}

TEST(Taint, JoinTakesMostSecret) {
  const auto card = TaintLabel::of(TaintCategory::card);
  const auto pw = TaintLabel::of(TaintCategory::password);
  const auto j = card.join(pw);
  EXPECT_EQ(j.level(), TaintLevel::secret);
  EXPECT_TRUE(j.has(TaintCategory::card));
  EXPECT_TRUE(j.has(TaintCategory::password));
  EXPECT_TRUE(card.leq(j));
  EXPECT_FALSE(j.leq(card));
}

TEST(Taint, Names) {
  EXPECT_EQ(pl::to_string(TaintLevel::sensitive), "sensitive");
  EXPECT_EQ(pl::to_string(TaintCategory::upi_id), "UPI_ID");
  EXPECT_EQ(pl::taint_level_from("secret"), TaintLevel::secret);
  EXPECT_FALSE(pl::taint_level_from("SECRET").has_value());
  EXPECT_EQ(pl::taint_category_from("QUASI_ID"), TaintCategory::quasi_id);
  EXPECT_FALSE(pl::taint_category_from("card").has_value());
  EXPECT_EQ(pl::level_of(TaintCategory::otp), TaintLevel::secret);
}

TEST(Taint, JsonRoundTripAndValidation) {
  const auto l = TaintLabel::of(TaintCategory::aadhaar).join(TaintLabel::of(TaintCategory::email));
  const auto j = l.to_json();
  EXPECT_EQ(j["schema"], "taint_label.v1");
  EXPECT_EQ(j["level"], "sensitive");
  EXPECT_EQ(j["categories"], (nlohmann::json{"AADHAAR", "EMAIL"}));
  EXPECT_EQ(TaintLabel::from_json(j), l);
  EXPECT_THROW((void)TaintLabel::from_json({{"schema", "x"}}), std::invalid_argument);
  EXPECT_THROW((void)TaintLabel::from_json({{"schema", "taint_label.v1"}, {"level", "huge"}, {"categories", nlohmann::json::array()}}),
               std::invalid_argument);
  EXPECT_THROW((void)TaintLabel::from_json({{"schema", "taint_label.v1"}, {"level", "public"}, {"categories", {"NOPE"}}}),
               std::invalid_argument);
  // A card is at least sensitive; claiming "public" is rejected.
  EXPECT_THROW((void)TaintLabel::from_json({{"schema", "taint_label.v1"}, {"level", "public"}, {"categories", {"CARD"}}}),
               std::invalid_argument);
}

TEST(Taint, TopIsAboveEverything) {
  for (unsigned k = 0; k < kCats; ++k) {
    EXPECT_TRUE(TaintLabel::of(static_cast<TaintCategory>(k)).leq(TaintLabel::top()));
  }
}

RC_GTEST_PROP(TaintLattice, Laws, (unsigned a, unsigned b, unsigned c, unsigned la, unsigned lb, unsigned lc)) {
  const auto x = gen_label(a, la);
  const auto y = gen_label(b, lb);
  const auto z = gen_label(c, lc);
  RC_ASSERT(x.join(y) == y.join(x));                       // commutative
  RC_ASSERT(x.join(y).join(z) == x.join(y.join(z)));       // associative
  RC_ASSERT(x.join(x) == x);                               // idempotent
  RC_ASSERT(x.meet(y) == y.meet(x));
  RC_ASSERT(x.meet(y).meet(z) == x.meet(y.meet(z)));
  RC_ASSERT(x.join(x.meet(y)) == x);                       // absorption
  RC_ASSERT(x.meet(x.join(y)) == x);
  RC_ASSERT(x.leq(x.join(y)) && y.leq(x.join(y)));         // join is an upper bound
  RC_ASSERT(x.meet(y).leq(x) && x.meet(y).leq(y));         // meet is a lower bound
  RC_ASSERT(x.leq(y) == (x.join(y) == y));                 // order agrees with join
  RC_ASSERT(TaintLabel{}.leq(x));                          // bottom
  RC_ASSERT(TaintLabel::from_json(x.to_json()) == x);      // wire round trip
  RC_ASSERT(x.allows_egress() == (x == TaintLabel{}));
}

}  // namespace
