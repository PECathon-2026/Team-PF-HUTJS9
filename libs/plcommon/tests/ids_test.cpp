#include "pl/ids.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <thread>
#include <vector>

namespace {

TEST(Ids, StrictlyIncreasing) {
  pl::MonotonicIds ids;
  std::uint64_t last = 0;
  for (int k = 0; k < 10000; ++k) {
    const auto n = ids.next();
    ASSERT_GT(n, last);
    last = n;
  }
}

TEST(Ids, FloorAboveClockStillIncreases) {
  pl::MonotonicIds ids(~0ULL - 10);
  EXPECT_EQ(ids.next(), ~0ULL - 9);
}

TEST(Ids, UniqueAcrossThreads) {
  pl::MonotonicIds ids;
  std::vector<std::vector<std::uint64_t>> got(4);
  std::vector<std::thread> threads;
  for (auto& g : got) {
    threads.emplace_back([&ids, &g] {
      for (int k = 0; k < 5000; ++k) {
        g.push_back(ids.next());
      }
    });
  }
  for (auto& t : threads) {
    t.join();
  }
  std::vector<std::uint64_t> all;
  for (const auto& g : got) {
    EXPECT_TRUE(std::is_sorted(g.begin(), g.end()));
    all.insert(all.end(), g.begin(), g.end());
  }
  std::sort(all.begin(), all.end());
  EXPECT_EQ(std::adjacent_find(all.begin(), all.end()), all.end());
}

TEST(Ids, Format) {
  EXPECT_EQ(pl::format_id("dec", 0x1858f3a2c4b10ULL), "dec-0001858f3a2c4b10");
  EXPECT_THROW((void)pl::format_id("D", 1), std::invalid_argument);
  EXPECT_THROW((void)pl::format_id("toolongprefix", 1), std::invalid_argument);
  EXPECT_THROW((void)pl::format_id("a1", 1), std::invalid_argument);
}

TEST(Ids, Clocks) {
  EXPECT_GT(pl::realtime_ns(), 1'600'000'000'000'000'000ULL);
  const auto a = pl::monotonic_ns();
  EXPECT_GE(pl::monotonic_ns(), a);
}

}  // namespace
