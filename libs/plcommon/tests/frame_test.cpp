#include "pl/frame.hpp"

#include <gtest/gtest.h>
#include <rapidcheck/gtest.h>

#include <string>
#include <vector>

namespace {

std::string str(const std::vector<std::byte>& b) { return {reinterpret_cast<const char*>(b.data()), b.size()}; }

TEST(Frame, EncodeHasBigEndianHeader) {
  const auto f = pl::encode_frame(std::string_view("abc"));
  ASSERT_EQ(f.size(), 7U);
  EXPECT_EQ(f[0], std::byte{0});
  EXPECT_EQ(f[3], std::byte{3});
  EXPECT_EQ(str({f.begin() + 4, f.end()}), "abc");
}

TEST(Frame, EncodeRejectsEmptyAndOversize) {
  EXPECT_THROW((void)pl::encode_frame(std::string_view("")), std::length_error);
  const std::vector<std::byte> big(pl::kMaxFrameBytes + 1);
  EXPECT_THROW((void)pl::encode_frame(big), std::length_error);
}

TEST(Frame, DecodesByteAtATime) {
  auto wire = pl::encode_frame(std::string_view("hello"));
  const auto second = pl::encode_frame(std::string_view("world!"));
  wire.insert(wire.end(), second.begin(), second.end());
  pl::FrameDecoder d;
  std::vector<std::string> got;
  for (const auto b : wire) {
    d.feed(std::span(&b, 1));
    while (auto p = d.next()) {
      got.push_back(str(*p));
    }
  }
  EXPECT_EQ(got, (std::vector<std::string>{"hello", "world!"}));
  EXPECT_EQ(d.buffered(), 0U);
  EXPECT_FALSE(d.failed());
}

TEST(Frame, PartialFrameWaits) {
  const auto wire = pl::encode_frame(std::string_view("hello"));
  pl::FrameDecoder d;
  d.feed(std::span(wire).first(6));
  EXPECT_FALSE(d.next().has_value());
  EXPECT_FALSE(d.failed());
  d.feed(std::span(wire).subspan(6));
  EXPECT_EQ(str(*d.next()), "hello");
}

TEST(Frame, ZeroLengthFailsClosed) {
  pl::FrameDecoder d;
  const std::vector<std::byte> wire = {std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0}, std::byte{'x'}};
  d.feed(wire);
  EXPECT_FALSE(d.next().has_value());
  EXPECT_EQ(d.error(), pl::FrameError::empty_frame);
  // Stays failed: later valid frames are ignored.
  d.feed(pl::encode_frame(std::string_view("ok")));
  EXPECT_FALSE(d.next().has_value());
  EXPECT_TRUE(d.failed());
  EXPECT_EQ(d.buffered(), 0U);
}

TEST(Frame, OversizeHeaderFailsBeforeBuffering) {
  pl::FrameDecoder d(1024);
  const std::vector<std::byte> wire = {std::byte{0}, std::byte{0}, std::byte{4}, std::byte{1}};
  d.feed(wire);
  EXPECT_FALSE(d.next().has_value());
  EXPECT_EQ(d.error(), pl::FrameError::too_large);
  EXPECT_EQ(pl::to_string(d.error()), "too_large");
}

TEST(Frame, ErrorNames) {
  EXPECT_EQ(pl::to_string(pl::FrameError::none), "none");
  EXPECT_EQ(pl::to_string(pl::FrameError::empty_frame), "empty_frame");
}

RC_GTEST_PROP(FrameProp, RoundTripsAnySplit, (const std::vector<std::string>& msgs, unsigned split_seed)) {
  std::vector<std::byte> wire;
  std::vector<std::string> sent;
  for (const auto& m : msgs) {
    if (m.empty()) {
      continue;
    }
    const auto f = pl::encode_frame(std::string_view(m));
    wire.insert(wire.end(), f.begin(), f.end());
    sent.push_back(m);
  }
  pl::FrameDecoder d;
  std::vector<std::string> got;
  std::size_t off = 0;
  unsigned seed = split_seed | 1U;
  while (off < wire.size()) {
    seed = seed * 1103515245U + 12345U;
    const std::size_t n = std::min<std::size_t>(wire.size() - off, 1 + (seed >> 16U) % 17);
    d.feed(std::span(wire).subspan(off, n));
    off += n;
    while (auto p = d.next()) {
      got.push_back(str(*p));
    }
  }
  RC_ASSERT(got == sent);
  RC_ASSERT(!d.failed());
}

}  // namespace
