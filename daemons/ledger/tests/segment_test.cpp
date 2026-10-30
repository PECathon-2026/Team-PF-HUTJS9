#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>

#include "ledger/segment.hpp"

using namespace pl::ledger;
namespace fs = std::filesystem;

namespace {
fs::path tmpdir(const char* name) {
  const fs::path p = fs::temp_directory_path() / (std::string("pl-ledger-test-") + name + "-" + std::to_string(::getpid()));
  fs::remove_all(p);
  return p;
}
}  // namespace

TEST(Sha256, KnownAnswer) {
  EXPECT_EQ(sha256_hex(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  EXPECT_EQ(sha256_hex("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST(Segments, AppendChainAndVerify) {
  const auto dir = tmpdir("chain");
  {
    SegmentWriter w({dir, 4096, false});
    EXPECT_EQ(w.head_hash(), kZeroHash);
    std::uint64_t seq = 0;
    const auto l1 = w.append("event", {{"a", 1}}, 100, &seq);
    EXPECT_EQ(seq, 1U);
    EXPECT_EQ(l1, R"({"kind":"event","prev":")" + std::string(kZeroHash) + R"(","record":{"a":1},"seq":1,"ts_ns":100})");
    const auto l2 = w.append("event", {{"a", 2}}, 101, &seq);
    EXPECT_EQ(seq, 2U);
    EXPECT_NE(l2.find(sha256_hex(l1)), std::string::npos);  // prev = hash of line 1
  }
  const auto v = verify_segments(dir);
  EXPECT_TRUE(v.ok) << v.error;
  EXPECT_EQ(v.entries, 2U);
  fs::remove_all(dir);
}

TEST(Segments, RotationSealsAndRecoveryContinuesChain) {
  const auto dir = tmpdir("rot");
  {
    SegmentWriter w({dir, 200, false});
    for (int i = 0; i < 10; ++i) w.append("event", {{"i", i}}, 1, nullptr);
  }
  std::size_t files = 0;
  for (const auto& e : fs::directory_iterator(dir)) {
    ++files;
    (void)e;
  }
  EXPECT_GT(files, 1U);
  EXPECT_EQ(fs::status(dir / "seg-00000001.jsonl").permissions() & fs::perms::owner_write, fs::perms::none);  // sealed
  {
    SegmentWriter w({dir, 200, false});  // recover
    EXPECT_EQ(w.next_seq(), 11U);
    w.append("event", {{"i", 10}}, 2, nullptr);
  }
  const auto v = verify_segments(dir);
  EXPECT_TRUE(v.ok) << v.error;
  EXPECT_EQ(v.entries, 11U);
  fs::remove_all(dir);
}

TEST(Segments, TornTailIsTruncatedOnRecovery) {
  const auto dir = tmpdir("torn");
  {
    SegmentWriter w({dir, 4096, false});
    w.append("event", {{"i", 1}}, 1, nullptr);
  }
  {
    std::ofstream out(dir / "seg-00000001.jsonl", std::ios::app | std::ios::binary);
    out << R"({"kind":"event","pre)";  // crash mid-write
  }
  SegmentWriter w({dir, 4096, false});
  EXPECT_EQ(w.next_seq(), 2U);
  w.append("event", {{"i", 2}}, 2, nullptr);
  EXPECT_TRUE(verify_segments(dir).ok);
  fs::remove_all(dir);
}

TEST(Segments, TamperingIsDetected) {
  const auto dir = tmpdir("tamper");
  {
    SegmentWriter w({dir, 4096, false});
    for (int i = 0; i < 3; ++i) w.append("event", {{"i", i}}, 1, nullptr);
  }
  const auto file = dir / "seg-00000001.jsonl";
  std::string content;
  {
    std::ifstream in(file, std::ios::binary);
    content.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
  }
  const auto pos = content.find("\"i\":1");
  ASSERT_NE(pos, std::string::npos);
  content[pos + 4] = '7';
  {
    std::ofstream out(file, std::ios::binary | std::ios::trunc);
    out << content;
  }
  const auto v = verify_segments(dir);
  EXPECT_FALSE(v.ok);
  EXPECT_NE(v.error.find("hash chain broken"), std::string::npos);
  fs::remove_all(dir);
}
