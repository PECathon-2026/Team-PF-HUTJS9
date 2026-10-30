// Append-only segment files with a SHA-256 hash chain (owner: WIN-B).
//
// Directory layout: seg-00000001.jsonl, seg-00000002.jsonl, ... One entry per
// line:  {"kind":..,"prev":"<hex sha256 of previous line>","record":{..},"seq":N,"ts_ns":..}
// (keys sorted, compact). entry hash = SHA-256(line without the newline); the
// first entry's prev is 64 zeros. Segments rotate at max_segment_bytes and are
// made read-only when sealed. Sprint 2 builds the Merkle tree over these hashes.
#pragma once

#include <cstdint>
#include <filesystem>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

#include "pl/uds.hpp"

namespace pl::ledger {

struct SegmentConfig {
  std::filesystem::path dir;
  std::uint64_t max_segment_bytes = std::uint64_t{4} * 1024 * 1024;
  bool sync = true;  // fdatasync after every append
};

[[nodiscard]] std::string sha256_hex(std::string_view data);
inline constexpr std::string_view kZeroHash = "0000000000000000000000000000000000000000000000000000000000000000";

class SegmentWriter {
 public:
  // Creates dir if needed; recovers seq and chain head from existing segments
  // (a torn, unterminated tail line is truncated). Throws std::runtime_error.
  explicit SegmentWriter(SegmentConfig cfg);

  // Appends one entry; returns the line written (without newline). Throws on I/O error.
  std::string append(std::string_view kind, const nlohmann::json& record, std::uint64_t ts_ns,
                     std::uint64_t* seq_out = nullptr);

  [[nodiscard]] std::uint64_t next_seq() const noexcept { return next_seq_; }
  [[nodiscard]] const std::string& head_hash() const noexcept { return head_; }

 private:
  void open_segment(std::uint64_t index);
  void seal_current();

  SegmentConfig cfg_;
  Fd fd_;
  std::uint64_t index_ = 0;
  std::uint64_t size_ = 0;
  std::uint64_t next_seq_ = 1;
  std::string head_{kZeroHash};
};

struct VerifyResult {
  bool ok = false;
  std::uint64_t entries = 0;
  std::string error;  // empty when ok; never contains record contents
};

// Re-reads every segment in order and checks seq continuity and the hash chain.
[[nodiscard]] VerifyResult verify_segments(const std::filesystem::path& dir);

// All entry lines of all segments, in order (tests and tooling).
[[nodiscard]] std::vector<std::string> read_all_lines(const std::filesystem::path& dir);

}  // namespace pl::ledger
