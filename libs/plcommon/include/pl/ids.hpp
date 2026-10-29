// Monotonic IDs (owner: LNX). Strictly increasing within a process and roughly
// time-ordered across restarts: next = max(last + 1, CLOCK_REALTIME ns).
// Python twin: plpy.ids.
#pragma once

#include <atomic>
#include <cstdint>
#include <string>
#include <string_view>

namespace pl {

class MonotonicIds {
 public:
  MonotonicIds() noexcept = default;
  explicit MonotonicIds(std::uint64_t floor) noexcept : last_(floor) {}
  [[nodiscard]] std::uint64_t next() noexcept;

 private:
  std::atomic<std::uint64_t> last_{0};
};

// "<prefix>-<16 lowercase hex digits>", e.g. "dec-0001858f3a2c4b10". Prefix: [a-z]{2,8}.
[[nodiscard]] std::string format_id(std::string_view prefix, std::uint64_t id);

[[nodiscard]] std::uint64_t realtime_ns() noexcept;
[[nodiscard]] std::uint64_t monotonic_ns() noexcept;

}  // namespace pl
