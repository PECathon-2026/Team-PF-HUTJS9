#include "pl/ids.hpp"

#include <algorithm>
#include <array>
#include <ctime>
#include <stdexcept>

namespace pl {

namespace {

std::uint64_t clock_ns(clockid_t id) noexcept {
  timespec ts{};
  ::clock_gettime(id, &ts);
  return (static_cast<std::uint64_t>(ts.tv_sec) * 1'000'000'000ULL) + static_cast<std::uint64_t>(ts.tv_nsec);
}

}  // namespace

std::uint64_t realtime_ns() noexcept { return clock_ns(CLOCK_REALTIME); }
std::uint64_t monotonic_ns() noexcept { return clock_ns(CLOCK_MONOTONIC); }

std::uint64_t MonotonicIds::next() noexcept {
  std::uint64_t last = last_.load(std::memory_order_relaxed);
  for (;;) {
    const std::uint64_t candidate = std::max(last + 1, realtime_ns());
    if (last_.compare_exchange_weak(last, candidate, std::memory_order_relaxed)) {
      return candidate;
    }
  }
}

std::string format_id(std::string_view prefix, std::uint64_t id) {
  if (prefix.size() < 2 || prefix.size() > 8 || !std::all_of(prefix.begin(), prefix.end(), [](char c) { return c >= 'a' && c <= 'z'; })) {
    throw std::invalid_argument("id prefix must be 2-8 lowercase letters");
  }
  static constexpr std::array<char, 16> kHex = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
  std::string out(prefix);
  out.push_back('-');
  for (int shift = 60; shift >= 0; shift -= 4) {
    out.push_back(kHex.at(static_cast<std::size_t>((id >> static_cast<unsigned>(shift)) & 0xFU)));
  }
  return out;
}

}  // namespace pl
