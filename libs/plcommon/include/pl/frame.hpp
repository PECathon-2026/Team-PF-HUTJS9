// Length-prefixed framing (owner: LNX, AD-04).
//
// Wire format: a 4-byte big-endian unsigned length L, then exactly L payload
// bytes. 1 <= L <= kMaxFrameBytes. Anything else is a protocol error, and the
// decoder stays failed afterwards (fail-closed: the caller must drop the
// connection). Python twin: plpy.frame.
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace pl {

inline constexpr std::size_t kFrameHeaderBytes = 4;
inline constexpr std::uint32_t kMaxFrameBytes = 16U * 1024U * 1024U;

enum class FrameError : std::uint8_t { none, empty_frame, too_large };

[[nodiscard]] std::string_view to_string(FrameError e) noexcept;

// Throws std::length_error when the payload is empty or larger than kMaxFrameBytes.
[[nodiscard]] std::vector<std::byte> encode_frame(std::span<const std::byte> payload);
[[nodiscard]] std::vector<std::byte> encode_frame(std::string_view payload);

class FrameDecoder {
 public:
  explicit FrameDecoder(std::uint32_t max_frame = kMaxFrameBytes) noexcept : max_frame_(max_frame) {}

  // Appends received bytes. Ignored once the decoder has failed.
  void feed(std::span<const std::byte> data);

  // Next complete payload, if any. Sets error() and returns nullopt on a bad header.
  [[nodiscard]] std::optional<std::vector<std::byte>> next();

  [[nodiscard]] FrameError error() const noexcept { return error_; }
  [[nodiscard]] bool failed() const noexcept { return error_ != FrameError::none; }
  [[nodiscard]] std::size_t buffered() const noexcept { return buf_.size() - pos_; }

 private:
  void compact();

  std::vector<std::byte> buf_;
  std::size_t pos_ = 0;
  std::uint32_t max_frame_;
  FrameError error_ = FrameError::none;
};

}  // namespace pl
