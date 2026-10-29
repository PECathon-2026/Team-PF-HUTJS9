#include "pl/frame.hpp"

#include <algorithm>
#include <stdexcept>

namespace pl {

std::string_view to_string(FrameError e) noexcept {
  switch (e) {
    case FrameError::none:
      return "none";
    case FrameError::empty_frame:
      return "empty_frame";
    case FrameError::too_large:
      return "too_large";
  }
  return "unknown";
}

std::vector<std::byte> encode_frame(std::span<const std::byte> payload) {
  if (payload.empty()) {
    throw std::length_error("frame payload is empty");
  }
  if (payload.size() > kMaxFrameBytes) {
    throw std::length_error("frame payload exceeds kMaxFrameBytes");
  }
  const auto n = static_cast<std::uint32_t>(payload.size());
  std::vector<std::byte> out;
  out.reserve(kFrameHeaderBytes + payload.size());
  out.push_back(static_cast<std::byte>((n >> 24U) & 0xFFU));
  out.push_back(static_cast<std::byte>((n >> 16U) & 0xFFU));
  out.push_back(static_cast<std::byte>((n >> 8U) & 0xFFU));
  out.push_back(static_cast<std::byte>(n & 0xFFU));
  out.insert(out.end(), payload.begin(), payload.end());
  return out;
}

std::vector<std::byte> encode_frame(std::string_view payload) {
  return encode_frame(std::as_bytes(std::span<const char>(payload.data(), payload.size())));
}

void FrameDecoder::feed(std::span<const std::byte> data) {
  if (failed() || data.empty()) {
    return;
  }
  compact();
  buf_.insert(buf_.end(), data.begin(), data.end());
}

void FrameDecoder::compact() {
  // Drop consumed bytes once they dominate the buffer, keeping appends amortised O(1).
  if (pos_ > 0 && pos_ * 2 >= buf_.size()) {
    buf_.erase(buf_.begin(), buf_.begin() + static_cast<std::ptrdiff_t>(pos_));
    pos_ = 0;
  }
}

std::optional<std::vector<std::byte>> FrameDecoder::next() {
  if (failed() || buffered() < kFrameHeaderBytes) {
    return std::nullopt;
  }
  const auto* h = buf_.data() + pos_;
  const std::uint32_t n = (std::to_integer<std::uint32_t>(h[0]) << 24U) | (std::to_integer<std::uint32_t>(h[1]) << 16U) |
                          (std::to_integer<std::uint32_t>(h[2]) << 8U) | std::to_integer<std::uint32_t>(h[3]);
  if (n == 0) {
    error_ = FrameError::empty_frame;
  } else if (n > max_frame_) {
    error_ = FrameError::too_large;
  }
  if (failed()) {
    buf_.clear();
    buf_.shrink_to_fit();
    pos_ = 0;
    return std::nullopt;
  }
  if (buffered() - kFrameHeaderBytes < n) {
    return std::nullopt;
  }
  const auto begin = buf_.begin() + static_cast<std::ptrdiff_t>(pos_ + kFrameHeaderBytes);
  std::vector<std::byte> payload(begin, begin + static_cast<std::ptrdiff_t>(n));
  pos_ += kFrameHeaderBytes + n;
  if (pos_ == buf_.size()) {
    buf_.clear();
    pos_ = 0;
  }
  return payload;
}

}  // namespace pl
