// libFuzzer target: the frame decoder plus bounded JSON parsing of each payload,
// i.e. everything a hostile peer controls on an IPC socket.
#include <cstddef>
#include <cstdint>
#include <span>

#include "pl/frame.hpp"
#include "pl/uds.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const auto bytes = std::as_bytes(std::span<const std::uint8_t>(data, size));
  // Small max frame so length checks are exercised; feed in uneven chunks.
  pl::FrameDecoder d(4096);
  std::size_t off = 0;
  std::size_t step = 1;
  while (off < bytes.size()) {
    const std::size_t n = std::min(step, bytes.size() - off);
    d.feed(bytes.subspan(off, n));
    off += n;
    step = (step * 3) % 61 + 1;
    while (auto payload = d.next()) {
      if (payload->empty() || payload->size() > 4096) {
        __builtin_trap();  // decoder invariant broken
      }
      try {
        (void)pl::parse_json_bounded(*payload);
      } catch (const pl::ProtocolError&) {
        // expected for malformed input
      }
    }
  }
  return 0;
}
