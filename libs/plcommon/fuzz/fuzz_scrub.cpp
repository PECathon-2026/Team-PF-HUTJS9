// libFuzzer target: the log scrubber runs on attacker-influenced text (page
// content can reach log fields). It must never crash and never emit a run of
// 6 or more consecutive ASCII digits.
#include <cstddef>
#include <cstdint>
#include <string_view>

#include "pl/scrub.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const std::string_view in(reinterpret_cast<const char*>(data), size);
  const std::string out = pl::scrub(in);
  int run = 0;
  for (const char c : out) {
    run = (c >= '0' && c <= '9') ? run + 1 : 0;
    if (run >= 6) {
      __builtin_trap();
    }
  }
  return 0;
}
