// Fuzz the gate's untrusted-input parsers: scanner and HTTP head parser (owner: LNX).
#include <cstddef>
#include <cstdint>
#include <string_view>

#include "pl/gate/http.hpp"
#include "pl/gate/scanner.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const std::string_view s(reinterpret_cast<const char*>(data), size);
  static const pl::gate::CanaryRegistry reg = [] {
    pl::gate::CanaryRegistry r;
    r.add("ZEPHYR-PLANT-0042");
    return r;
  }();
  (void)pl::gate::scan(s, reg);
  (void)pl::gate::parse_request_head(s);
  (void)pl::gate::split_host_port(s, 80);
  return 0;
}
