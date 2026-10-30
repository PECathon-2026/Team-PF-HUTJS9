// libFuzzer target (owner: LNX): bounded JSON parsing plus schema validation of
// the result against every contract, i.e. everything a hostile peer reaches in
// FramedSocket::recv_json. Must never crash, hang or throw out of validate().
#include <cstddef>
#include <cstdint>
#include <span>

#include "pl/contracts.hpp"
#include "pl/uds.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  static const auto reg = pl::contracts::Registry::load_dir(PL_CONTRACTS_DIR "/schemas");
  nlohmann::json message;
  try {
    message = pl::parse_json_bounded(std::as_bytes(std::span<const std::uint8_t>(data, size)));
  } catch (const pl::ProtocolError&) {
    return 0;  // malformed input is expected
  }
  (void)pl::validate_dispatch(reg, message);
  for (const auto& id : reg.ids()) {
    (void)reg.validate(id, message);
  }
  return 0;
}
