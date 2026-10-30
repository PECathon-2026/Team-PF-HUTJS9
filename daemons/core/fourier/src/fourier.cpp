#include "pl/fourier/fourier.hpp"

namespace pl::detect {

std::optional<ScrollEstimate> phase_correlate(const ImageView& /*previous*/, const ImageView& /*current*/) {
  return std::nullopt;  // no estimate: callers fall back to a full rescan (fail safe)
}

}  // namespace pl::detect
