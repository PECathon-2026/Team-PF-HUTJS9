// WIN's detect library (owner: WIN). Adopts LNX's interface unchanged (request
// L-001): the types and factories are those of pl/detect_api_proposal.hpp in the
// core shell's tree; this header adds WIN-side helpers.
#pragma once

#include "pl/detect_api_proposal.hpp"
#include "pl/taint.hpp"

namespace pl::detect {

// Taint label of one detection (spec §6): the lattice point for its category.
[[nodiscard]] TaintLabel taint_of(const Detection& d);

}  // namespace pl::detect
