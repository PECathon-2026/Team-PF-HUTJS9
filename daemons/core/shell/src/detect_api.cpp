// Compile check for the proposal header (owner: LNX). Kept separate so the
// header is built even when nothing else includes it yet.
#include "pl/detect_api_proposal.hpp"

static_assert(sizeof(pl::detect::Detection) <= 64, "Detection stays small: it's created per match");
