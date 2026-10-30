// Actuator validation (owner: LNX): the last check before core touches the page.
// Accepted actions: click, fill, select, navigate, scroll, done (WIN's agent_action
// draft). A fill carries either a placeholder (vault decrypt, binding-checked) or
// plain text; sensitive fields accept only their matching placeholder, and plain
// text must pass the PII scan.
#pragma once

#include <map>
#include <set>
#include <string>

#include <nlohmann/json.hpp>

#include "pl/core/capture.hpp"

namespace pl::core {

struct VaultRef {
  std::string handle;
  nlohmann::json binding;  // vault_api.v1 binding as stored
  std::string field_type;  // placeholder type, e.g. PASSWORD
};

struct ActionVerdict {
  bool ok = false;
  std::string rule;  // C-1xx on rejection
  std::uint32_t node = 0;
  const VaultRef* vault = nullptr;  // set for placeholder fills
};

// Field type a sensitive input demands, or "" if any placeholder/plain text is fine.
[[nodiscard]] std::string required_type(const CaptureModel& page, std::uint32_t node);

[[nodiscard]] ActionVerdict validate_action(const nlohmann::json& action, const CaptureModel& page,
                                            const std::map<std::string, VaultRef>& placeholders,
                                            const std::set<std::string>& allowed_hosts);

}  // namespace pl::core
