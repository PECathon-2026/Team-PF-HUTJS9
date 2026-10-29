// Schema validation hook (owner: LNX). plcommon doesn't know the schemas; the
// contracts library implements MessageValidator, and IPC code calls it on every
// payload it receives (and, in debug/test builds, on every payload it sends).
#pragma once

#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

namespace pl {

struct ValidationResult {
  bool ok = false;
  std::vector<std::string> errors;  // JSON pointers + failing rule; never values

  static ValidationResult success() { return {true, {}}; }
  static ValidationResult failure(std::vector<std::string> errs) { return {false, std::move(errs)}; }
};

class MessageValidator {
 public:
  MessageValidator() = default;
  MessageValidator(const MessageValidator&) = default;
  MessageValidator& operator=(const MessageValidator&) = default;
  MessageValidator(MessageValidator&&) = default;
  MessageValidator& operator=(MessageValidator&&) = default;
  virtual ~MessageValidator() = default;
  [[nodiscard]] virtual ValidationResult validate(std::string_view schema_id, const nlohmann::json& message) const = 0;
};

// Validates against the schema named by the message's own "schema" field.
// Fails closed: a missing or non-string "schema" is an error.
[[nodiscard]] ValidationResult validate_dispatch(const MessageValidator& validator, const nlohmann::json& message);

}  // namespace pl
