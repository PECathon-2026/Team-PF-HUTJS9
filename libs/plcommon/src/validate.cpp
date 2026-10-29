#include "pl/validate.hpp"

namespace pl {

ValidationResult validate_dispatch(const MessageValidator& validator, const nlohmann::json& message) {
  if (!message.is_object()) {
    return ValidationResult::failure({"/: message must be an object"});
  }
  const auto it = message.find("schema");
  if (it == message.end() || !it->is_string()) {
    return ValidationResult::failure({"/schema: missing or not a string"});
  }
  return validator.validate(it->get_ref<const std::string&>(), message);
}

}  // namespace pl
