// C++ schema registry for contracts/schemas (owner: LNX).
// Implements plcommon's MessageValidator hook so framing/IPC code can validate
// every payload it sends or receives (SHARED.md §5).
#pragma once

#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

#include "pl/validate.hpp"

namespace pl::contracts {

class Registry final : public MessageValidator {
 public:
  Registry();
  ~Registry() override;
  Registry(const Registry&) = delete;
  Registry& operator=(const Registry&) = delete;
  Registry(Registry&&) noexcept;
  Registry& operator=(Registry&&) noexcept;

  // Loads every <name>.v<N>.json in `dir`. Throws std::runtime_error on a bad file.
  static Registry load_dir(const std::filesystem::path& dir);

  // Adds one schema under `schema_id` (e.g. "event.v1"). Throws on an invalid schema.
  void add(std::string schema_id, const nlohmann::json& schema);

  [[nodiscard]] bool has(std::string_view schema_id) const;
  [[nodiscard]] std::vector<std::string> ids() const;

  // Error descriptions are JSON pointers plus the failing rule, never instance values.
  [[nodiscard]] ValidationResult validate(std::string_view schema_id, const nlohmann::json& message) const override;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace pl::contracts
