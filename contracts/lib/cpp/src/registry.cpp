#include "pl/contracts.hpp"

#include <algorithm>
#include <fstream>
#include <map>
#include <regex>
#include <stdexcept>

#include <nlohmann/json-schema.hpp>

namespace pl::contracts {

namespace {

using nlohmann::json;
using nlohmann::json_schema::json_validator;

// Matches the Python registry: only date-time and uuid are checked.
void format_check(const std::string& format, const std::string& value) {
  if (format == "date-time" || format == "uuid") {
    nlohmann::json_schema::default_string_format_check(format, value);
    return;
  }
  throw std::invalid_argument("unsupported format '" + format + "'");
}

// Collects errors without ever recording the offending instance value.
class Collector final : public nlohmann::json_schema::basic_error_handler {
 public:
  void error(const json::json_pointer& ptr, const json& /*instance*/, const std::string& message) override {
    basic_error_handler::error(ptr, json{}, message);
    // The validator's messages can quote instance data (values and attacker-chosen
    // keys), so keep only the JSON pointer of the failing location.
    (void)message;
    errors.push_back(ptr.to_string() + ": schema violation");
  }
  std::vector<std::string> errors;
};

// Schemas are checked against the draft-7 meta-schema (the engine's dialect),
// matching jsonschema's check_schema on the Python side.
const json_validator& meta_validator() {
  static const json_validator v = [] {
    // Like jsonschema's check_schema: meta-schema formats (uri-reference, regex) are annotations only.
    json_validator m(nullptr, [](const std::string& /*format*/, const std::string& /*value*/) {});
    m.set_root_schema(nlohmann::json_schema::draft7_schema_builtin);
    return m;
  }();
  return v;
}

const std::regex& schema_file_re() {
  static const std::regex re(R"(^([a-z][a-z0-9_]*)\.v([1-9][0-9]*)\.json$)");
  return re;
}

}  // namespace

struct Registry::Impl {
  std::map<std::string, json_validator, std::less<>> validators;
};

Registry::Registry() : impl_(std::make_unique<Impl>()) {}
Registry::~Registry() = default;
Registry::Registry(Registry&&) noexcept = default;
Registry& Registry::operator=(Registry&&) noexcept = default;

Registry Registry::load_dir(const std::filesystem::path& dir) {
  Registry reg;
  std::vector<std::filesystem::path> files;
  for (const auto& entry : std::filesystem::directory_iterator(dir)) {
    if (entry.is_regular_file() && entry.path().extension() == ".json") {
      files.push_back(entry.path());
    }
  }
  std::sort(files.begin(), files.end());
  for (const auto& path : files) {
    const std::string fname = path.filename().string();
    if (!std::regex_match(fname, schema_file_re())) {
      throw std::runtime_error(fname + ": schema file name must be <name>.v<N>.json");
    }
    std::ifstream in(path);
    if (!in) {
      throw std::runtime_error(fname + ": cannot open");
    }
    reg.add(fname.substr(0, fname.size() - 5), json::parse(in));
  }
  return reg;
}

void Registry::add(std::string schema_id, const json& schema) {
  json meta_view = schema;
  if (meta_view.is_object()) {
    meta_view.erase("$schema");
  }
  Collector meta_errors;
  meta_validator().validate(meta_view, meta_errors);
  if (!meta_errors.errors.empty()) {
    throw std::invalid_argument(schema_id + ": not a valid schema: " + meta_errors.errors.front());
  }
  json_validator v(nullptr, format_check);
  v.set_root_schema(schema);
  impl_->validators.insert_or_assign(std::move(schema_id), std::move(v));
}

bool Registry::has(std::string_view schema_id) const { return impl_->validators.find(schema_id) != impl_->validators.end(); }

std::vector<std::string> Registry::ids() const {
  std::vector<std::string> out;
  out.reserve(impl_->validators.size());
  for (const auto& [id, v] : impl_->validators) {
    out.push_back(id);
  }
  return out;
}

ValidationResult Registry::validate(std::string_view schema_id, const json& message) const {
  const auto it = impl_->validators.find(schema_id);
  if (it == impl_->validators.end()) {
    return ValidationResult::failure({"unknown schema '" + std::string(schema_id) + "'"});
  }
  Collector errors;
  try {
    it->second.validate(message, errors);
  } catch (const std::exception&) {
    // e.g. Boost.Regex giving up on a pathological input: fail closed.
    return ValidationResult::failure({"/: validator aborted"});
  }
  if (errors.errors.empty()) {
    return ValidationResult::success();
  }
  return ValidationResult::failure(std::move(errors.errors));
}

}  // namespace pl::contracts
