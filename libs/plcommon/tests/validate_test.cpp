#include "pl/validate.hpp"

#include <gtest/gtest.h>

namespace {

class Echo final : public pl::MessageValidator {
 public:
  mutable std::string last;
  [[nodiscard]] pl::ValidationResult validate(std::string_view id, const nlohmann::json& /*m*/) const override {
    last = id;
    return pl::ValidationResult::success();
  }
};

TEST(Validate, DispatchesOnSchemaField) {
  const Echo v;
  EXPECT_TRUE(pl::validate_dispatch(v, {{"schema", "event.v1"}}).ok);
  EXPECT_EQ(v.last, "event.v1");
}

TEST(Validate, FailsClosedWithoutSchema) {
  const Echo v;
  EXPECT_FALSE(pl::validate_dispatch(v, nlohmann::json::array()).ok);
  EXPECT_FALSE(pl::validate_dispatch(v, {{"x", 1}}).ok);
  EXPECT_FALSE(pl::validate_dispatch(v, {{"schema", 5}}).ok);
  EXPECT_TRUE(v.last.empty());
}

}  // namespace
