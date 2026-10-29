#include "pl/taint.hpp"

#include <algorithm>
#include <array>
#include <stdexcept>
#include <utility>

namespace pl {

namespace {

constexpr auto kCategoryCount = static_cast<std::size_t>(TaintCategory::count_);
static_assert(kCategoryCount <= 32, "categories are a 32-bit set");

constexpr std::array<std::string_view, 5> kLevels = {"public", "internal", "personal", "sensitive", "secret"};

struct CategoryInfo {
  std::string_view name;
  TaintLevel level;
};

constexpr std::array<CategoryInfo, kCategoryCount> kCategories = {{
    {"CARD", TaintLevel::sensitive},       {"AADHAAR", TaintLevel::sensitive}, {"PAN", TaintLevel::sensitive},
    {"API_KEY", TaintLevel::secret},       {"OTP", TaintLevel::secret},        {"PASSWORD", TaintLevel::secret},
    {"EMAIL", TaintLevel::personal},       {"PHONE", TaintLevel::personal},    {"IP_ADDRESS", TaintLevel::personal},
    {"PIN_CODE", TaintLevel::personal},    {"BANK_ACCOUNT", TaintLevel::sensitive}, {"IFSC", TaintLevel::personal},
    {"UPI_ID", TaintLevel::personal},      {"PASSPORT", TaintLevel::sensitive}, {"DOB", TaintLevel::personal},
    {"NAME", TaintLevel::personal},        {"ADDRESS", TaintLevel::personal},  {"FACE", TaintLevel::personal},
    {"SECRET", TaintLevel::secret},        {"QUASI_ID", TaintLevel::personal},
}};

constexpr std::uint32_t bit(TaintCategory c) noexcept { return 1U << static_cast<unsigned>(c); }

TaintLevel implied_level(std::uint32_t cats) noexcept {
  TaintLevel l = TaintLevel::public_;
  for (std::size_t k = 0; k < kCategoryCount; ++k) {
    if ((cats & (1U << k)) != 0) {
      l = std::max(l, kCategories.at(k).level);
    }
  }
  return l;
}

}  // namespace

std::string_view to_string(TaintLevel l) noexcept { return kLevels.at(static_cast<std::size_t>(l)); }
std::string_view to_string(TaintCategory c) noexcept { return kCategories.at(static_cast<std::size_t>(c)).name; }

std::optional<TaintLevel> taint_level_from(std::string_view s) noexcept {
  for (std::size_t k = 0; k < kLevels.size(); ++k) {
    if (kLevels.at(k) == s) {
      return static_cast<TaintLevel>(k);
    }
  }
  return std::nullopt;
}

std::optional<TaintCategory> taint_category_from(std::string_view s) noexcept {
  for (std::size_t k = 0; k < kCategoryCount; ++k) {
    if (kCategories.at(k).name == s) {
      return static_cast<TaintCategory>(k);
    }
  }
  return std::nullopt;
}

TaintLevel level_of(TaintCategory c) noexcept { return kCategories.at(static_cast<std::size_t>(c)).level; }

TaintLabel TaintLabel::of(TaintCategory c) noexcept { return {level_of(c), bit(c)}; }
TaintLabel TaintLabel::at(TaintLevel l) noexcept { return {l, 0}; }
TaintLabel TaintLabel::top() noexcept { return {TaintLevel::secret, (kCategoryCount == 32) ? ~0U : ((1U << kCategoryCount) - 1U)}; }

bool TaintLabel::has(TaintCategory c) const noexcept { return (cats_ & bit(c)) != 0; }

TaintLabel TaintLabel::join(const TaintLabel& o) const noexcept { return {std::max(level_, o.level_), cats_ | o.cats_}; }

TaintLabel TaintLabel::meet(const TaintLabel& o) const noexcept {
  // The intersection's categories may imply less than min(level); keep min(level), which is >= implied.
  return {std::min(level_, o.level_), cats_ & o.cats_};
}

bool TaintLabel::leq(const TaintLabel& o) const noexcept { return level_ <= o.level_ && (cats_ & ~o.cats_) == 0; }

nlohmann::json TaintLabel::to_json() const {
  nlohmann::json cats = nlohmann::json::array();
  for (std::size_t k = 0; k < kCategoryCount; ++k) {
    if ((cats_ & (1U << k)) != 0) {
      cats.push_back(kCategories.at(k).name);
    }
  }
  return {{"schema", "taint_label.v1"}, {"level", to_string(level_)}, {"categories", std::move(cats)}};
}

TaintLabel TaintLabel::from_json(const nlohmann::json& j) {
  if (!j.is_object() || j.value("schema", "") != "taint_label.v1") {
    throw std::invalid_argument("not a taint_label.v1");
  }
  const auto level = taint_level_from(j.at("level").get<std::string>());
  if (!level) {
    throw std::invalid_argument("unknown taint level");
  }
  std::uint32_t cats = 0;
  for (const auto& c : j.at("categories")) {
    const auto cat = taint_category_from(c.get<std::string>());
    if (!cat) {
      throw std::invalid_argument("unknown taint category");
    }
    cats |= bit(*cat);
  }
  if (*level < implied_level(cats)) {
    throw std::invalid_argument("taint level is below what its categories imply");
  }
  return {*level, cats};
}

}  // namespace pl
