#include "pl/null_detector.hpp"

#include <string>
#include <unordered_map>

namespace pl::detect {

namespace {

void flag_string(DetectionSet& out, const PageSnapshot& page, const Node& n, std::int32_t idx) {
  if (idx < 0 || static_cast<std::size_t>(idx) >= page.strings.size()) {
    return;
  }
  const auto len = page.strings[static_cast<std::size_t>(idx)].size();
  if (len == 0) {
    return;
  }
  out.items.push_back(Detection{
      .node_id = n.node_id,
      .string_index = idx,
      .begin = 0,
      .end = static_cast<std::uint32_t>(len),
      .region = n.bounds,
      .category = TaintCategory::secret,
      .score = 1.0F,
      .source = Source::fallback,
      .rule = 0,
  });
}

// [REDACTED:<TYPE>#<n>] with TYPE = [A-Z][A-Z0-9_]{1,23}, n = 1-6 digits (contracts/README.md).
bool is_placeholder(std::string_view p) noexcept {
  constexpr std::string_view kPrefix = "[REDACTED:";
  if (!p.starts_with(kPrefix) || !p.ends_with("]")) {
    return false;
  }
  const auto body = p.substr(kPrefix.size(), p.size() - kPrefix.size() - 1);
  const auto hash = body.find('#');
  if (hash == std::string_view::npos || hash < 2 || hash > 24 || body.size() - hash - 1 < 1 || body.size() - hash - 1 > 6) {
    return false;
  }
  for (std::size_t k = 0; k < body.size(); ++k) {
    const char c = body[k];
    const bool upper = c >= 'A' && c <= 'Z';
    const bool digit = c >= '0' && c <= '9';
    bool ok = false;
    if (k == 0) {
      ok = upper;
    } else if (k < hash) {
      ok = upper || digit || c == '_';
    } else {
      ok = k == hash || digit;
    }
    if (!ok) {
      return false;
    }
  }
  return true;
}

}  // namespace

DetectionSet NullDetector::detect(const PageSnapshot& page, const DetectContext& /*ctx*/) {
  DetectionSet out;
  for (const auto& n : page.nodes) {
    flag_string(out, page, n, n.text);
    flag_string(out, page, n, n.input_text);
    flag_string(out, page, n, n.ax_name);
    for (const auto& a : n.attrs) {
      flag_string(out, page, n, static_cast<std::int32_t>(a.value));
    }
  }
  return out;
}

SanitizedPage NullSanitizer::sanitize(const PageSnapshot& page, const DetectionSet& found, SanitizeContext& ctx) {
  nlohmann::json elements = nlohmann::json::array();
  std::unordered_map<std::uint32_t, std::size_t> index_of;  // node ids need not be dense
  for (const auto& n : page.nodes) {
    index_of.emplace(n.node_id, elements.size());
    elements.push_back({{"element_id", "n" + std::to_string(n.node_id)}, {"flags", n.flags}, {"placeholders", nlohmann::json::array()}});
  }
  for (const auto& d : found.items) {
    std::string placeholder = "[REDACTED:SECRET#0]";
    if (ctx.vault_store && d.string_index >= 0 && static_cast<std::size_t>(d.string_index) < page.strings.size()) {
      const auto s = page.strings[static_cast<std::size_t>(d.string_index)];
      try {
        std::string got = ctx.vault_store(d, s.substr(d.begin, d.end - d.begin));
        if (is_placeholder(got)) {
          placeholder = std::move(got);
        }
      } catch (...) {  // NOLINT(bugprone-empty-catch): fail closed with the bare placeholder
      }
    }
    if (const auto it = index_of.find(d.node_id); it != index_of.end()) {
      elements[it->second]["placeholders"].push_back(placeholder);
    }
  }
  // No screenshot is passed on: without real detection nothing on screen is known to be safe.
  return {{{"schema", "sanitized_page.v1"}, {"fallback", "null_detector"}, {"elements", std::move(elements)}}, {}};
}

#ifndef PL_HAVE_WIN_DETECT
std::unique_ptr<Detector> default_detector(const EngineConfig& /*cfg*/) { return std::make_unique<NullDetector>(); }
std::unique_ptr<Sanitizer> default_sanitizer(const EngineConfig& /*cfg*/) { return std::make_unique<NullSanitizer>(); }
bool using_null_detector() noexcept { return true; }
#else
std::unique_ptr<Detector> default_detector(const EngineConfig& cfg) { return make_detector(cfg); }
std::unique_ptr<Sanitizer> default_sanitizer(const EngineConfig& cfg) { return make_sanitizer(cfg); }
bool using_null_detector() noexcept { return false; }
#endif

}  // namespace pl::detect
