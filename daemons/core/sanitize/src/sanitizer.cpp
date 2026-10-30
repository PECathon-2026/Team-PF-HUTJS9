// sanitize v1 (spec §5): placeholders, solid field boxes, PNG re-encode, every
// hiding place scrubbed. Owner: WIN.
//
// - Each detected value goes to the vault via SanitizeContext::vault_store and
//   only the returned placeholder is kept (AD-12). If the vault call fails, the
//   text is still removed (fail closed) and the element is marked redacted.
// - Element names come from the accessible name or text with detected ranges
//   replaced by placeholders. Input values are never copied into the output.
// - URLs (href) lose their query and fragment entirely; detected path segments
//   become placeholders.
// - Boxes cover the element's box (the field, not the text) plus a margin, with
//   text boxes rounded up to fixed widths so length doesn't leak (spec §5).
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

#include <opencv2/core.hpp>
#include <opencv2/imgcodecs.hpp>
#include <opencv2/imgproc.hpp>

#include "pl/detect_api_proposal.hpp"
#include "pl/sanitize/sanitize.hpp"

namespace pl::detect {
namespace {

constexpr float kMargin = 4.0F;
constexpr float kWidthStep = 32.0F;
constexpr std::size_t kMaxName = 2000;

std::string category_name(TaintCategory c) {
  std::string s(to_string(c));
  std::transform(s.begin(), s.end(), s.begin(), [](char ch) {
    return (ch >= 'a' && ch <= 'z') ? static_cast<char>(ch - 'a' + 'A') : ch;
  });
  return s;
}

std::string role_for(std::string_view ax_role, std::string_view tag) {
  std::string r;
  for (char ch : ax_role) {
    if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')) r.push_back(ch);
    if (r.size() >= 32) break;
  }
  if (!r.empty()) {
    if (r[0] >= 'A' && r[0] <= 'Z') r[0] = static_cast<char>(r[0] - 'A' + 'a');
    return r;
  }
  if (tag == "input" || tag == "textarea") return "textbox";
  if (tag == "button") return "button";
  if (tag == "a") return "link";
  if (tag == "select") return "combobox";
  if (tag == "img") return "img";
  if (tag == "h1" || tag == "h2" || tag == "h3") return "heading";
  return "text";
}

// Cut a UTF-8 string to at most n bytes without splitting a code point.
std::string utf8_cut(std::string s, std::size_t n) {
  if (s.size() <= n) return s;
  std::size_t k = n;
  while (k > 0 && (static_cast<unsigned char>(s[k]) & 0xC0U) == 0x80U) --k;
  s.resize(k);
  return s;
}

struct Range {
  std::uint32_t begin, end;
  std::string placeholder;  // empty: the vault failed; redact without one
};

// Replace ranges (sorted, non-overlapping after merge) with placeholders.
std::string replace_ranges(std::string_view s, std::vector<Range> rs) {
  std::sort(rs.begin(), rs.end(), [](const Range& a, const Range& b) { return a.begin < b.begin; });
  std::string out;
  std::uint32_t pos = 0;
  for (const auto& r : rs) {
    if (r.begin < pos) continue;  // overlapping: already covered
    out.append(s.substr(pos, r.begin - pos));
    out.append(r.placeholder.empty() ? "[REDACTED]" : r.placeholder);
    pos = r.end;
  }
  if (pos < s.size()) out.append(s.substr(pos));
  return out;
}

std::vector<std::uint8_t> redact_png(const ImageView& img, const std::vector<Rect>& boxes) {
  if (img.width == 0 || img.height == 0 || img.rgba.empty()) return {};
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast): cv::Mat wraps read-only data, copied immediately.
  cv::Mat src(static_cast<int>(img.height), static_cast<int>(img.width), CV_8UC4,
              const_cast<std::byte*>(img.rgba.data()), img.stride);  // NOLINT(cppcoreguidelines-pro-type-const-cast)
  cv::Mat bgr;
  cv::cvtColor(src, bgr, cv::COLOR_RGBA2BGR);
  for (const Rect& r : boxes) {
    const int x0 = std::max(0, static_cast<int>(std::floor(r.x)));
    const int y0 = std::max(0, static_cast<int>(std::floor(r.y)));
    const int x1 = std::min(bgr.cols, static_cast<int>(std::ceil(r.x + r.width)));
    const int y1 = std::min(bgr.rows, static_cast<int>(std::ceil(r.y + r.height)));
    if (x1 > x0 && y1 > y0) {
      cv::rectangle(bgr, cv::Rect(x0, y0, x1 - x0, y1 - y0), cv::Scalar(0, 0, 0), cv::FILLED);
    }
  }
  std::vector<std::uint8_t> png;
  cv::imencode(".png", bgr, png);  // re-encoded from pixels: no source metadata survives
  return png;
}

class SanitizerV1 final : public Sanitizer {
 public:
  SanitizedPage sanitize(const PageSnapshot& page, const DetectionSet& found, SanitizeContext& ctx) override {
    auto str = [&](std::int32_t idx) -> std::string_view {
      if (idx < 0 || static_cast<std::size_t>(idx) >= page.strings.size()) return {};
      return page.strings[static_cast<std::size_t>(idx)];
    };
    // 1. Values to the vault, once per (string, range).
    std::map<std::tuple<std::uint32_t, std::int32_t, std::uint32_t, std::uint32_t>, std::string> placeholder_of;
    std::map<std::int32_t, std::vector<Range>> ranges_by_string;
    std::map<std::uint32_t, std::vector<std::string>> placeholders_by_node;
    std::map<std::uint32_t, TaintCategory> input_category;
    std::set<std::uint32_t> failed_nodes;
    nlohmann::json redactions = nlohmann::json::array();
    std::vector<Rect> boxes;
    for (const Detection& d : found.items) {
      const auto key = std::make_tuple(d.node_id, d.string_index, d.begin, d.end);
      auto it = placeholder_of.find(key);
      if (it == placeholder_of.end()) {
        std::string ph;
        const auto s = str(d.string_index);
        if (d.string_index != kNone && d.end <= s.size() && d.begin < d.end && ctx.vault_store) {
          try {
            ph = ctx.vault_store(d, s.substr(d.begin, d.end - d.begin));
          } catch (...) {
            ph.clear();  // fail closed: the text is still removed below
          }
        }
        it = placeholder_of.emplace(key, ph).first;
        if (ph.empty()) failed_nodes.insert(d.node_id);
        if (d.string_index != kNone) ranges_by_string[d.string_index].push_back({d.begin, d.end, ph});
        if (!ph.empty()) placeholders_by_node[d.node_id].push_back(ph);
        if (d.node_id < page.nodes.size() && d.string_index == page.nodes[d.node_id].input_text) {
          input_category[d.node_id] = d.category;
        }
      }
      // Field box (the element), padded; text boxes rounded up to a fixed width step.
      Rect b = d.region;
      if (d.node_id < page.nodes.size()) b = page.nodes[d.node_id].bounds;
      b.x -= kMargin;
      b.y -= kMargin;
      b.width = std::ceil((b.width + 2 * kMargin) / kWidthStep) * kWidthStep;
      b.height += 2 * kMargin;
      boxes.push_back(b);
      nlohmann::json r = {{"element_id", "n" + std::to_string(d.node_id)},
                          {"category", category_name(d.category)},
                          {"box", {b.x, b.y, b.width, b.height}}};
      if (!it->second.empty()) r["placeholder"] = it->second;
      redactions.push_back(std::move(r));
    }

    // 2. Elements the agent may see.
    nlohmann::json elements = nlohmann::json::array();
    for (const Node& n : page.nodes) {
      if ((n.flags & kVisible) == 0U) continue;
      const std::string tag(str(static_cast<std::int32_t>(n.tag)));
      const bool interactive = tag == "input" || tag == "button" || tag == "a" || tag == "select" ||
                               tag == "textarea" || tag == "option" || (n.flags & kFocusable) != 0U;
      const std::int32_t name_idx = n.ax_name != kNone && !str(n.ax_name).empty() ? n.ax_name : n.text;
      const auto raw_name = str(name_idx);
      if (!interactive && raw_name.empty()) continue;
      std::string name;
      auto rit = ranges_by_string.find(name_idx);
      name = rit == ranges_by_string.end() ? std::string(raw_name) : replace_ranges(raw_name, rit->second);
      if (failed_nodes.count(n.node_id) != 0U && rit != ranges_by_string.end()) {
        // A value we couldn't hand to the vault: never risk a partial name.
        bool any_failed = std::any_of(rit->second.begin(), rit->second.end(), [](const Range& r) { return r.placeholder.empty(); });
        if (any_failed) name = "[REDACTED]";
      }
      nlohmann::json e = {{"element_id", "n" + std::to_string(n.node_id)},
                          {"flags", n.flags},
                          {"placeholders", placeholders_by_node.count(n.node_id) != 0U ? nlohmann::json(placeholders_by_node[n.node_id]) : nlohmann::json::array()},
                          {"role", role_for(str(n.ax_role), tag)},
                          {"name", utf8_cut(name, kMaxName)},
                          {"bounds", {n.bounds.x, n.bounds.y, n.bounds.width, n.bounds.height}}};
      if (auto ic = input_category.find(n.node_id); ic != input_category.end()) {
        e["data_type"] = category_name(ic->second);
      }
      if (n.input_text != kNone) e["filled"] = !str(n.input_text).empty();
      for (const AttrRef& a : n.attrs) {
        if (str(static_cast<std::int32_t>(a.name)) == "href") {
          const auto idx = static_cast<std::int32_t>(a.value);
          std::string href(str(idx));
          if (auto hr = ranges_by_string.find(idx); hr != ranges_by_string.end()) href = replace_ranges(href, hr->second);
          if (auto q = href.find_first_of("?#"); q != std::string::npos) href.resize(q);  // drop query + fragment
          e["href"] = utf8_cut(href, 2048);
        }
      }
      elements.push_back(std::move(e));
    }

    SanitizedPage out;
    out.message = {{"schema", "sanitized_page.v1"},
                   {"snapshot_id", page.snapshot_id},
                   {"url", "https://" + std::string(page.url_host) + "/"},
                   {"elements", std::move(elements)},
                   {"redactions", std::move(redactions)}};
    const auto png = redact_png(page.screenshot, boxes);
    out.redacted_png.resize(png.size());
    std::transform(png.begin(), png.end(), out.redacted_png.begin(), [](std::uint8_t b) { return static_cast<std::byte>(b); });
    return out;
  }
};

}  // namespace

std::unique_ptr<Sanitizer> make_sanitizer(const EngineConfig& /*cfg*/) { return std::make_unique<SanitizerV1>(); }

}  // namespace pl::detect
