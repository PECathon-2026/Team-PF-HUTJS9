// detect v1 (spec §4): text clean-up, pattern + check-digit validation,
// structural detection, split-value re-joining by on-screen geometry. Owner: WIN.
#include <algorithm>
#include <array>
#include <cctype>
#include <cmath>
#include <ctime>
#include <initializer_list>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "pl/detect/detect.hpp"
#include "pl/detect/normalize.hpp"
#include "pl/detect/scanner.hpp"
#include "pl/detect_api_proposal.hpp"

namespace pl::detect {
namespace {

std::string lower(std::string_view s) {
  std::string out(s);
  std::transform(out.begin(), out.end(), out.begin(), [](char c) {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
  });
  return out;
}

bool contains_any(std::string_view hay, std::initializer_list<std::string_view> needles) {
  return std::any_of(needles.begin(), needles.end(), [&](std::string_view n) { return hay.find(n) != std::string_view::npos; });
}

// Attributes whose values are scanned (spec §5 "every hiding place").
bool scanned_attr(std::string_view name) {
  static constexpr std::array<std::string_view, 12> kNames{
      "aria-label", "aria-description", "title", "placeholder", "alt", "href",
      "src", "action", "value", "content", "data", "aria-valuetext"};
  return name.starts_with("data-") || std::find(kNames.begin(), kNames.end(), name) != kNames.end();
}

bool url_attr(std::string_view name) { return name == "href" || name == "src" || name == "action"; }

// Percent-decode a URL attribute for scanning; keeps a map back to source bytes.
struct Decoded {
  std::string text;
  std::vector<std::uint32_t> begin, end;
};
Decoded percent_decode(std::string_view s) {
  Decoded d;
  auto hex = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  for (std::size_t i = 0; i < s.size();) {
    if (s[i] == '%' && i + 2 < s.size() && hex(s[i + 1]) >= 0 && hex(s[i + 2]) >= 0) {
      d.text.push_back(static_cast<char>(hex(s[i + 1]) * 16 + hex(s[i + 2])));
      d.begin.push_back(static_cast<std::uint32_t>(i));
      d.end.push_back(static_cast<std::uint32_t>(i + 3));
      i += 3;
    } else {
      d.text.push_back(s[i] == '+' ? ' ' : s[i]);
      d.begin.push_back(static_cast<std::uint32_t>(i));
      d.end.push_back(static_cast<std::uint32_t>(i + 1));
      ++i;
    }
  }
  return d;
}

struct NodeContext {
  std::string label;  // lowercased accessible name + id/name/autocomplete/placeholder/aria-label
  std::string autocomplete;
  std::string type;
  std::string tag;
};

class DetectorV1 final : public Detector {
 public:
  DetectionSet detect(const PageSnapshot& page, const DetectContext& ctx) override {
    DetectionSet out;
    auto str = [&](std::int32_t idx) -> std::string_view {
      if (idx < 0 || static_cast<std::size_t>(idx) >= page.strings.size()) return {};
      return page.strings[static_cast<std::size_t>(idx)];
    };
    bool page_otp = ctx.otp_context;
    std::vector<NodeContext> nctx(page.nodes.size());
    for (std::size_t k = 0; k < page.nodes.size(); ++k) {
      const Node& n = page.nodes[k];
      NodeContext& c = nctx[k];
      c.tag = lower(str(static_cast<std::int32_t>(n.tag)));
      c.label = lower(str(n.ax_name));
      for (const AttrRef& a : n.attrs) {
        const auto name = lower(str(static_cast<std::int32_t>(a.name)));
        const auto val = lower(str(static_cast<std::int32_t>(a.value)));
        if (name == "autocomplete") c.autocomplete = val;
        if (name == "type") c.type = val;
        if (name == "id" || name == "name" || name == "placeholder" || name == "aria-label" || name == "autocomplete") {
          c.label += " " + val;
        }
      }
      if (c.autocomplete.find("one-time-code") != std::string::npos) page_otp = true;
    }

    for (std::size_t k = 0; k < page.nodes.size(); ++k) {
      if (ctx.deadline_ns != 0 && now_ns() > ctx.deadline_ns) {
        out.complete = false;
        break;
      }
      const Node& n = page.nodes[k];
      const NodeContext& c = nctx[k];
      ScanContext sc;
      sc.otp = (page_otp && contains_any(c.label, {"otp", "one-time", "code", "ओटीपी"})) ||
               c.autocomplete.find("one-time-code") != std::string::npos;
      sc.account_label = contains_any(c.label, {"account", "a/c", "acct", "खाता"});
      sc.pin_label = contains_any(c.label, {"pin code", "pincode", "postal", "zip", "पिन"}) ||
                     c.autocomplete.find("postal-code") != std::string::npos;

      // 1. structural: the whole input value is sensitive whatever it looks like.
      if (n.input_text != kNone && !str(n.input_text).empty()) {
        if (auto cat = structural(n, c)) {
          push(out, n, n.input_text, 0, static_cast<std::uint32_t>(str(n.input_text).size()), *cat, Source::structural,
               structural_rule(n, c), 0.97F);
          continue;  // whole value covered
        }
      }
      // 2. patterns in every channel of the node.
      scan_string(out, n, n.text, str(n.text), sc, false);
      scan_string(out, n, n.input_text, str(n.input_text), sc, false);
      scan_string(out, n, n.ax_name, str(n.ax_name), sc, false);
      for (const AttrRef& a : n.attrs) {
        const auto name = lower(str(static_cast<std::int32_t>(a.name)));
        if (scanned_attr(name)) {
          scan_string(out, n, static_cast<std::int32_t>(a.value), str(static_cast<std::int32_t>(a.value)), sc,
                      url_attr(name));
        }
      }
    }
    rejoin_split_values(page, out, str);
    return out;
  }

  void on_navigation(std::uint64_t /*session_id*/) override {}
  void on_session_end(std::uint64_t /*session_id*/) override {}

 private:
  Scanner scanner_;

  static std::uint64_t now_ns() {
    timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<std::uint64_t>(ts.tv_sec) * 1000000000ULL + static_cast<std::uint64_t>(ts.tv_nsec);
  }

  static std::optional<TaintCategory> structural(const Node& n, const NodeContext& c) {
    if ((n.flags & kPasswordField) != 0U || c.type == "password" || c.autocomplete.find("password") != std::string::npos) {
      return TaintCategory::password;
    }
    const auto& ac = c.autocomplete;
    if (ac.find("cc-number") != std::string::npos || ac.find("cc-csc") != std::string::npos ||
        ac.find("cc-exp") != std::string::npos) {
      return TaintCategory::card;
    }
    if (ac.find("one-time-code") != std::string::npos) return TaintCategory::otp;
    if (contains_any(c.label, {"cvv", "cvc", "security code", "सीवीवी"})) return TaintCategory::card;
    if (contains_any(c.label, {"otp", "one-time", "ओटीपी"})) return TaintCategory::otp;
    if (contains_any(c.label, {"password", "passcode", "पासवर्ड"})) return TaintCategory::password;
    return std::nullopt;
  }

  static std::uint32_t structural_rule(const Node& n, const NodeContext& c) {
    if ((n.flags & kPasswordField) != 0U || c.type == "password") return kRulePassword;
    if (!c.autocomplete.empty()) return kRuleAutocomplete;
    return kRuleLabel;
  }

  static void push(DetectionSet& out, const Node& n, std::int32_t sidx, std::uint32_t b, std::uint32_t e,
                   TaintCategory cat, Source src, std::uint32_t rule, float score) {
    Detection d;
    d.node_id = n.node_id;
    d.string_index = sidx;
    d.begin = b;
    d.end = e;
    d.region = n.bounds;
    d.category = cat;
    d.score = score;
    d.source = src;
    d.rule = rule;
    out.items.push_back(d);
  }

  void scan_string(DetectionSet& out, const Node& n, std::int32_t sidx, std::string_view s, const ScanContext& sc,
                   bool is_url) const {
    if (sidx == kNone || s.empty()) return;
    if (is_url) {
      const Decoded dec = percent_decode(s);
      const Normalized norm = normalize(dec.text);
      for (const Hit& h : scanner_.scan(norm.text, sc)) {
        const std::uint32_t db = norm.source_begin(h.begin);
        const std::uint32_t de = norm.source_end(h.end);
        push(out, n, sidx, dec.begin[db], dec.end[de - 1], h.category, h.checksum ? Source::checksum : Source::pattern,
             h.rule, h.checksum ? 0.99F : 0.9F);
      }
      return;
    }
    const Normalized norm = normalize(s);
    for (const Hit& h : scanner_.scan(norm.text, sc)) {
      push(out, n, sidx, norm.source_begin(h.begin), norm.source_end(h.end), h.category,
           h.checksum ? Source::checksum : Source::pattern, h.rule, h.checksum ? 0.99F : 0.9F);
    }
  }

  // Values split over several elements that sit side by side on screen
  // (e.g. <span>4111</span><span>1111</span>...): join neighbouring short text
  // nodes on the same line and scan the joined string; report one Detection per
  // participating node, each covering its own bytes.
  template <typename Str>
  void rejoin_split_values(const PageSnapshot& page, DetectionSet& out, Str str) const {
    struct Piece {
      const Node* node;
      Normalized norm;
    };
    std::vector<Piece> pieces;
    for (const Node& n : page.nodes) {
      const auto t = str(n.text);
      if ((n.flags & kVisible) == 0U || t.empty() || t.size() > 40 || n.bounds.width <= 0 || n.bounds.height <= 0) {
        continue;
      }
      Normalized norm = normalize(t);
      if (std::none_of(norm.text.begin(), norm.text.end(), [](char ch) { return std::isalnum(static_cast<unsigned char>(ch)) != 0; })) {
        continue;
      }
      pieces.push_back({&n, std::move(norm)});
    }
    std::sort(pieces.begin(), pieces.end(), [](const Piece& a, const Piece& b) {
      const float ya = a.node->bounds.y + a.node->bounds.height / 2, yb = b.node->bounds.y + b.node->bounds.height / 2;
      if (std::fabs(ya - yb) > 0.5F * std::max(a.node->bounds.height, b.node->bounds.height)) return ya < yb;
      return a.node->bounds.x < b.node->bounds.x;
    });
    std::size_t i = 0;
    while (i < pieces.size()) {
      std::size_t j = i + 1;
      while (j < pieces.size()) {
        const Rect& p = pieces[j - 1].node->bounds;
        const Rect& q = pieces[j].node->bounds;
        const float h = std::max(p.height, q.height);
        const bool same_line = std::fabs((p.y + p.height / 2) - (q.y + q.height / 2)) <= 0.5F * h;
        const float gap = q.x - (p.x + p.width);
        if (!same_line || gap > 0.8F * h || gap < -0.5F * h) break;
        ++j;
      }
      if (j - i >= 2) {
        // Joined string with a map: joined byte -> (piece, normalised byte).
        std::string joined;
        std::vector<std::pair<std::size_t, std::size_t>> where;
        for (std::size_t k = i; k < j; ++k) {
          for (std::size_t b = 0; b < pieces[k].norm.text.size(); ++b) {
            joined.push_back(pieces[k].norm.text[b]);
            where.emplace_back(k, b);
          }
        }
        for (const Hit& h : scanner_.scan(joined, ScanContext{})) {
          const std::size_t first = where[h.begin].first, last = where[h.end - 1].first;
          if (first == last) continue;  // single node: already found by the per-node scan
          for (std::size_t k = first; k <= last; ++k) {
            const Piece& pc = pieces[k];
            const std::size_t nb = k == first ? where[h.begin].second : 0;
            const std::size_t ne = k == last ? where[h.end - 1].second + 1 : pc.norm.text.size();
            push(out, *pc.node, pc.node->text, pc.norm.source_begin(nb), pc.norm.source_end(ne), h.category,
                 h.checksum ? Source::checksum : Source::pattern, h.rule, h.checksum ? 0.99F : 0.9F);
          }
        }
      }
      i = j;
    }
  }
};

}  // namespace

std::unique_ptr<Detector> make_detector(const EngineConfig& /*cfg*/) { return std::make_unique<DetectorV1>(); }

TaintLabel taint_of(const Detection& d) { return TaintLabel::of(d.category); }

}  // namespace pl::detect
