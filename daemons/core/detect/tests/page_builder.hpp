// Test helper: build a PageSnapshot (LNX's capture model view) from plain data.
#pragma once

#include <cstdint>
#include <deque>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "pl/detect_api_proposal.hpp"

namespace pl::detect::test {

class PageBuilder {
 public:
  struct Spec {
    std::string tag = "span";
    std::string text;
    std::string input;  // live input value
    std::string ax_name;
    std::string ax_role;
    std::vector<std::pair<std::string, std::string>> attrs;
    Rect bounds{0, 0, 100, 20};
    std::uint32_t flags = kVisible;
  };

  std::uint32_t add(const Spec& s) {
    Node n;
    n.node_id = static_cast<std::uint32_t>(nodes_.size());
    n.tag = intern(s.tag);
    n.text = s.text.empty() ? kNone : static_cast<std::int32_t>(intern(s.text));
    n.input_text = s.input.empty() ? kNone : static_cast<std::int32_t>(intern(s.input));
    n.ax_name = s.ax_name.empty() ? kNone : static_cast<std::int32_t>(intern(s.ax_name));
    n.ax_role = s.ax_role.empty() ? kNone : static_cast<std::int32_t>(intern(s.ax_role));
    auto& a = attr_store_.emplace_back();
    for (const auto& [k, v] : s.attrs) a.push_back({intern(k), intern(v)});
    n.bounds = s.bounds;
    n.flags = s.flags;
    nodes_.push_back(n);
    return n.node_id;
  }

  PageSnapshot build() {
    for (std::size_t i = 0; i < nodes_.size(); ++i) nodes_[i].attrs = attr_store_[i];
    views_.assign(strings_.begin(), strings_.end());
    PageSnapshot p;
    p.snapshot_id = 7;
    p.session_id = 1;
    p.url_host = "shop.example";
    p.strings = views_;
    p.nodes = nodes_;
    return p;
  }

  [[nodiscard]] std::string_view str(std::int32_t idx) const { return strings_[static_cast<std::size_t>(idx)]; }

 private:
  std::uint32_t intern(const std::string& s) {
    strings_.push_back(s);
    return static_cast<std::uint32_t>(strings_.size() - 1);
  }
  std::deque<std::string> strings_;  // deque: stable addresses for string_views
  std::vector<std::string_view> views_;
  std::vector<Node> nodes_;
  std::deque<std::vector<AttrRef>> attr_store_;
};

}  // namespace pl::detect::test
