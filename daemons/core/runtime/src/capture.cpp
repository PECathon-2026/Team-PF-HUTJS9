// Capture model (owner: LNX). See capture.hpp.
#include "pl/core/capture.hpp"

#include <algorithm>
#include <cctype>
#include <span>

#include "pl/channel.hpp"

namespace pl::core {
namespace {

std::string lower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return s;
}

}  // namespace

CaptureModel::~CaptureModel() {
  for (auto& s : strings_) {
    secure_wipe(std::as_writable_bytes(std::span(s.data(), s.size())));
  }
}

CaptureModel CaptureModel::from_cdp(const nlohmann::json& snapshot, std::string host) {
  CaptureModel m;
  m.host_ = std::move(host);
  for (const auto& s : snapshot.at("strings")) {
    m.strings_.push_back(s.get<std::string>());
  }
  const auto& doc = snapshot.at("documents").at(0);
  const auto& n = doc.at("nodes");
  const auto& parent = n.at("parentIndex");
  const auto& name = n.at("nodeName");
  const std::size_t count = parent.size();
  auto get_or = [&](const char* key, std::size_t i, std::int64_t def) -> std::int64_t {
    return n.contains(key) && i < n[key].size() ? n[key][i].get<std::int64_t>() : def;
  };
  // Input values (rare string data) and layout bounds by node index.
  std::vector<std::int32_t> input(count, detect::kNone);
  if (n.contains("inputValue")) {
    const auto& iv = n["inputValue"];
    for (std::size_t k = 0; k < iv.at("index").size(); ++k) {
      const auto idx = iv["index"][k].get<std::size_t>();
      if (idx < count) {
        input[idx] = iv["value"][k].get<std::int32_t>();
      }
    }
  }
  std::vector<detect::Rect> bounds(count);
  std::vector<bool> laid_out(count, false);
  if (doc.contains("layout")) {
    const auto& lay = doc["layout"];
    for (std::size_t k = 0; k < lay.at("nodeIndex").size(); ++k) {
      const auto idx = lay["nodeIndex"][k].get<std::size_t>();
      const auto& b = lay["bounds"][k];
      if (idx < count && b.size() == 4) {
        bounds[idx] = {b[0].get<float>(), b[1].get<float>(), b[2].get<float>(), b[3].get<float>()};
        laid_out[idx] = true;
      }
    }
  }
  // Lower-case tag names appended to the string table.
  std::vector<std::uint32_t> tag_idx(count, 0);
  std::vector<std::string> tags(count);
  for (std::size_t i = 0; i < count; ++i) {
    const auto si = name[i].get<std::size_t>();
    tags[i] = lower(si < m.strings_.size() ? m.strings_[si] : "");
    tag_idx[i] = static_cast<std::uint32_t>(m.strings_.size());
    m.strings_.push_back(tags[i]);
  }
  // Nodes inside script/style carry no visible content: skip their text.
  std::vector<bool> hidden_text(count, false);
  for (std::size_t i = 0; i < count; ++i) {
    const auto p = parent[i].get<std::int64_t>();
    if (p >= 0 && static_cast<std::size_t>(p) < count) {
      const auto& pt = tags[static_cast<std::size_t>(p)];
      hidden_text[i] = pt == "script" || pt == "style" || pt == "noscript" || pt == "template" ||
                       hidden_text[static_cast<std::size_t>(p)];
    }
  }
  for (std::size_t i = 0; i < count; ++i) {
    detect::Node node;
    node.node_id = static_cast<std::uint32_t>(i);
    node.parent = static_cast<std::int32_t>(parent[i].get<std::int64_t>());
    node.tag = tag_idx[i];
    const auto begin = m.attrs_.size();
    if (n.contains("attributes") && i < n["attributes"].size()) {
      const auto& a = n["attributes"][i];
      for (std::size_t k = 0; k + 1 < a.size(); k += 2) {
        m.attrs_.push_back({a[k].get<std::uint32_t>(), a[k + 1].get<std::uint32_t>()});
      }
    }
    m.attr_ranges_.emplace_back(begin, m.attrs_.size());
    const auto type = get_or("nodeType", i, 1);
    const auto value = get_or("nodeValue", i, -1);
    if (type == 3 && value >= 0 && !hidden_text[i]) {
      node.text = static_cast<std::int32_t>(value);
    }
    node.input_text = input[i];
    node.bounds = bounds[i];
    std::uint32_t flags = 0;
    if (laid_out[i] && bounds[i].width > 0 && bounds[i].height > 0) {
      flags |= detect::kVisible;
    }
    const auto& t = tags[i];
    if (t == "input" || t == "textarea" || t == "select") {
      flags |= detect::kEditable | detect::kFocusable;
    }
    if (t == "a" || t == "button") {
      flags |= detect::kFocusable;
    }
    node.flags = flags;
    m.nodes_.push_back(node);
    m.backend_.push_back(get_or("backendNodeId", i, 0));
  }
  m.rebuild_views();
  // Password inputs, once attrs are reachable.
  for (auto& node : m.nodes_) {
    if (m.tag(node.node_id) == "input" && lower(std::string(m.attr(node.node_id, "type"))) == "password") {
      node.flags |= detect::kPasswordField;
    }
  }
  return m;
}

void CaptureModel::rebuild_views() {
  views_.assign(strings_.begin(), strings_.end());
  for (std::size_t i = 0; i < nodes_.size(); ++i) {
    const auto [b, e] = attr_ranges_[i];
    nodes_[i].attrs = std::span<const detect::AttrRef>(attrs_).subspan(b, e - b);
  }
}

detect::PageSnapshot CaptureModel::view(std::uint64_t snapshot_id, std::uint64_t session_id) const {
  detect::PageSnapshot p;
  p.snapshot_id = snapshot_id;
  p.session_id = session_id;
  p.url_host = host_;
  p.strings = views_;
  p.nodes = nodes_;
  p.full = true;
  return p;
}

std::int64_t CaptureModel::backend_id(std::uint32_t node_id) const {
  return node_id < backend_.size() ? backend_[node_id] : 0;
}

std::string_view CaptureModel::str(std::int32_t idx) const {
  return idx >= 0 && static_cast<std::size_t>(idx) < views_.size() ? views_[static_cast<std::size_t>(idx)] : std::string_view{};
}

std::string_view CaptureModel::attr(std::uint32_t node_id, std::string_view name) const {
  if (node_id >= nodes_.size()) {
    return {};
  }
  for (const auto& a : nodes_[node_id].attrs) {
    if (str(static_cast<std::int32_t>(a.name)) == name) {
      return str(static_cast<std::int32_t>(a.value));
    }
  }
  return {};
}

std::string_view CaptureModel::tag(std::uint32_t node_id) const {
  return node_id < nodes_.size() ? str(static_cast<std::int32_t>(nodes_[node_id].tag)) : std::string_view{};
}

}  // namespace pl::core
