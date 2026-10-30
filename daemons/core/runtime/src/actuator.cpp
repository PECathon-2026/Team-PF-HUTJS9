// Actuator validation (owner: LNX). See actuator.hpp.
#include "pl/core/actuator.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <regex>

#include "pl/gate/scanner.hpp"

namespace pl::core {
namespace {

std::optional<std::uint32_t> parse_target(const nlohmann::json& a, const CaptureModel& page) {
  if (!a.contains("target") || !a["target"].is_string()) {
    return std::nullopt;
  }
  const auto& t = a["target"].get_ref<const std::string&>();
  if (t.size() < 2 || t.size() > 10 || t[0] != 'n') {
    return std::nullopt;
  }
  std::uint32_t id = 0;
  const auto [p, ec] = std::from_chars(t.data() + 1, t.data() + t.size(), id);
  if (ec != std::errc{} || p != t.data() + t.size() || id >= page.nodes().size()) {
    return std::nullopt;
  }
  return id;
}

bool is_placeholder(const std::string& s) {
  static const std::regex re(R"(^\[REDACTED:[A-Z][A-Z0-9_]{1,23}#[0-9]{1,6}\]$)");
  return s.size() <= 40 && std::regex_match(s, re);
}

std::string lower(std::string_view s) {
  std::string o(s);
  std::transform(o.begin(), o.end(), o.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return o;
}

}  // namespace

std::string required_type(const CaptureModel& page, std::uint32_t node) {
  if ((page.nodes().at(node).flags & detect::kPasswordField) != 0U) {
    return "PASSWORD";
  }
  const auto ac = lower(page.attr(node, "autocomplete"));
  if (ac.starts_with("cc-number") || ac == "cc-csc") {
    return "CARD";
  }
  if (ac == "one-time-code") {
    return "OTP";
  }
  return "";
}

ActionVerdict validate_action(const nlohmann::json& a, const CaptureModel& page,
                              const std::map<std::string, VaultRef>& placeholders,
                              const std::set<std::string>& allowed_hosts) {
  ActionVerdict v;
  if (!a.is_object() || !a.contains("kind") || !a["kind"].is_string()) {
    v.rule = "C-101";
    return v;
  }
  const auto kind = a["kind"].get<std::string>();
  if (kind == "done") {
    v.ok = true;
    return v;
  }
  if (kind == "scroll") {
    v.ok = a.value("direction", "") == "up" || a.value("direction", "") == "down";
    v.rule = v.ok ? "" : "C-101";
    return v;
  }
  if (kind == "navigate") {
    const auto url = a.value("url", "");
    static const std::regex re(R"(^https?://([a-z0-9.-]{1,253})(:[0-9]{1,5})?(/[^\s]*)?$)");
    std::smatch m;
    if (url.size() > 2048 || !std::regex_match(url, m, re) || !allowed_hosts.contains(m[1].str())) {
      v.rule = "C-107";
      return v;
    }
    v.ok = true;
    return v;
  }
  if (kind != "click" && kind != "fill" && kind != "select") {
    v.rule = "C-101";
    return v;
  }
  const auto target = parse_target(a, page);
  if (!target) {
    v.rule = "C-102";
    return v;
  }
  v.node = *target;
  const auto& node = page.nodes().at(*target);
  if (kind == "click") {
    v.ok = true;
    return v;
  }
  if ((node.flags & detect::kEditable) == 0U) {
    v.rule = "C-103";
    return v;
  }
  if (kind == "select") {
    v.ok = a.contains("option") && a["option"].is_string() && a["option"].get_ref<const std::string&>().size() <= 200;
    v.rule = v.ok ? "" : "C-101";
    return v;
  }
  // fill
  const auto need = required_type(page, *target);
  if (a.contains("placeholder")) {
    const auto& p = a["placeholder"];
    if (!p.is_string() || !is_placeholder(p.get<std::string>())) {
      v.rule = "C-101";
      return v;
    }
    const auto it = placeholders.find(p.get<std::string>());
    if (it == placeholders.end()) {
      v.rule = "C-104";
      return v;
    }
    if (!need.empty() && it->second.field_type != need) {
      v.rule = "C-108";
      return v;
    }
    v.vault = &it->second;
    v.ok = true;
    return v;
  }
  if (a.contains("text") && a["text"].is_string()) {
    const auto& text = a["text"].get_ref<const std::string&>();
    if (!need.empty()) {
      v.rule = "C-105";  // sensitive fields take only their placeholder
      return v;
    }
    if (text.size() > 500 || !pl::gate::scan(text, {}).empty()) {
      v.rule = "C-106";
      return v;
    }
    v.ok = true;
    return v;
  }
  v.rule = "C-101";
  return v;
}

}  // namespace pl::core
