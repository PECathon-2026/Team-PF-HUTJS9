// Capture model (owner: LNX): DOMSnapshot.captureSnapshot -> flat nodes over a
// string table (spec §3), exposed to WIN's detect as pl::detect::PageSnapshot.
// It holds raw page content (typed values included): it never leaves core and
// its strings are wiped when it is dropped.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "pl/detect_api_proposal.hpp"

namespace pl::core {

class CaptureModel {
 public:
  CaptureModel() = default;
  ~CaptureModel();
  CaptureModel(const CaptureModel&) = delete;
  CaptureModel& operator=(const CaptureModel&) = delete;
  CaptureModel(CaptureModel&&) noexcept = default;
  CaptureModel& operator=(CaptureModel&&) noexcept = default;

  // `snapshot` is the result of DOMSnapshot.captureSnapshot (first document used).
  static CaptureModel from_cdp(const nlohmann::json& snapshot, std::string host);

  [[nodiscard]] detect::PageSnapshot view(std::uint64_t snapshot_id, std::uint64_t session_id) const;
  [[nodiscard]] const std::vector<detect::Node>& nodes() const noexcept { return nodes_; }
  [[nodiscard]] std::int64_t backend_id(std::uint32_t node_id) const;
  [[nodiscard]] std::string_view str(std::int32_t idx) const;
  [[nodiscard]] std::string_view attr(std::uint32_t node_id, std::string_view name) const;
  [[nodiscard]] std::string_view tag(std::uint32_t node_id) const;
  [[nodiscard]] const std::string& host() const noexcept { return host_; }

 private:
  void rebuild_views();
  std::string host_;
  std::vector<std::string> strings_;
  std::vector<std::string_view> views_;
  std::vector<detect::AttrRef> attrs_;
  std::vector<std::pair<std::size_t, std::size_t>> attr_ranges_;  // per node: [begin, end) into attrs_
  std::vector<detect::Node> nodes_;
  std::vector<std::int64_t> backend_;
};

}  // namespace pl::core
