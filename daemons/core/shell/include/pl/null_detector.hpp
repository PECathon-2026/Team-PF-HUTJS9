// Fail-closed fallback used until WIN's libraries are linked (owner: LNX).
//
// NullDetector reports every non-empty text, input value and attribute value of
// every node as a SECRET detection covering the whole string, so nothing on the
// page can reach the agent unredacted. NullSanitizer replaces each with a
// placeholder from SanitizeContext::vault_store (or a bare [REDACTED:SECRET#0]
// if the vault call fails) and keeps only structure: element IDs and roles.
#pragma once

#include "pl/detect_api_proposal.hpp"

namespace pl::detect {

class NullDetector final : public Detector {
 public:
  [[nodiscard]] DetectionSet detect(const PageSnapshot& page, const DetectContext& ctx) override;
  void on_navigation(std::uint64_t /*session_id*/) override {}
  void on_session_end(std::uint64_t /*session_id*/) override {}
};

class NullSanitizer final : public Sanitizer {
 public:
  [[nodiscard]] SanitizedPage sanitize(const PageSnapshot& page, const DetectionSet& found, SanitizeContext& ctx) override;
};

// The detector/sanitizer the shell uses: WIN's when linked, else the Null ones.
[[nodiscard]] std::unique_ptr<Detector> default_detector(const EngineConfig& cfg);
[[nodiscard]] std::unique_ptr<Sanitizer> default_sanitizer(const EngineConfig& cfg);
[[nodiscard]] bool using_null_detector() noexcept;

}  // namespace pl::detect
