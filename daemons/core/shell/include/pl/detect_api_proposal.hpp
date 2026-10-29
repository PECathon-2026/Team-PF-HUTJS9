// PROPOSAL (owner: LNX) for the C++ boundary between the core shell and WIN's
// detect/sanitize/fourier libraries. LNX can't write inside daemons/core/detect/,
// so this lives in the shell's tree; request L-001 asks WIN to adopt or amend it
// in WIN's own headers. Until then the shell uses NullDetector/NullSanitizer
// (null_detector.hpp), which fail closed.
//
// Rules this interface encodes:
//  - Detection sees the in-memory capture model by reference (spec §3); nothing
//    is copied out of core, nothing is written to disk.
//  - Detected values leave core immediately (AD-12): the sanitizer calls
//    SanitizeContext::vault_store for each value, gets back a placeholder, and
//    must not keep the value. Placeholders look like [REDACTED:CARD#3].
//  - Detections refer to text by (node, string index, byte range), never by
//    copying the value; scores and kinds are metadata only (spec §11).
//  - All calls are synchronous, single-threaded per session, and must respect
//    DetectContext::deadline_ns (return what is found so far; the shell then
//    fails closed for anything unscanned).
#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

#include "pl/taint.hpp"

namespace pl::detect {

inline constexpr std::int32_t kNone = -1;

// ---- capture model view (what core hands to detect) ---------------------------

struct Rect {
  float x = 0, y = 0, width = 0, height = 0;  // CSS px, viewport coordinates
};

enum NodeFlags : std::uint32_t {  // NOLINT(performance-enum-size): matches Node::flags, room for more bits
  kVisible = 1U << 0U,
  kFocusable = 1U << 1U,
  kPasswordField = 1U << 2U,
  kInIframe = 1U << 3U,
  kEditable = 1U << 4U,
};

struct AttrRef {
  std::uint32_t name;   // index into PageSnapshot::strings
  std::uint32_t value;  // index into PageSnapshot::strings
};

// One DOM node, flattened (page_snapshot.v1 "nodes").
struct Node {
  std::uint32_t node_id = 0;
  std::int32_t parent = kNone;
  std::uint32_t tag = 0;              // string index, lowercase tag name
  std::span<const AttrRef> attrs;     // autocomplete, type, name, id, aria-*, placeholder ...
  std::int32_t text = kNone;          // string index of the node's own text
  std::int32_t input_text = kNone;    // string index of the live input value (what the user typed)
  Rect bounds;
  std::int32_t ax_role = kNone;       // accessibility role (string index)
  std::int32_t ax_name = kNone;       // accessible name (string index)
  std::uint32_t flags = 0;            // NodeFlags
};

struct ImageView {
  std::span<const std::byte> rgba;  // 8-bit RGBA, row-major
  std::uint32_t width = 0, height = 0, stride = 0;
};

// Read-only view of one captured frame. Valid only for the duration of the call.
struct PageSnapshot {
  std::uint64_t snapshot_id = 0;
  std::uint64_t session_id = 0;
  std::string_view url_host;
  std::span<const std::string_view> strings;  // string table
  std::span<const Node> nodes;                // nodes[k].node_id == k
  ImageView screenshot;                       // for OCR and faces
  // Incremental processing (spec §3): nodes and 64x64 tiles changed since the
  // previous snapshot of this session. Empty spans + full == true: rescan all.
  bool full = true;
  std::span<const std::uint32_t> dirty_nodes;
  std::span<const std::uint32_t> dirty_tiles;  // tile index = (y / 64) * tiles_x + (x / 64)
};

struct DetectContext {
  std::uint64_t session_id = 0;
  std::uint64_t deadline_ns = 0;  // CLOCK_MONOTONIC; 0 = no deadline
  bool otp_context = false;       // page signals an OTP field (autocomplete=one-time-code)
};

// ---- detect output -------------------------------------------------------------

enum class Source : std::uint8_t { pattern, checksum, structural, model, ocr, face, entropy, site_memory, fallback };

struct Detection {
  std::uint32_t node_id = 0;
  std::int32_t string_index = kNone;  // which string (text, input_text, attribute value); kNone for image-only
  std::uint32_t begin = 0, end = 0;   // byte range within that string
  Rect region;                        // screen region to redact (text box, OCR box or face)
  TaintCategory category = TaintCategory::secret;
  float score = 0;                    // calibrated, 0..1
  Source source = Source::fallback;
  std::uint32_t rule = 0;             // WIN's rule number, for decision records
};

struct DetectionSet {
  std::vector<Detection> items;
  bool complete = true;  // false if the deadline cut scanning short
};

class Detector {
 public:
  Detector() = default;
  Detector(const Detector&) = delete;
  Detector& operator=(const Detector&) = delete;
  Detector(Detector&&) = delete;
  Detector& operator=(Detector&&) = delete;
  virtual ~Detector() = default;

  [[nodiscard]] virtual DetectionSet detect(const PageSnapshot& page, const DetectContext& ctx) = 0;
  // Incremental hooks.
  virtual void on_navigation(std::uint64_t session_id) = 0;  // drop per-page state
  virtual void on_session_end(std::uint64_t session_id) = 0;  // drop all session state
};

// ---- sanitize ------------------------------------------------------------------

struct SanitizeContext {
  std::uint64_t session_id = 0;
  // Hands one detected value to the vault (AD-12) bound to (session, field type,
  // site, element) and returns its placeholder. The core shell implements it over
  // the encrypted core->vault channel. The callee may throw; sanitize must then
  // fail closed (redact without a placeholder).
  std::function<std::string(const Detection& d, std::string_view value)> vault_store;
};

struct SanitizedPage {
  nlohmann::json message;               // WIN's sanitized_page.vN, validated by the shell before it leaves core
  std::vector<std::byte> redacted_png;  // solid-fill redacted screenshot (spec §5)
};

class Sanitizer {
 public:
  Sanitizer() = default;
  Sanitizer(const Sanitizer&) = delete;
  Sanitizer& operator=(const Sanitizer&) = delete;
  Sanitizer(Sanitizer&&) = delete;
  Sanitizer& operator=(Sanitizer&&) = delete;
  virtual ~Sanitizer() = default;

  [[nodiscard]] virtual SanitizedPage sanitize(const PageSnapshot& page, const DetectionSet& found, SanitizeContext& ctx) = 0;
};

// ---- Fourier (WIN's daemons/core/fourier) -------------------------------------------

struct ScrollEstimate {
  float dx = 0, dy = 0;  // CSS px, positive = content moved up/left
  float peak = 0;        // phase-correlation peak height, 0..1; < 0.3 means unreliable
};

// ---- factories WIN provides (link targets pl::detect, pl::sanitize, pl::fourier) -----

struct EngineConfig {
  std::string artifacts_dir;  // models/thresholds from make fetch-artifacts (attested)
  std::string policy_path;    // signed policy.yaml
};

// Implemented by WIN. The core shell calls these when PL_HAVE_WIN_DETECT is defined.
[[nodiscard]] std::unique_ptr<Detector> make_detector(const EngineConfig& cfg);
[[nodiscard]] std::unique_ptr<Sanitizer> make_sanitizer(const EngineConfig& cfg);
[[nodiscard]] std::optional<ScrollEstimate> phase_correlate(const ImageView& previous, const ImageView& current);

}  // namespace pl::detect
