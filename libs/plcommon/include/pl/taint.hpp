// Taint lattice (owner: LNX, spec §6 "Taint tracking as a security lattice").
//
// A label is (level, categories): a chain of levels
//   public < internal < personal < sensitive < secret
// times the powerset of data categories. join = (max level, union), meet =
// (min level, intersection), leq = (level <=, subset). Joining is how combined
// data takes the most secret colour of its ingredients (Denning). Only the
// bottom element (public, no categories) may leave through the gate.
// Wire form: taint_label.v1. Python twin: plpy.taint.
#pragma once

#include <cstdint>
#include <optional>
#include <string_view>

#include <nlohmann/json.hpp>

namespace pl {

enum class TaintLevel : std::uint8_t { public_ = 0, internal = 1, personal = 2, sensitive = 3, secret = 4 };

// Data categories. The names (to_string) are also the placeholder types: [REDACTED:CARD#3].
enum class TaintCategory : std::uint8_t {
  card, aadhaar, pan, api_key, otp, password, email, phone, ip_address, pin_code,
  bank_account, ifsc, upi_id, passport, dob, name, address, face, secret, quasi_id,
  count_  // keep last
};

[[nodiscard]] std::string_view to_string(TaintLevel l) noexcept;
[[nodiscard]] std::string_view to_string(TaintCategory c) noexcept;
[[nodiscard]] std::optional<TaintLevel> taint_level_from(std::string_view s) noexcept;
[[nodiscard]] std::optional<TaintCategory> taint_category_from(std::string_view s) noexcept;
// The minimum level data of this category carries.
[[nodiscard]] TaintLevel level_of(TaintCategory c) noexcept;

class TaintLabel {
 public:
  constexpr TaintLabel() noexcept = default;  // bottom: public, no categories
  [[nodiscard]] static TaintLabel of(TaintCategory c) noexcept;
  [[nodiscard]] static TaintLabel at(TaintLevel l) noexcept;
  [[nodiscard]] static TaintLabel top() noexcept;

  [[nodiscard]] TaintLevel level() const noexcept { return level_; }
  [[nodiscard]] std::uint32_t categories() const noexcept { return cats_; }
  [[nodiscard]] bool has(TaintCategory c) const noexcept;

  [[nodiscard]] TaintLabel join(const TaintLabel& o) const noexcept;
  [[nodiscard]] TaintLabel meet(const TaintLabel& o) const noexcept;
  [[nodiscard]] bool leq(const TaintLabel& o) const noexcept;
  [[nodiscard]] bool allows_egress() const noexcept { return level_ == TaintLevel::public_ && cats_ == 0; }

  friend bool operator==(const TaintLabel&, const TaintLabel&) = default;

  // taint_label.v1
  [[nodiscard]] nlohmann::json to_json() const;
  // Throws std::invalid_argument on unknown names or a level below what the categories imply.
  [[nodiscard]] static TaintLabel from_json(const nlohmann::json& j);

 private:
  constexpr TaintLabel(TaintLevel l, std::uint32_t c) noexcept : level_(l), cats_(c) {}
  TaintLevel level_ = TaintLevel::public_;
  std::uint32_t cats_ = 0;
};

}  // namespace pl
