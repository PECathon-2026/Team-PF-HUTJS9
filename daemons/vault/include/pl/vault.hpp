// Vault (owner: LNX): binding-checked storage of detected values (spec §6, AD-12).
//
// The master key lives in memfd_secret memory (removed from the kernel direct
// map) or, where that syscall is unavailable, in an mlock'ed MADV_DONTDUMP
// mapping. Each value is sealed with XChaCha20-Poly1305 under a per-session key
// derived from the master key, with the canonical binding as associated data:
// decryption succeeds only for the exact (session, placeholder, field type,
// site, element) it was stored with.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include <sodium.h>

#include <nlohmann/json.hpp>

namespace pl::vault {

// Page-aligned locked memory for key material.
class SecretMemory {
 public:
  explicit SecretMemory(std::size_t size);
  ~SecretMemory();
  SecretMemory(const SecretMemory&) = delete;
  SecretMemory& operator=(const SecretMemory&) = delete;
  SecretMemory(SecretMemory&&) = delete;
  SecretMemory& operator=(SecretMemory&&) = delete;

  [[nodiscard]] std::span<unsigned char> bytes() noexcept { return {ptr_, size_}; }
  [[nodiscard]] bool is_memfd_secret() const noexcept { return memfd_secret_; }

 private:
  unsigned char* ptr_ = nullptr;
  std::size_t size_ = 0;
  std::size_t mapped_ = 0;
  bool memfd_secret_ = false;
};

struct Binding {
  std::string session_id, placeholder, field_type, site, element_id;
  [[nodiscard]] std::string canonical() const;  // fixed field order, unit-separator joined
  [[nodiscard]] static Binding from_json(const nlohmann::json& j);
};

struct ShreddedSession : std::runtime_error {
  ShreddedSession() : std::runtime_error("vault: session shredded") {}
};

enum class Error : std::uint8_t { binding_mismatch, unknown_handle, shredded, too_large, internal };
[[nodiscard]] std::string_view error_name(Error e) noexcept;

class Vault {
 public:
  Vault();
  [[nodiscard]] std::string store(const Binding& b, std::string_view plaintext);  // returns vh-<32 hex>
  // Plaintext on an exact binding match; Error otherwise. Never reveals which part differed.
  [[nodiscard]] std::variant<std::string, Error> decrypt(std::string_view handle, const Binding& b);
  bool wipe(std::string_view handle);
  void shred(std::string_view session_id);  // drop the session key and every ciphertext of the session
  [[nodiscard]] bool key_in_memfd_secret() const noexcept { return master_.is_memfd_secret(); }
  [[nodiscard]] std::size_t size() const;

  // Handles one vault_api.v1 request; the reply is a vault_api.v1 message.
  [[nodiscard]] nlohmann::json handle(const nlohmann::json& request);

 private:
  struct Entry {
    std::string session_id;
    std::array<unsigned char, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES> nonce{};
    std::vector<unsigned char> ciphertext;
  };
  void session_key(std::string_view session_id, std::span<unsigned char, 32> out) const;

  SecretMemory master_;
  mutable std::mutex mu_;
  std::map<std::string, Entry, std::less<>> entries_;
  std::map<std::string, bool, std::less<>> shredded_;
};

inline constexpr std::size_t kMaxPlaintext = 4096;

}  // namespace pl::vault
