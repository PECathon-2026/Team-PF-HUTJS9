// Encrypted, authenticated framed channel (AD-04, owner: LNX).
//
// Handshake over a FramedSocket: the client sends its X25519 public key, the
// server answers with its own, both derive rx/tx keys with crypto_kx, and each
// side sends a crypto_secretstream_xchacha20poly1305 header for its direction.
// Every later frame is one secretstream message: tampering, replay, reordering
// and truncation all fail decryption, and the channel is then dead (fail-closed).
//
// Sprint 1 limit: the X25519 keys are ephemeral per connection and the peer is
// identified by SO_PEERCRED only; component keys pinned through the ledger
// registry come later (docs/architecture/lnx.md).
#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <optional>
#include <span>
#include <vector>

#include <sodium.h>

#include <nlohmann/json.hpp>

#include "pl/uds.hpp"
#include "pl/validate.hpp"

namespace pl {

class SecureChannel {
 public:
  enum class Role : std::uint8_t { client, server };

  // Runs the handshake; throws ProtocolError on any failure or timeout.
  SecureChannel(Fd fd, Role role, std::chrono::milliseconds timeout = std::chrono::milliseconds{5000});
  ~SecureChannel();
  SecureChannel(const SecureChannel&) = delete;
  SecureChannel& operator=(const SecureChannel&) = delete;
  SecureChannel(SecureChannel&&) = delete;
  SecureChannel& operator=(SecureChannel&&) = delete;

  void send(std::span<const std::byte> plaintext);
  // nullopt on clean EOF or timeout; throws ProtocolError on a bad frame.
  [[nodiscard]] std::optional<std::vector<std::byte>> recv(std::chrono::milliseconds timeout);

  void send_json(const nlohmann::json& message, const MessageValidator* validator);
  [[nodiscard]] std::optional<nlohmann::json> recv_json(const MessageValidator& validator, std::chrono::milliseconds timeout);

  [[nodiscard]] const Fd& fd() const noexcept { return sock_.fd(); }

 private:
  FramedSocket sock_;
  crypto_secretstream_xchacha20poly1305_state tx_{};
  crypto_secretstream_xchacha20poly1305_state rx_{};
  bool dead_ = false;
};

// Zero `bytes` in a way the compiler can't elide.
void secure_wipe(std::span<std::byte> bytes) noexcept;

}  // namespace pl
