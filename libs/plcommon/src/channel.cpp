// Encrypted channel (owner: LNX). See channel.hpp.
#include "pl/channel.hpp"

#include <stdexcept>
#include <string>
#include <utility>

namespace pl {
namespace {

void ensure_sodium() {
  if (sodium_init() < 0) {
    throw ProtocolError("libsodium init failed");
  }
}

std::vector<std::byte> recv_exact(FramedSocket& sock, std::size_t size, std::chrono::milliseconds timeout) {
  auto frame = sock.recv(timeout);
  if (!frame || frame->size() != size) {
    throw ProtocolError("channel handshake failed");
  }
  return std::move(*frame);
}

}  // namespace

void secure_wipe(std::span<std::byte> bytes) noexcept {
  if (!bytes.empty()) {
    sodium_memzero(bytes.data(), bytes.size());
  }
}

SecureChannel::SecureChannel(Fd fd, Role role, std::chrono::milliseconds timeout) : sock_(std::move(fd)) {
  ensure_sodium();
  std::array<unsigned char, crypto_kx_PUBLICKEYBYTES> pk{};
  std::array<unsigned char, crypto_kx_SECRETKEYBYTES> sk{};
  std::array<unsigned char, crypto_kx_SESSIONKEYBYTES> rx_key{};
  std::array<unsigned char, crypto_kx_SESSIONKEYBYTES> tx_key{};
  crypto_kx_keypair(pk.data(), sk.data());
  const auto pk_bytes = std::as_bytes(std::span(pk));
  int rc = -1;
  if (role == Role::client) {
    sock_.send(pk_bytes, timeout);
    const auto server_pk = recv_exact(sock_, crypto_kx_PUBLICKEYBYTES, timeout);
    rc = crypto_kx_client_session_keys(rx_key.data(), tx_key.data(), pk.data(), sk.data(),
                                       reinterpret_cast<const unsigned char*>(server_pk.data()));
  } else {
    const auto client_pk = recv_exact(sock_, crypto_kx_PUBLICKEYBYTES, timeout);
    sock_.send(pk_bytes, timeout);
    rc = crypto_kx_server_session_keys(rx_key.data(), tx_key.data(), pk.data(), sk.data(),
                                       reinterpret_cast<const unsigned char*>(client_pk.data()));
  }
  sodium_memzero(sk.data(), sk.size());
  if (rc != 0) {
    sodium_memzero(rx_key.data(), rx_key.size());
    sodium_memzero(tx_key.data(), tx_key.size());
    throw ProtocolError("channel key exchange failed");
  }
  std::array<unsigned char, crypto_secretstream_xchacha20poly1305_HEADERBYTES> header{};
  crypto_secretstream_xchacha20poly1305_init_push(&tx_, header.data(), tx_key.data());
  sodium_memzero(tx_key.data(), tx_key.size());
  sock_.send(std::as_bytes(std::span(header)), timeout);
  const auto peer_header = recv_exact(sock_, crypto_secretstream_xchacha20poly1305_HEADERBYTES, timeout);
  rc = crypto_secretstream_xchacha20poly1305_init_pull(&rx_, reinterpret_cast<const unsigned char*>(peer_header.data()),
                                                       rx_key.data());
  sodium_memzero(rx_key.data(), rx_key.size());
  if (rc != 0) {
    throw ProtocolError("channel header rejected");
  }
}

SecureChannel::~SecureChannel() {
  sodium_memzero(&tx_, sizeof tx_);
  sodium_memzero(&rx_, sizeof rx_);
}

void SecureChannel::send(std::span<const std::byte> plaintext) {
  if (dead_) {
    throw ProtocolError("channel closed");
  }
  std::vector<std::byte> out(plaintext.size() + crypto_secretstream_xchacha20poly1305_ABYTES);
  unsigned long long out_len = 0;
  crypto_secretstream_xchacha20poly1305_push(&tx_, reinterpret_cast<unsigned char*>(out.data()), &out_len,
                                             reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size(),
                                             nullptr, 0, crypto_secretstream_xchacha20poly1305_TAG_MESSAGE);
  out.resize(static_cast<std::size_t>(out_len));
  sock_.send(out);
}

std::optional<std::vector<std::byte>> SecureChannel::recv(std::chrono::milliseconds timeout) {
  if (dead_) {
    throw ProtocolError("channel closed");
  }
  auto frame = sock_.recv(timeout);
  if (!frame) {
    return std::nullopt;
  }
  if (frame->size() < crypto_secretstream_xchacha20poly1305_ABYTES) {
    dead_ = true;
    throw ProtocolError("channel frame too short");
  }
  std::vector<std::byte> out(frame->size() - crypto_secretstream_xchacha20poly1305_ABYTES);
  unsigned long long out_len = 0;
  unsigned char tag = 0;
  if (crypto_secretstream_xchacha20poly1305_pull(&rx_, reinterpret_cast<unsigned char*>(out.data()), &out_len, &tag,
                                                 reinterpret_cast<const unsigned char*>(frame->data()), frame->size(),
                                                 nullptr, 0) != 0 ||
      tag != crypto_secretstream_xchacha20poly1305_TAG_MESSAGE) {
    dead_ = true;
    secure_wipe(out);
    throw ProtocolError("channel frame failed authentication");
  }
  out.resize(static_cast<std::size_t>(out_len));
  return out;
}

void SecureChannel::send_json(const nlohmann::json& message, const MessageValidator* validator) {
  if (validator != nullptr && !validate_dispatch(*validator, message).ok) {
    throw ProtocolError("outgoing message fails its schema");
  }
  std::string text = message.dump();
  send(std::as_bytes(std::span<const char>(text.data(), text.size())));
  secure_wipe(std::as_writable_bytes(std::span<char>(text.data(), text.size())));
}

std::optional<nlohmann::json> SecureChannel::recv_json(const MessageValidator& validator, std::chrono::milliseconds timeout) {
  auto payload = recv(timeout);
  if (!payload) {
    return std::nullopt;
  }
  nlohmann::json message;
  try {
    message = parse_json_bounded(*payload);
  } catch (...) {
    secure_wipe(*payload);
    throw;
  }
  secure_wipe(*payload);
  if (!validate_dispatch(validator, message).ok) {
    throw ProtocolError("incoming message fails its schema");
  }
  return message;
}

}  // namespace pl
