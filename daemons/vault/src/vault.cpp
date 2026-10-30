// Vault implementation (owner: LNX). See vault.hpp.
#include "pl/vault.hpp"

#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <variant>

namespace pl::vault {
namespace {

#ifndef SYS_memfd_secret
constexpr long kSysMemfdSecret = 447;
#else
constexpr long kSysMemfdSecret = SYS_memfd_secret;
#endif

std::string hex(std::span<const unsigned char> b) {
  std::string out(b.size() * 2 + 1, '\0');
  sodium_bin2hex(out.data(), out.size(), b.data(), b.size());
  out.pop_back();
  return out;
}

}  // namespace

SecretMemory::SecretMemory(std::size_t size) : size_(size) {
  const auto page = static_cast<std::size_t>(::sysconf(_SC_PAGESIZE));
  mapped_ = ((size + page - 1) / page) * page;
  const long fd = ::syscall(kSysMemfdSecret, 0);
  if (fd >= 0) {
    const int ifd = static_cast<int>(fd);
    if (::ftruncate(ifd, static_cast<off_t>(mapped_)) == 0) {
      void* p = ::mmap(nullptr, mapped_, PROT_READ | PROT_WRITE, MAP_SHARED, ifd, 0);
      if (p != MAP_FAILED) {
        ptr_ = static_cast<unsigned char*>(p);
        memfd_secret_ = true;
      }
    }
    ::close(ifd);
  }
  if (ptr_ == nullptr) {
    void* p = ::mmap(nullptr, mapped_, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
      throw std::runtime_error("vault: cannot map key memory");
    }
    ptr_ = static_cast<unsigned char*>(p);
    (void)::madvise(p, mapped_, MADV_DONTDUMP);
    if (::mlock(p, mapped_) != 0) {
      // Locking can fail under a tight RLIMIT_MEMLOCK; the key still never reaches a core dump.
      (void)errno;
    }
  }
}

SecretMemory::~SecretMemory() {
  sodium_memzero(ptr_, mapped_);
  (void)::munlock(ptr_, mapped_);
  (void)::munmap(ptr_, mapped_);
}

std::string Binding::canonical() const {
  std::string out;
  for (const auto* f : {&session_id, &placeholder, &field_type, &site, &element_id}) {
    out += *f;
    out += '\x1f';
  }
  return out;
}

Binding Binding::from_json(const nlohmann::json& j) {
  return Binding{j.at("session_id").get<std::string>(), j.at("placeholder").get<std::string>(),
                 j.at("field_type").get<std::string>(), j.at("site").get<std::string>(),
                 j.at("element_id").get<std::string>()};
}

std::string_view error_name(Error e) noexcept {
  switch (e) {
    case Error::binding_mismatch: return "binding_mismatch";
    case Error::unknown_handle: return "unknown_handle";
    case Error::shredded: return "shredded";
    case Error::too_large: return "too_large";
    case Error::internal: break;
  }
  return "internal";
}

Vault::Vault() : master_(crypto_kdf_KEYBYTES) {
  if (sodium_init() < 0) {
    throw std::runtime_error("vault: libsodium init failed");
  }
  crypto_kdf_keygen(master_.bytes().data());
}

void Vault::session_key(std::string_view session_id, std::span<unsigned char, 32> out) const {
  // Per-session subkey: BLAKE2b keyed by the master key over a purpose label + session id.
  crypto_generichash_state st;
  crypto_generichash_init(&st, const_cast<SecretMemory&>(master_).bytes().data(), crypto_kdf_KEYBYTES, out.size());
  static constexpr std::string_view kLabel = "pl.vault.session.v1";
  crypto_generichash_update(&st, reinterpret_cast<const unsigned char*>(kLabel.data()), kLabel.size());
  crypto_generichash_update(&st, reinterpret_cast<const unsigned char*>(session_id.data()), session_id.size());
  crypto_generichash_final(&st, out.data(), out.size());
  sodium_memzero(&st, sizeof st);
}

std::string Vault::store(const Binding& b, std::string_view plaintext) {
  if (plaintext.empty() || plaintext.size() > kMaxPlaintext) {
    throw std::invalid_argument("vault: plaintext size");
  }
  const std::lock_guard lock(mu_);
  if (shredded_.contains(b.session_id)) {
    throw ShreddedSession();
  }
  Entry e;
  e.session_id = b.session_id;
  randombytes_buf(e.nonce.data(), e.nonce.size());
  const std::string ad = b.canonical();
  std::array<unsigned char, 32> key{};
  session_key(b.session_id, key);
  e.ciphertext.resize(plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
  unsigned long long clen = 0;
  crypto_aead_xchacha20poly1305_ietf_encrypt(e.ciphertext.data(), &clen,
                                             reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size(),
                                             reinterpret_cast<const unsigned char*>(ad.data()), ad.size(), nullptr,
                                             e.nonce.data(), key.data());
  sodium_memzero(key.data(), key.size());
  e.ciphertext.resize(static_cast<std::size_t>(clen));
  std::array<unsigned char, 16> h{};
  randombytes_buf(h.data(), h.size());
  std::string handle = "vh-" + hex(h);
  entries_.emplace(handle, std::move(e));
  return handle;
}

std::variant<std::string, Error> Vault::decrypt(std::string_view handle, const Binding& b) {
  const std::lock_guard lock(mu_);
  const auto it = entries_.find(handle);
  if (it == entries_.end()) {
    return shredded_.contains(b.session_id) ? Error::shredded : Error::unknown_handle;
  }
  const Entry& e = it->second;
  if (e.session_id != b.session_id) {
    return Error::binding_mismatch;
  }
  const std::string ad = b.canonical();
  std::array<unsigned char, 32> key{};
  session_key(b.session_id, key);
  std::string out(e.ciphertext.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES, '\0');
  unsigned long long plen = 0;
  const int rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
      reinterpret_cast<unsigned char*>(out.data()), &plen, nullptr, e.ciphertext.data(), e.ciphertext.size(),
      reinterpret_cast<const unsigned char*>(ad.data()), ad.size(), e.nonce.data(), key.data());
  sodium_memzero(key.data(), key.size());
  if (rc != 0) {
    sodium_memzero(out.data(), out.size());
    return Error::binding_mismatch;
  }
  out.resize(static_cast<std::size_t>(plen));
  return out;
}

bool Vault::wipe(std::string_view handle) {
  const std::lock_guard lock(mu_);
  const auto it = entries_.find(handle);
  if (it == entries_.end()) {
    return false;
  }
  sodium_memzero(it->second.ciphertext.data(), it->second.ciphertext.size());
  entries_.erase(it);
  return true;
}

void Vault::shred(std::string_view session_id) {
  const std::lock_guard lock(mu_);
  for (auto it = entries_.begin(); it != entries_.end();) {
    if (it->second.session_id == session_id) {
      sodium_memzero(it->second.ciphertext.data(), it->second.ciphertext.size());
      it = entries_.erase(it);
    } else {
      ++it;
    }
  }
  shredded_.emplace(std::string(session_id), true);
}

std::size_t Vault::size() const {
  const std::lock_guard lock(mu_);
  return entries_.size();
}

nlohmann::json Vault::handle(const nlohmann::json& request) {
  nlohmann::json reply = {{"schema", "vault_api.v1"}, {"request_id", request.value("request_id", "rq-0000000000000000")}};
  auto fail = [&reply](Error e) {
    reply["op"] = "error";
    reply["error_code"] = std::string(error_name(e));
    return reply;
  };
  try {
    const std::string op = request.at("op").get<std::string>();
    if (op == "store") {
      const auto pt = request.at("plaintext").get_ref<const std::string&>();
      if (pt.size() > kMaxPlaintext) {
        return fail(Error::too_large);
      }
      const Binding b = Binding::from_json(request.at("binding"));
      reply["op"] = "store.ok";
      reply["handle"] = store(b, pt);
      return reply;
    }
    if (op == "decrypt") {
      auto r = decrypt(request.at("handle").get<std::string>(), Binding::from_json(request.at("binding")));
      if (auto* e = std::get_if<Error>(&r)) {
        return fail(*e);
      }
      reply["op"] = "decrypt.ok";
      reply["plaintext"] = std::move(std::get<std::string>(r));
      return reply;
    }
    if (op == "wipe") {
      if (!wipe(request.at("handle").get<std::string>())) {
        return fail(Error::unknown_handle);
      }
      reply["op"] = "ok";
      return reply;
    }
    if (op == "shred") {
      shred(request.at("session_id").get<std::string>());
      reply["op"] = "ok";
      return reply;
    }
  } catch (const ShreddedSession&) {
    return fail(Error::shredded);
  } catch (const std::exception&) {
    return fail(Error::internal);
  }
  return fail(Error::internal);
}

}  // namespace pl::vault
