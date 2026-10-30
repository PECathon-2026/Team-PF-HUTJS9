// RFC 6962 / RFC 9162 Merkle tree with Ed25519-signed tree heads (owner: WIN-B, spec §11).
//
// leaf = SHA-256(0x00 || data), node = SHA-256(0x01 || left || right), empty root = SHA-256("").
// Complete subtrees are cached per level, so appends and roots are O(log n).
// Signed tree head (STH) signs the exact bytes of sth_message(): see below.
#pragma once

#include <array>
#include <cstdint>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace pl::ledger {

using Hash = std::array<std::uint8_t, 32>;

[[nodiscard]] std::string to_hex(const Hash& h);
[[nodiscard]] std::optional<Hash> from_hex(std::string_view hex);
[[nodiscard]] Hash leaf_hash(std::string_view data);
[[nodiscard]] Hash node_hash(const Hash& l, const Hash& r);

class MerkleTree {
 public:
  void append_leaf_hash(const Hash& leaf);
  void append(std::string_view data) { append_leaf_hash(leaf_hash(data)); }
  [[nodiscard]] std::uint64_t size() const noexcept { return levels_.empty() ? 0 : levels_[0].size(); }
  [[nodiscard]] const Hash& leaf(std::uint64_t i) const { return levels_.at(0).at(i); }
  // Root of the first n leaves (n <= size()).
  [[nodiscard]] Hash root(std::uint64_t n) const;
  [[nodiscard]] Hash root() const { return root(size()); }
  // Audit path for leaf m in the first n leaves; throws std::out_of_range on bad arguments.
  [[nodiscard]] std::vector<Hash> inclusion_proof(std::uint64_t m, std::uint64_t n) const;
  // Consistency proof between the first m and the first n leaves (1 <= m <= n <= size()).
  [[nodiscard]] std::vector<Hash> consistency_proof(std::uint64_t m, std::uint64_t n) const;

 private:
  [[nodiscard]] Hash mth(std::uint64_t start, std::uint64_t n) const;
  void path(std::uint64_t m, std::uint64_t start, std::uint64_t n, std::vector<Hash>& out) const;
  void subproof(std::uint64_t m, std::uint64_t start, std::uint64_t n, bool b, std::vector<Hash>& out) const;
  std::vector<std::vector<Hash>> levels_;
};

[[nodiscard]] bool verify_inclusion(const Hash& leaf, std::uint64_t index, std::uint64_t tree_size,
                                    const std::vector<Hash>& proof, const Hash& root);
[[nodiscard]] bool verify_consistency(std::uint64_t first, std::uint64_t second, const Hash& first_root,
                                      const Hash& second_root, const std::vector<Hash>& proof);

// ---- Signed tree heads ----
using SeedKey = std::array<std::uint8_t, 32>;
using PublicKey = std::array<std::uint8_t, 32>;

struct Signer {
  std::array<std::uint8_t, 64> sk{};  // libsodium Ed25519 secret key
  PublicKey pk{};
  static Signer from_seed(const SeedKey& seed);
  [[nodiscard]] std::string key_id() const;  // "ledger:<first 8 bytes of pk, hex>"
};

// Bytes that are signed: "pl-sth-v1\n<tree_size>\n<root hex>\n<ts_ns>".
[[nodiscard]] std::string sth_message(std::uint64_t tree_size, const Hash& root, std::uint64_t ts_ns);
// merkle_proof.v1 "sth" object.
[[nodiscard]] nlohmann::json make_sth(const Signer& s, std::uint64_t tree_size, const Hash& root, std::uint64_t ts_ns);
[[nodiscard]] bool verify_sth(const nlohmann::json& sth, const PublicKey& pk);

// merkle_proof.v1 messages (inclusion / consistency), each carrying an STH.
[[nodiscard]] nlohmann::json inclusion_message(const MerkleTree& t, const Signer& s, std::uint64_t index,
                                               std::uint64_t n, std::uint64_t ts_ns);
[[nodiscard]] nlohmann::json consistency_message(const MerkleTree& t, const Signer& s, std::uint64_t m,
                                                 std::uint64_t n, std::uint64_t ts_ns);
// Verifies a merkle_proof.v1 message against the key. For inclusion, `leaf` must be the recomputed leaf hash.
[[nodiscard]] bool verify_proof_message(const nlohmann::json& msg, const PublicKey& pk);

}  // namespace pl::ledger
