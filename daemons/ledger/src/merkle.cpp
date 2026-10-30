#include "ledger/merkle.hpp"

#include <sodium.h>

#include <stdexcept>

namespace pl::ledger {

namespace {

void init_sodium() {
  if (sodium_init() < 0) {
    throw std::runtime_error("sodium_init failed");
  }
}

Hash sha256(const std::uint8_t* data, std::size_t n) {
  Hash h{};
  crypto_hash_sha256(h.data(), data, n);
  return h;
}

std::uint64_t split_point(std::uint64_t n) {  // largest power of two < n (n >= 2)
  std::uint64_t k = 1;
  while (k * 2 < n) {
    k *= 2;
  }
  return k;
}

bool is_pow2(std::uint64_t x) { return x != 0 && (x & (x - 1)) == 0; }

std::string b64(const std::uint8_t* d, std::size_t n) {
  std::string out(sodium_base64_ENCODED_LEN(n, sodium_base64_VARIANT_ORIGINAL), '\0');
  sodium_bin2base64(out.data(), out.size(), d, n, sodium_base64_VARIANT_ORIGINAL);
  out.resize(out.find('\0'));
  return out;
}

}  // namespace

std::string to_hex(const Hash& h) {
  std::string s(h.size() * 2 + 1, '\0');
  sodium_bin2hex(s.data(), s.size(), h.data(), h.size());
  s.resize(h.size() * 2);
  return s;
}

std::optional<Hash> from_hex(std::string_view hex) {
  Hash h{};
  if (hex.size() != 64) {
    return std::nullopt;
  }
  std::size_t len = 0;
  const std::string tmp(hex);
  if (sodium_hex2bin(h.data(), h.size(), tmp.c_str(), tmp.size(), nullptr, &len, nullptr) != 0 || len != h.size()) {
    return std::nullopt;
  }
  return h;
}

Hash leaf_hash(std::string_view data) {
  init_sodium();
  crypto_hash_sha256_state st;
  crypto_hash_sha256_init(&st);
  const std::uint8_t prefix = 0x00;
  crypto_hash_sha256_update(&st, &prefix, 1);
  crypto_hash_sha256_update(&st, reinterpret_cast<const std::uint8_t*>(data.data()), data.size());
  Hash h{};
  crypto_hash_sha256_final(&st, h.data());
  return h;
}

Hash node_hash(const Hash& l, const Hash& r) {
  init_sodium();
  std::array<std::uint8_t, 65> buf{};
  buf[0] = 0x01;
  std::copy(l.begin(), l.end(), buf.begin() + 1);
  std::copy(r.begin(), r.end(), buf.begin() + 33);
  return sha256(buf.data(), buf.size());
}

void MerkleTree::append_leaf_hash(const Hash& leaf) {
  if (levels_.empty()) {
    levels_.emplace_back();
  }
  levels_[0].push_back(leaf);
  for (std::size_t i = 0; levels_[i].size() % 2 == 0; ++i) {
    const auto& lv = levels_[i];
    const Hash h = node_hash(lv[lv.size() - 2], lv[lv.size() - 1]);
    if (i + 1 == levels_.size()) {
      levels_.emplace_back();
    }
    levels_[i + 1].push_back(h);
  }
}

Hash MerkleTree::mth(std::uint64_t start, std::uint64_t n) const {
  if (n == 0) {
    init_sodium();
    return sha256(nullptr, 0);
  }
  if (is_pow2(n) && start % n == 0) {
    std::size_t lvl = 0;
    while ((std::uint64_t{1} << lvl) < n) {
      ++lvl;
    }
    return levels_.at(lvl).at(start / n);
  }
  const std::uint64_t k = split_point(n);
  return node_hash(mth(start, k), mth(start + k, n - k));
}

Hash MerkleTree::root(std::uint64_t n) const {
  if (n > size()) {
    throw std::out_of_range("merkle: root beyond tree size");
  }
  return mth(0, n);
}

void MerkleTree::path(std::uint64_t m, std::uint64_t start, std::uint64_t n, std::vector<Hash>& out) const {
  if (n == 1) {
    return;
  }
  const std::uint64_t k = split_point(n);
  if (m < k) {
    path(m, start, k, out);
    out.push_back(mth(start + k, n - k));
  } else {
    path(m - k, start + k, n - k, out);
    out.push_back(mth(start, k));
  }
}

std::vector<Hash> MerkleTree::inclusion_proof(std::uint64_t m, std::uint64_t n) const {
  if (n > size() || m >= n) {
    throw std::out_of_range("merkle: bad inclusion proof arguments");
  }
  std::vector<Hash> out;
  path(m, 0, n, out);
  return out;
}

void MerkleTree::subproof(std::uint64_t m, std::uint64_t start, std::uint64_t n, bool b, std::vector<Hash>& out) const {
  if (m == n) {
    if (!b) {
      out.push_back(mth(start, n));
    }
    return;
  }
  const std::uint64_t k = split_point(n);
  if (m <= k) {
    subproof(m, start, k, b, out);
    out.push_back(mth(start + k, n - k));
  } else {
    subproof(m - k, start + k, n - k, false, out);
    out.push_back(mth(start, k));
  }
}

std::vector<Hash> MerkleTree::consistency_proof(std::uint64_t m, std::uint64_t n) const {
  if (m < 1 || m > n || n > size()) {
    throw std::out_of_range("merkle: bad consistency proof arguments");
  }
  std::vector<Hash> out;
  if (m < n) {
    subproof(m, 0, n, true, out);
  }
  return out;
}

bool verify_inclusion(const Hash& leaf, std::uint64_t index, std::uint64_t tree_size, const std::vector<Hash>& proof,
                      const Hash& root) {
  if (index >= tree_size) {
    return false;
  }
  std::uint64_t fn = index;
  std::uint64_t sn = tree_size - 1;
  Hash r = leaf;
  for (const Hash& p : proof) {
    if (sn == 0) {
      return false;
    }
    if ((fn & 1U) != 0 || fn == sn) {
      r = node_hash(p, r);
      if ((fn & 1U) == 0) {
        while ((fn & 1U) == 0 && fn != 0) {
          fn >>= 1U;
          sn >>= 1U;
        }
      }
    } else {
      r = node_hash(r, p);
    }
    fn >>= 1U;
    sn >>= 1U;
  }
  return sn == 0 && r == root;
}

bool verify_consistency(std::uint64_t first, std::uint64_t second, const Hash& first_root, const Hash& second_root,
                        const std::vector<Hash>& proof) {
  if (first < 1 || first > second) {
    return false;
  }
  if (first == second) {
    return proof.empty() && first_root == second_root;
  }
  std::vector<Hash> p;
  if (is_pow2(first)) {
    p.push_back(first_root);
  }
  p.insert(p.end(), proof.begin(), proof.end());
  if (p.empty()) {
    return false;
  }
  std::uint64_t fn = first - 1;
  std::uint64_t sn = second - 1;
  while ((fn & 1U) != 0) {
    fn >>= 1U;
    sn >>= 1U;
  }
  Hash fr = p[0];
  Hash sr = p[0];
  for (std::size_t i = 1; i < p.size(); ++i) {
    if (sn == 0) {
      return false;
    }
    const Hash& c = p[i];
    if ((fn & 1U) != 0 || fn == sn) {
      fr = node_hash(c, fr);
      sr = node_hash(c, sr);
      if ((fn & 1U) == 0) {
        while ((fn & 1U) == 0 && fn != 0) {
          fn >>= 1U;
          sn >>= 1U;
        }
      }
    } else {
      sr = node_hash(sr, c);
    }
    fn >>= 1U;
    sn >>= 1U;
  }
  return sn == 0 && fr == first_root && sr == second_root;
}

Signer Signer::from_seed(const SeedKey& seed) {
  init_sodium();
  Signer s;
  crypto_sign_seed_keypair(s.pk.data(), s.sk.data(), seed.data());
  return s;
}

std::string Signer::key_id() const {
  std::string hex(17, '\0');
  sodium_bin2hex(hex.data(), hex.size(), pk.data(), 8);
  hex.resize(16);
  return "ledger:" + hex;
}

std::string sth_message(std::uint64_t tree_size, const Hash& root, std::uint64_t ts_ns) {
  return "pl-sth-v1\n" + std::to_string(tree_size) + "\n" + to_hex(root) + "\n" + std::to_string(ts_ns);
}

nlohmann::json make_sth(const Signer& s, std::uint64_t tree_size, const Hash& root, std::uint64_t ts_ns) {
  init_sodium();
  const std::string msg = sth_message(tree_size, root, ts_ns);
  std::array<std::uint8_t, crypto_sign_BYTES> sig{};
  crypto_sign_detached(sig.data(), nullptr, reinterpret_cast<const std::uint8_t*>(msg.data()), msg.size(), s.sk.data());
  return {{"tree_size", tree_size},
          {"root", to_hex(root)},
          {"ts_ns", ts_ns},
          {"key_id", s.key_id()},
          {"signature", b64(sig.data(), sig.size())}};
}

bool verify_sth(const nlohmann::json& sth, const PublicKey& pk) {
  init_sodium();
  try {
    const auto root = from_hex(sth.at("root").get<std::string>());
    if (!root) {
      return false;
    }
    const std::string msg = sth_message(sth.at("tree_size").get<std::uint64_t>(), *root, sth.at("ts_ns").get<std::uint64_t>());
    const std::string sig_b64 = sth.at("signature").get<std::string>();
    std::array<std::uint8_t, crypto_sign_BYTES + 4> sig{};
    std::size_t len = 0;
    if (sodium_base642bin(sig.data(), sig.size(), sig_b64.c_str(), sig_b64.size(), nullptr, &len, nullptr,
                          sodium_base64_VARIANT_ORIGINAL) != 0 ||
        len != crypto_sign_BYTES) {
      return false;
    }
    return crypto_sign_verify_detached(sig.data(), reinterpret_cast<const std::uint8_t*>(msg.data()), msg.size(),
                                       pk.data()) == 0;
  } catch (const nlohmann::json::exception&) {
    return false;
  }
}

namespace {
nlohmann::json hashes_json(const std::vector<Hash>& v) {
  auto a = nlohmann::json::array();
  for (const auto& h : v) {
    a.push_back(to_hex(h));
  }
  return a;
}
}  // namespace

nlohmann::json inclusion_message(const MerkleTree& t, const Signer& s, std::uint64_t index, std::uint64_t n,
                                 std::uint64_t ts_ns) {
  return {{"schema", "merkle_proof.v1"}, {"proof_type", "inclusion"}, {"tree_size", n},
          {"leaf_index", index},         {"leaf_hash", to_hex(t.leaf(index))},
          {"hashes", hashes_json(t.inclusion_proof(index, n))}, {"sth", make_sth(s, n, t.root(n), ts_ns)}};
}

nlohmann::json consistency_message(const MerkleTree& t, const Signer& s, std::uint64_t m, std::uint64_t n,
                                   std::uint64_t ts_ns) {
  return {{"schema", "merkle_proof.v1"}, {"proof_type", "consistency"}, {"tree_size", n},
          {"first_size", m},             {"hashes", hashes_json(t.consistency_proof(m, n))},
          {"sth", make_sth(s, n, t.root(n), ts_ns)}};
}

bool verify_proof_message(const nlohmann::json& msg, const PublicKey& pk) {
  try {
    if (!verify_sth(msg.at("sth"), pk) || msg.at("sth").at("tree_size") != msg.at("tree_size")) {
      return false;
    }
    const auto root = from_hex(msg.at("sth").at("root").get<std::string>());
    std::vector<Hash> proof;
    for (const auto& h : msg.at("hashes")) {
      const auto x = from_hex(h.get<std::string>());
      if (!x) {
        return false;
      }
      proof.push_back(*x);
    }
    if (!root) {
      return false;
    }
    const auto type = msg.at("proof_type").get<std::string>();
    if (type == "inclusion") {
      const auto leaf = from_hex(msg.at("leaf_hash").get<std::string>());
      return leaf && verify_inclusion(*leaf, msg.at("leaf_index").get<std::uint64_t>(),
                                      msg.at("tree_size").get<std::uint64_t>(), proof, *root);
    }
    return false;  // consistency needs the older root too: use verify_consistency directly
  } catch (const nlohmann::json::exception&) {
    return false;
  }
}

}  // namespace pl::ledger
