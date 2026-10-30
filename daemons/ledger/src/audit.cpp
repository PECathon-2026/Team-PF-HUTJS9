#include "ledger/audit.hpp"

#include <sodium.h>

#include <fstream>
#include <map>
#include <ranges>

#include "ledger/segment.hpp"

namespace pl::ledger {

namespace {

std::vector<nlohmann::json> read_heads(const std::filesystem::path& dir) {
  std::vector<nlohmann::json> out;
  std::ifstream in(dir / "sth.jsonl");
  std::string l;
  while (std::getline(in, l)) {
    auto j = nlohmann::json::parse(l, nullptr, false);
    if (j.is_object()) {
      out.push_back(std::move(j));
    } else {
      out.push_back(nlohmann::json::object());  // unparseable head: reported by verify
    }
  }
  return out;
}

MerkleTree build_tree(const std::filesystem::path& dir) {
  MerkleTree t;
  for (const auto& line : read_all_lines(dir)) {
    t.append(line);
  }
  return t;
}

nlohmann::json hashes_json(const std::vector<Hash>& v) {
  auto a = nlohmann::json::array();
  for (const auto& h : v) {
    a.push_back(to_hex(h));
  }
  return a;
}

}  // namespace

std::optional<PublicKey> read_public_key(const std::filesystem::path& file) {
  std::ifstream in(file);
  std::string hex;
  PublicKey pk{};
  std::size_t len = 0;
  if (!(in >> hex) || hex.size() != 64 ||
      sodium_hex2bin(pk.data(), pk.size(), hex.c_str(), hex.size(), nullptr, &len, nullptr) != 0 || len != pk.size()) {
    return std::nullopt;
  }
  return pk;
}

AuditReport audit_verify(const std::filesystem::path& dir, const PublicKey& pk) {
  AuditReport rep;
  const auto chain = verify_segments(dir);
  rep.entries = chain.entries;
  if (!chain.ok) {
    rep.errors.push_back("hash chain: " + chain.error);
    return rep;
  }
  const MerkleTree tree = build_tree(dir);
  rep.root_hex = to_hex(tree.root());
  const auto lines = read_all_lines(dir);
  if (!lines.empty()) {
    const auto e0 = nlohmann::json::parse(lines[0], nullptr, false);
    rep.entry0_is_attestation = e0.is_object() && e0.value("kind", "") == "attestation";
  }
  const auto heads = read_heads(dir);
  rep.heads = heads.size();
  std::uint64_t prev_size = 0;
  Hash prev_root{};
  for (std::size_t i = 0; i < heads.size(); ++i) {
    const auto& h = heads[i];
    const std::string tag = "head " + std::to_string(i) + ": ";
    if (!verify_sth(h, pk)) {
      rep.errors.push_back(tag + "bad signature or format");
      continue;
    }
    const auto size = h["tree_size"].get<std::uint64_t>();
    if (size > tree.size() || size == 0) {
      rep.errors.push_back(tag + "tree_size outside the log");
      continue;
    }
    const Hash root = tree.root(size);
    if (to_hex(root) != h["root"].get<std::string>()) {
      rep.errors.push_back(tag + "root does not match the entries");
      continue;
    }
    if (prev_size != 0) {
      if (size < prev_size) {
        rep.errors.push_back(tag + "tree shrank");
      } else if (!verify_consistency(prev_size, size, prev_root, root, tree.consistency_proof(prev_size, size))) {
        rep.errors.push_back(tag + "not consistent with the previous head");
      }
    }
    prev_size = size;
    prev_root = root;
  }
  rep.ok = rep.errors.empty();
  return rep;
}

std::optional<nlohmann::json> audit_inclusion_proof(const std::filesystem::path& dir, std::uint64_t seq) {
  if (seq == 0) {
    return std::nullopt;
  }
  const MerkleTree tree = build_tree(dir);
  const auto heads = read_heads(dir);
  for (const auto& head : std::views::reverse(heads)) {
    if (!head.contains("tree_size") || !head["tree_size"].is_number_unsigned()) {
      continue;
    }
    const auto size = head["tree_size"].get<std::uint64_t>();
    if (size >= seq && size <= tree.size()) {
      const std::uint64_t idx = seq - 1;
      return nlohmann::json{{"schema", "merkle_proof.v1"}, {"proof_type", "inclusion"}, {"tree_size", size},
                            {"leaf_index", idx},           {"leaf_hash", to_hex(tree.leaf(idx))},
                            {"hashes", hashes_json(tree.inclusion_proof(idx, size))}, {"sth", head}};
    }
  }
  return std::nullopt;
}

std::optional<nlohmann::json> audit_consistency_proof(const std::filesystem::path& dir, std::uint64_t first,
                                                      std::uint64_t second) {
  const MerkleTree tree = build_tree(dir);
  if (first < 1 || first > second || second > tree.size()) {
    return std::nullopt;
  }
  for (const auto& h : read_heads(dir)) {
    if (h.contains("tree_size") && h["tree_size"] == second) {
      return nlohmann::json{{"schema", "merkle_proof.v1"}, {"proof_type", "consistency"}, {"tree_size", second},
                            {"first_size", first},         {"first_root", to_hex(tree.root(first))},
                            {"hashes", hashes_json(tree.consistency_proof(first, second))}, {"sth", h}};
    }
  }
  return std::nullopt;
}

}  // namespace pl::ledger
