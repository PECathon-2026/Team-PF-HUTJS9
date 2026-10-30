#include "ledger/merkle.hpp"

#include <gtest/gtest.h>
#include <unistd.h>

#include <array>
#include <filesystem>
#include <fstream>

#include "ledger/audit.hpp"
#include "ledger/ledger.hpp"
#include "pl/contracts.hpp"

using namespace pl::ledger;
namespace fs = std::filesystem;

namespace {

std::string unhex(const std::string& h) {
  std::string out;
  for (std::size_t i = 0; i + 1 < h.size(); i += 2) {
    out.push_back(static_cast<char>(std::stoi(h.substr(i, 2), nullptr, 16)));
  }
  return out;
}

// RFC 6962 test leaves (Certificate Transparency reference vectors).
const std::array<const char*, 8> kLeaves = {"", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f"};

// Independent, naive recursive definition straight from RFC 6962 section 2.1.
Hash naive_mth(const std::vector<Hash>& leaves, std::size_t lo, std::size_t hi) {
  if (hi - lo == 1) {
    return leaves[lo];
  }
  std::size_t k = 1;
  while (k * 2 < hi - lo) {
    k *= 2;
  }
  return node_hash(naive_mth(leaves, lo, lo + k), naive_mth(leaves, lo + k, hi));
}

MerkleTree make(std::size_t n, std::vector<Hash>* leaves = nullptr) {
  MerkleTree t;
  for (std::size_t i = 0; i < n; ++i) {
    t.append("entry-" + std::to_string(i));
    if (leaves != nullptr) {
      leaves->push_back(leaf_hash("entry-" + std::to_string(i)));
    }
  }
  return t;
}

fs::path tmpdir(const char* name) {
  const fs::path p = fs::temp_directory_path() / (std::string("pl-merkle-test-") + name + "-" + std::to_string(::getpid()));
  fs::remove_all(p);
  return p;
}

}  // namespace

TEST(Merkle, EmptyRootIsSha256OfNothing) {
  MerkleTree t;
  EXPECT_EQ(to_hex(t.root()), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST(Merkle, Rfc6962KnownAnswers) {
  MerkleTree t;
  for (const char* l : kLeaves) {
    t.append(unhex(l));
  }
  EXPECT_EQ(to_hex(t.root(1)), "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d");
  EXPECT_EQ(to_hex(t.root(2)), "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125");
  EXPECT_EQ(to_hex(t.root(3)), "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77");
  EXPECT_EQ(to_hex(t.root(4)), "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7");
  EXPECT_EQ(to_hex(t.root(8)), "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328");
}

TEST(Merkle, IncrementalMatchesNaiveDefinition) {
  std::vector<Hash> leaves;
  const auto t = make(70, &leaves);
  for (std::size_t n = 1; n <= 70; ++n) {
    EXPECT_EQ(t.root(n), naive_mth(leaves, 0, n)) << n;
  }
}

TEST(Merkle, AllInclusionProofsVerifyAndTamperFails) {
  std::vector<Hash> leaves;
  const auto t = make(37, &leaves);
  for (std::uint64_t n = 1; n <= 37; ++n) {
    for (std::uint64_t i = 0; i < n; ++i) {
      auto p = t.inclusion_proof(i, n);
      ASSERT_TRUE(verify_inclusion(leaves[i], i, n, p, t.root(n))) << i << "/" << n;
      if (!p.empty()) {
        auto bad = p;
        bad[0][0] ^= 1U;
        EXPECT_FALSE(verify_inclusion(leaves[i], i, n, bad, t.root(n)));
      }
      EXPECT_FALSE(verify_inclusion(leaves[(i + 1) % n], i, n, p, t.root(n)) && n > 1 && leaves[(i + 1) % n] != leaves[i]);
      auto longer = p;
      longer.push_back(p.empty() ? t.root(n) : p[0]);
      EXPECT_FALSE(verify_inclusion(leaves[i], i, n, longer, t.root(n)));
    }
  }
}

TEST(Merkle, AllConsistencyProofsVerifyAndTamperFails) {
  const auto t = make(37);
  for (std::uint64_t n = 1; n <= 37; ++n) {
    for (std::uint64_t m = 1; m <= n; ++m) {
      auto p = t.consistency_proof(m, n);
      ASSERT_TRUE(verify_consistency(m, n, t.root(m), t.root(n), p)) << m << "/" << n;
      if (!p.empty()) {
        auto bad = p;
        bad.back()[5] ^= 0x80U;
        EXPECT_FALSE(verify_consistency(m, n, t.root(m), t.root(n), bad));
      }
      if (m < n) {
        EXPECT_FALSE(verify_consistency(m, n, t.root(m - 1 == 0 ? 1 : m - 1) == t.root(m) ? leaf_hash("x") : t.root(m - 1 == 0 ? 1 : m - 1), t.root(n), p));
      }
    }
  }
}

TEST(Merkle, SignedHeadVerifiesAndRejectsChanges) {
  SeedKey seed{};
  seed.fill(7);
  const auto s = Signer::from_seed(seed);
  const auto t = make(5);
  auto sth = make_sth(s, 5, t.root(), 123);
  EXPECT_TRUE(verify_sth(sth, s.pk));
  EXPECT_EQ(sth["key_id"].get<std::string>().rfind("ledger:", 0), 0U);
  auto b = sth;
  b["tree_size"] = 6;
  EXPECT_FALSE(verify_sth(b, s.pk));
  b = sth;
  b["root"] = to_hex(make(6).root());
  EXPECT_FALSE(verify_sth(b, s.pk));
  SeedKey other{};
  other.fill(8);
  EXPECT_FALSE(verify_sth(sth, Signer::from_seed(other).pk));
  const auto msg = inclusion_message(t, s, 2, 5, 9);
  EXPECT_TRUE(verify_proof_message(msg, s.pk));
  auto bad = msg;
  bad["leaf_index"] = 3;
  EXPECT_FALSE(verify_proof_message(bad, s.pk));
}

namespace {
const pl::contracts::Registry& registry() {
  static const auto r = pl::contracts::Registry::load_dir(fs::path(PL_CONTRACTS_DIR) / "schemas");
  return r;
}
nlohmann::json fixture(const char* rel) {
  std::ifstream in(fs::path(PL_CONTRACTS_DIR) / "fixtures" / rel);
  return nlohmann::json::parse(in);
}
}  // namespace

TEST(Audit, LedgerSignsHeadsAndAuditCatchesTampering) {
  const auto dir = tmpdir("audit");
  PublicKey pk{};
  {
    LedgerConfig c;
    c.segments = {dir, 1U << 20, false};
    Ledger l(c, registry());
    EXPECT_TRUE(l.ingest(fixture("event.v1/valid/detection.json")).accepted);
    ASSERT_TRUE(l.publish_sth());
    EXPECT_FALSE(l.publish_sth());  // nothing new
    EXPECT_TRUE(l.ingest(fixture("egress_record.v1/valid/ai-sent.json")).accepted);
    EXPECT_TRUE(l.ingest(fixture("decision_record.v1/valid/gate-block.json")).accepted);
    ASSERT_TRUE(l.publish_sth());
    pk = l.public_key();
    EXPECT_EQ(l.tree().size(), 3U);
  }
  EXPECT_EQ(fs::status(dir / "ledger.key").permissions() & (fs::perms::group_all | fs::perms::others_all), fs::perms::none);
  auto rep = audit_verify(dir, pk);
  EXPECT_TRUE(rep.ok) << (rep.errors.empty() ? "" : rep.errors[0]);
  EXPECT_EQ(rep.entries, 3U);
  EXPECT_EQ(rep.heads, 2U);

  const auto inc = audit_inclusion_proof(dir, 2);
  ASSERT_TRUE(inc);
  EXPECT_TRUE(verify_proof_message(*inc, pk));
  ASSERT_TRUE(audit_consistency_proof(dir, 1, 3));

  {  // restart: recovered tree equals the old one, no spurious new head
    LedgerConfig c;
    c.segments = {dir, 1U << 20, false};
    Ledger l(c, registry());
    EXPECT_EQ(l.tree().size(), 3U);
    EXPECT_FALSE(l.publish_sth());
    EXPECT_EQ(l.public_key(), pk);
  }
  // Tamper with a stored head's root: audit must fail.
  std::string heads;
  {
    std::ifstream in(dir / "sth.jsonl");
    heads.assign(std::istreambuf_iterator<char>(in), {});
  }
  auto pos = heads.find(R"("root":")") + 8;
  heads[pos] = heads[pos] == 'a' ? 'b' : 'a';
  std::ofstream(dir / "sth.jsonl", std::ios::trunc) << heads;
  EXPECT_FALSE(audit_verify(dir, pk).ok);
  fs::remove_all(dir);
}
