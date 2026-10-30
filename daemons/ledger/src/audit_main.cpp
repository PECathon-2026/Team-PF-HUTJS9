// pl-audit: offline verifier for the ledger's Merkle log (owner: WIN-B).
//   pl-audit verify <dir> [--pub <file>]          exit 0 only if chain, root, signatures and consistency all hold
//   pl-audit inclusion <dir> <seq>                prints a merkle_proof.v1 inclusion proof (stored signed head)
//   pl-audit consistency <dir> <first> <second>   prints a consistency proof (+ "first_root", a CLI extra)
//   pl-audit check <proof.json> --pub <file> [--first-root <hex>]   verifies a proof file
#include <fstream>
#include <iostream>
#include <string>

#include "ledger/audit.hpp"

using namespace pl::ledger;

namespace {
std::string opt(int argc, char** argv, const std::string& name) {
  for (int i = 1; i + 1 < argc; ++i) {
    if (name == argv[i]) {
      return argv[i + 1];
    }
  }
  return {};
}
int usage() {
  std::cerr << "usage: pl-audit verify <dir> [--pub f] | inclusion <dir> <seq> | consistency <dir> <m> <n> | check <file> --pub f [--first-root h]\n";
  return 2;
}
}  // namespace

int main(int argc, char** argv) {
  if (argc < 3) {
    return usage();
  }
  const std::string cmd = argv[1];
  try {
    if (cmd == "verify") {
      const std::filesystem::path dir = argv[2];
      std::string pubf = opt(argc, argv, "--pub");
      if (pubf.empty()) {
        pubf = (dir / "ledger.pub").string();
      }
      const auto pk = read_public_key(pubf);
      if (!pk) {
        std::cout << "pl-audit: FAILED: cannot read public key " << pubf << "\n";
        return 1;
      }
      const auto r = audit_verify(dir, *pk);
      for (const auto& e : r.errors) {
        std::cout << "  error: " << e << "\n";
      }
      std::cout << "pl-audit verify: " << (r.ok ? "OK" : "FAILED") << " entries=" << r.entries << " heads=" << r.heads
                << " root=" << r.root_hex << " entry0_attestation=" << (r.entry0_is_attestation ? "yes" : "no") << "\n";
      return r.ok ? 0 : 1;
    }
    if (cmd == "inclusion" && argc >= 4) {
      const auto m = audit_inclusion_proof(argv[2], std::stoull(argv[3]));
      if (!m) {
        std::cerr << "no signed head covers that entry\n";
        return 1;
      }
      std::cout << m->dump(2) << "\n";
      return 0;
    }
    if (cmd == "consistency" && argc >= 5) {
      const auto m = audit_consistency_proof(argv[2], std::stoull(argv[3]), std::stoull(argv[4]));
      if (!m) {
        std::cerr << "no stored signed head of that size\n";
        return 1;
      }
      std::cout << m->dump(2) << "\n";
      return 0;
    }
    if (cmd == "check") {
      const auto pk = read_public_key(opt(argc, argv, "--pub"));
      std::ifstream in(argv[2]);
      const auto msg = nlohmann::json::parse(in, nullptr, false);
      if (!pk || !msg.is_object()) {
        std::cout << "pl-audit check: FAILED (key or file unreadable)\n";
        return 1;
      }
      bool ok = false;
      if (msg.value("proof_type", "") == "consistency") {
        const auto first = from_hex(opt(argc, argv, "--first-root").empty() ? msg.value("first_root", "") : opt(argc, argv, "--first-root"));
        const auto second = from_hex(msg["sth"].value("root", ""));
        std::vector<Hash> proof;
        for (const auto& h : msg["hashes"]) {
          if (auto x = from_hex(h.get<std::string>())) {
            proof.push_back(*x);
          }
        }
        ok = first && second && verify_sth(msg["sth"], *pk) &&
             verify_consistency(msg["first_size"].get<std::uint64_t>(), msg["tree_size"].get<std::uint64_t>(), *first,
                                *second, proof);
      } else {
        ok = verify_proof_message(msg, *pk);
      }
      std::cout << "pl-audit check: " << (ok ? "OK" : "FAILED") << "\n";
      return ok ? 0 : 1;
    }
  } catch (const std::exception& e) {
    std::cerr << "pl-audit: " << e.what() << "\n";
    return 1;
  }
  return usage();
}
