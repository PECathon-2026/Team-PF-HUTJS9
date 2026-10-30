// ledgerd: PrivacyLens ledger daemon (owner: WIN-B).
//   ledgerd --ingest <sock> --stream <sock> --dir <segments dir> --schemas <contracts/schemas dir>
//   ledgerd --verify <segments dir>
#include <atomic>
#include <csignal>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>

#include "ledger/ledger.hpp"
#include "ledger/server.hpp"
#include "pl/contracts.hpp"

namespace {
// Set from a signal handler, so it must be a mutable global.
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
std::atomic<bool> g_stop{false};
extern "C" void on_signal(int /*unused*/) { g_stop.store(true); }
}  // namespace

int main(int argc, char** argv) {
  std::string ingest = "/run/pl/ledger.sock";
  std::string stream = "/run/pl/ledger-stream.sock";
  std::string dir = "/var/lib/pl/ledger";
  std::string schemas = "/contracts/schemas";
  std::string verify;
  std::string attestation;
  bool no_sync = false;
  try {
    for (int i = 1; i < argc; ++i) {
      const std::string a = argv[i];
      auto next = [&]() -> std::string {
        if (i + 1 >= argc) {
          throw std::invalid_argument("missing value for " + a);
        }
        return argv[++i];
      };
      if (a == "--ingest") {
        ingest = next();
      } else if (a == "--stream") {
        stream = next();
      } else if (a == "--dir") {
        dir = next();
      } else if (a == "--schemas") {
        schemas = next();
      } else if (a == "--verify") {
        verify = next();
      } else if (a == "--attestation") {
        attestation = next();
      } else if (a == "--no-sync") {
        no_sync = true;
      } else {
        std::cerr << "ledgerd: unknown argument " << a << "\n";
        return 2;
      }
    }
    if (!verify.empty()) {
      const auto r = pl::ledger::verify_segments(verify);
      if (r.ok) {
        std::cout << "ledger verify: OK, " << r.entries << " entries\n";
        return 0;
      }
      std::cout << "ledger verify: FAILED: " << r.error << "\n";
      return 1;
    }
    const auto registry = pl::contracts::Registry::load_dir(schemas);
    pl::ledger::LedgerConfig cfg;
    cfg.segments.dir = dir;
    cfg.segments.sync = !no_sync;
    pl::ledger::Ledger ledger(std::move(cfg), registry);
    if (!attestation.empty() && ledger.next_seq() == 1) {
      // Entry #0 of the log is the attestation value (spec §11), recorded before anything is served.
      std::ifstream in(attestation);
      const auto att = nlohmann::json::parse(in, nullptr, false);
      const auto r = ledger.ingest(att);
      if (!r.accepted || att.value("schema", "") != "attestation.v1") {
        std::cerr << "ledgerd: attestation rejected (" << r.rule_id << " " << r.code << ")\n";
        return 1;
      }
    }
    pl::ledger::Server server(ledger, ingest, stream);
    (void)std::signal(SIGINT, on_signal);
    (void)std::signal(SIGTERM, on_signal);
    (void)std::signal(SIGPIPE, SIG_IGN);
    std::cerr << "ledgerd: up (ingest=" << ingest << " stream=" << stream << " dir=" << dir << ")\n";
    server.run(g_stop);
  } catch (const std::exception& e) {
    std::cerr << "ledgerd: fatal: " << e.what() << "\n";
    return 1;
  }
  return 0;
}
