// vault daemon (owner: LNX): serves vault_api.v1 over encrypted channels on /run/pl/vault.sock.
#include <sys/prctl.h>
#include <sys/resource.h>

#include <atomic>
#include <csignal>
#include <cstdlib>
#include <string>
#include <thread>

#include "pl/channel.hpp"
#include "pl/contracts.hpp"
#include "pl/log.hpp"
#include "pl/uds.hpp"
#include "pl/vault.hpp"

namespace {

std::atomic<bool> g_stop{false};

void on_signal(int /*sig*/) { g_stop = true; }

void harden_process() {
  (void)::prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
  const rlimit none{0, 0};
  (void)::setrlimit(RLIMIT_CORE, &none);
}

void serve(pl::Fd fd, pl::vault::Vault& vault, const pl::contracts::Registry& registry) {
  try {
    pl::SecureChannel ch(std::move(fd), pl::SecureChannel::Role::server);
    while (!g_stop) {
      auto req = ch.recv_json(registry, std::chrono::milliseconds{500});
      if (!req) {
        continue;
      }
      ch.send_json(vault.handle(*req), nullptr);
    }
  } catch (const std::exception&) {
    // Channel or protocol failure: drop the connection (fail-closed). Inputs are never echoed.
  }
}

}  // namespace

int main() {
  harden_process();
  (void)std::signal(SIGTERM, on_signal);
  (void)std::signal(SIGINT, on_signal);
  (void)std::signal(SIGPIPE, SIG_IGN);
  const char* env = std::getenv("PL_VAULT_SOCK");
  const std::string path = env != nullptr ? env : "/run/pl/vault.sock";
  const char* schemas = std::getenv("PL_SCHEMAS_DIR");
  const auto registry = pl::contracts::Registry::load_dir(schemas != nullptr ? schemas : "/usr/share/pl/schemas");
  pl::vault::Vault vault;
  auto listener = pl::listen_unix(path);
  pl::Logger log("vault");
  log.info("vault.started", {{"memfd_secret", vault.key_in_memfd_secret()}});
  while (!g_stop) {
    auto conn = pl::accept_unix(listener, std::chrono::milliseconds{500});
    if (conn) {
      std::thread(serve, std::move(*conn), std::ref(vault), std::cref(registry)).detach();
    }
  }
  return 0;
}
