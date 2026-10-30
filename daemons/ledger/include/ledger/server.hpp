// poll() loop: ingest socket (framed JSON in, framed ack out) and stream socket
// (framed JSON out to subscribers, e.g. the gate's UI relay). Owner: WIN-B.
#pragma once

#include <atomic>
#include <string>
#include <vector>

#include "ledger/ledger.hpp"
#include "pl/frame.hpp"
#include "pl/uds.hpp"

namespace pl::ledger {

inline constexpr std::uint32_t kMaxIngestFrame = 4U * 1024U * 1024U;

class Server {
 public:
  Server(Ledger& ledger, const std::string& ingest_path, const std::string& stream_path);
  // Runs until stop becomes true. Throws on unrecoverable errors only.
  void run(const std::atomic<bool>& stop);
  // One poll iteration (timeout in ms); exposed for tests.
  void step(int timeout_ms);
  [[nodiscard]] std::size_t subscribers() const noexcept { return subs_.size(); }

 private:
  struct Ingest {
    Fd fd;
    FrameDecoder dec{kMaxIngestFrame};
  };
  void accept_ingest();
  void accept_stream();
  bool read_ingest(Ingest& c);  // false: close
  void broadcast(const nlohmann::json& msg);

  Ledger* ledger_;
  Fd ingest_listener_;
  Fd stream_listener_;
  std::vector<Ingest> ingest_;
  std::vector<Fd> subs_;
  std::uint64_t last_stats_ms_ = 0;
};

}  // namespace pl::ledger
