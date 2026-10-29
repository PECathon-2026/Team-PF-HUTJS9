// Google Benchmark for plcommon hot paths: framing and the log scrubber.
#include <benchmark/benchmark.h>

#include <string>

#include "pl/frame.hpp"
#include "pl/scrub.hpp"

static void BM_FrameRoundTrip(benchmark::State& state) {
  const std::string payload(static_cast<std::size_t>(state.range(0)), 'x');
  for (auto _ : state) {
    pl::FrameDecoder d;
    d.feed(pl::encode_frame(std::string_view(payload)));
    benchmark::DoNotOptimize(d.next());
  }
  state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * state.range(0));
}
BENCHMARK(BM_FrameRoundTrip)->Arg(256)->Arg(64 << 10)->Arg(1 << 20);

static void BM_ScrubLogLine(benchmark::State& state) {
  const std::string line = "user jane.doe@example.com paid with 4111 1111 1111 1111 for order 1234567, token sk-test-abcdefgh";
  for (auto _ : state) {
    benchmark::DoNotOptimize(pl::scrub(line));
  }
  state.SetBytesProcessed(state.iterations() * static_cast<std::int64_t>(line.size()));
}
BENCHMARK(BM_ScrubLogLine);
