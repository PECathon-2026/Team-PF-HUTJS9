#!/usr/bin/env bash
# Run every libFuzzer target for N seconds each (default 60). Owner: LNX.
# Targets come from build/fuzz/pl_fuzzers.txt (written by pl_add_fuzzer).
# Crashes are kept in build/fuzz/artifacts/<target>/ and fail the run.
set -euo pipefail
secs="${1:-60}"
cmake --preset fuzz >/dev/null
cmake --build --preset fuzz
list=build/fuzz/pl_fuzzers.txt
if [[ ! -s "$list" ]] || ! grep -q '|' "$list"; then
  echo "fuzz-smoke: nothing to run yet"
  exit 0
fi
status=0
while IFS='|' read -r name bin corpus; do
  [[ -n "$name" ]] || continue
  work="build/fuzz/corpus/$name" art="build/fuzz/artifacts/$name"
  mkdir -p "$work" "$art"
  echo "fuzz-smoke: $name for ${secs}s (seeds: ${corpus:-none})"
  # Fresh working corpus first, read-only seeds second: new inputs go to $work.
  if ! "$bin" -max_total_time="$secs" -timeout=10 -rss_limit_mb=1024 -print_final_stats=1 \
        -artifact_prefix="$art/" "$work" ${corpus:+"$corpus"} 2>"build/fuzz/$name.log"; then
    echo "fuzz-smoke: $name FAILED; see build/fuzz/$name.log and $art/"
    tail -n 40 "build/fuzz/$name.log"
    status=1
  else
    grep -E 'stat::number_of_executed_units|stat::new_units_added' "build/fuzz/$name.log" | sed "s/^/  $name /"
  fi
done < "$list"
exit $status
