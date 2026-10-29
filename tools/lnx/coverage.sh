#!/usr/bin/env bash
# Clang source-based line coverage for LNX-owned C++ libraries. Owner: LNX.
# Fails when line coverage of the measured sources is below PL_COV_MIN (default 80).
set -euo pipefail
min="${PL_COV_MIN:-80}"
rm -rf build/coverage/profiles
cmake --preset coverage >/dev/null
cmake --build --preset coverage
ctest --preset coverage --output-on-failure
shopt -s nullglob
profiles=(build/coverage/profiles/*.profraw)
if (( ${#profiles[@]} == 0 )); then
  echo "coverage: nothing to run yet"
  exit 0
fi
llvm-profdata merge -sparse "${profiles[@]}" -o build/coverage/merged.profdata
mapfile -t bins < <(find build/coverage -type f -name '*_test' -perm -u+x)
objs=()
for b in "${bins[@]:1}"; do objs+=(-object "$b"); done
# Measured: LNX library sources (not tests, not third-party headers).
ignore='(/usr/|/opt/|_test\.cpp|/tests?/|/fuzz/|build/)'
llvm-cov report "${bins[0]}" "${objs[@]}" -instr-profile=build/coverage/merged.profdata \
  -ignore-filename-regex="$ignore" | tee build/coverage/report.txt
llvm-cov export "${bins[0]}" "${objs[@]}" -instr-profile=build/coverage/merged.profdata \
  -ignore-filename-regex="$ignore" -format=lcov > build/coverage/lcov.info
pct=$(awk '/^TOTAL/ {print $(NF-3)}' build/coverage/report.txt | tr -d '%')
echo "coverage: line coverage ${pct}% (minimum ${min}%)"
awk -v p="$pct" -v m="$min" 'BEGIN { exit (p + 0 >= m + 0) ? 0 : 1 }' || { echo "coverage: below minimum"; exit 1; }
