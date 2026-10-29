#!/usr/bin/env bash
# clang-tidy over LNX-owned C++ sources, using the clang-debug compile database. Owner: LNX.
# Pass file paths to check only those; default is every LNX .cpp file.
set -euo pipefail
cmake --preset clang-debug >/dev/null
cmake --build --preset clang-debug
if (( $# )); then files=("$@"); else
  mapfile -t files < <(git ls-files -co --exclude-standard -- 'libs/plcommon/*.cpp' 'contracts/lib/*.cpp' \
    'daemons/core/*.cpp' 'daemons/vault/*.cpp' 'daemons/gate/*.cpp' 'daemons/ledger/*.cpp' 'platform/*.cpp' \
    | grep -vE '^daemons/core/(detect|sanitize|fourier)/' || true)
fi
if (( ${#files[@]} == 0 )); then echo "clang-tidy: nothing to run yet"; exit 0; fi
echo "clang-tidy: ${#files[@]} file(s)"
# Tests, benchmarks and fuzz targets use test idioms (gtest asserts guard optionals,
# benchmark loop variables, expected exceptions in fuzzers); relax only those checks there.
relaxed='-bugprone-unchecked-optional-access,-misc-const-correctness,-performance-inefficient-vector-operation,'
relaxed+='-misc-use-anonymous-namespace,-clang-analyzer-deadcode.DeadStores,-bugprone-empty-catch,'
relaxed+='-readability-avoid-nested-conditional-operator,-cppcoreguidelines-avoid-goto,-cert-err33-c'
lib=() aux=()
for f in "${files[@]}"; do
  if [[ "$f" =~ /(tests|bench|fuzz)/ ]]; then aux+=("$f"); else lib+=("$f"); fi
done
status=0
if (( ${#lib[@]} )); then
  printf '%s\0' "${lib[@]}" | xargs -0 -P 4 -n 4 clang-tidy -p build/clang-debug --quiet \
    --config-file=platform/clang-tidy.yaml --warnings-as-errors='*' || status=1
fi
if (( ${#aux[@]} )); then
  printf '%s\0' "${aux[@]}" | xargs -0 -P 4 -n 4 clang-tidy -p build/clang-debug --quiet \
    --config-file=platform/clang-tidy.yaml --checks="$relaxed" --warnings-as-errors='*' || status=1
fi
exit $status
