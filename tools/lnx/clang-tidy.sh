#!/usr/bin/env bash
# clang-tidy over LNX-owned C++ sources, using the clang-debug compile database. Owner: LNX.
# Pass file paths to check only those; default is every LNX .cpp file.
set -euo pipefail
cmake --preset clang-debug >/dev/null
cmake --build --preset clang-debug
if (( $# )); then files=("$@"); else
  roots=(libs/plcommon contracts/lib daemons/core daemons/vault daemons/gate daemons/ledger platform)
  if git rev-parse --git-dir >/dev/null 2>&1; then
    list() { git ls-files -co --exclude-standard -- "${roots[@]/%//*.cpp}"; }
  else  # a git worktree mounted without its parent .git: fall back to find
    list() { find "${roots[@]}" -name '*.cpp' -not -path '*/build/*' 2>/dev/null | sort; }
  fi
  mapfile -t files < <(list | grep -vE '^daemons/core/(detect|sanitize|fourier)/' || true)
fi
# Each file is checked against the compile database that builds it: clang-debug for libraries and
# tests, the fuzz preset (configured only, into build/fuzz-tidy, no module scan) for fuzz targets. Files in neither are skipped
# with a note, never checked with guessed flags.
cmake --preset fuzz -B build/fuzz-tidy -DCMAKE_CXX_SCAN_FOR_MODULES=OFF >/dev/null
indb() {  # indb <compile_commands.json> <file>... : print the files that database compiles
  python3 - "$@" <<'PY'
import json, os, sys
db = {os.path.realpath(os.path.join(e["directory"], e["file"])) for e in json.load(open(sys.argv[1]))}
print("\n".join(f for f in sys.argv[2:] if os.path.realpath(f) in db))
PY
}
declare -A dbof=()
while IFS= read -r f; do [[ -n "$f" ]] && dbof[$f]=build/clang-debug; done < <(indb build/clang-debug/compile_commands.json "${files[@]}")
while IFS= read -r f; do [[ -n "$f" && -z "${dbof[$f]:-}" ]] && dbof[$f]=build/fuzz-tidy; done < <(indb build/fuzz-tidy/compile_commands.json "${files[@]}")
for f in "${files[@]}"; do [[ -n "${dbof[$f]:-}" ]] || echo "clang-tidy: skipping $f (in no compile database)" >&2; done
mapfile -t files < <(printf '%s\n' "${!dbof[@]}" | sort)
if (( ${#files[@]} == 0 )); then echo "clang-tidy: nothing to run yet"; exit 0; fi
echo "clang-tidy: ${#files[@]} file(s)"
# Tests, benchmarks and fuzz targets use test idioms (gtest asserts guard optionals,
# benchmark loop variables, expected exceptions in fuzzers); relax only those checks there.
relaxed='-bugprone-unchecked-optional-access,-misc-const-correctness,-performance-inefficient-vector-operation,'
relaxed+='-misc-use-anonymous-namespace,-clang-analyzer-deadcode.DeadStores,-bugprone-empty-catch,'
relaxed+='-readability-avoid-nested-conditional-operator,-cppcoreguidelines-avoid-goto,-cert-err33-c'
status=0
run() {  # run <db> <checks-or-empty> <file>...
  local db=$1 checks=$2; shift 2
  (( $# )) || return 0
  printf '%s\0' "$@" | xargs -0 -P 4 -n 4 clang-tidy -p "$db" --quiet \
    --config-file=platform/clang-tidy.yaml ${checks:+--checks="$checks"} --warnings-as-errors='*'
}
for db in build/clang-debug build/fuzz-tidy; do
  lib=() aux=()
  for f in "${files[@]}"; do
    [[ "${dbof[$f]}" == "$db" ]] || continue
    if [[ "$f" =~ /(tests|bench|fuzz)/ ]]; then aux+=("$f"); else lib+=("$f"); fi
  done
  run "$db" "" "${lib[@]}" || status=1
  run "$db" "$relaxed" "${aux[@]}" || status=1
done
exit $status
