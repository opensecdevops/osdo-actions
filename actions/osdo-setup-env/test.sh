#!/usr/bin/env bash
# Tests for scripts/detect-deps.sh. Cache flags must be false when the dependency
# file is absent, so setup-* steps never ask for a cache they cannot key on.
set -uo pipefail

ACTION_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$(cd "$(mktemp -d)" && pwd -P)"
trap 'rm -rf "$WORK"' EXIT
failures=0

check() {  # check <name> <dir> <expected python> <expected node> <expected go>
  local out="$WORK/out-$1"
  : > "$out"
  (cd "$2" && GITHUB_OUTPUT="$out" bash "$ACTION_DIR/scripts/detect-deps.sh") || { echo "FAIL $1: script failed"; failures=$((failures + 1)); return; }
  if grep -qx "python-cache=$3" "$out" && grep -qx "node-cache=$4" "$out" && grep -qx "go-cache=$5" "$out"; then
    echo "PASS $1"
  else
    echo "FAIL $1: expected python=$3 node=$4 go=$5"; cat "$out"; failures=$((failures + 1))
  fi
}

empty="$WORK/empty"; mkdir -p "$empty"
check "no dependency files: no caches requested" "$empty" false false false

py="$WORK/py"; mkdir -p "$py/svc"; echo "requests" > "$py/svc/requirements.txt"
check "requirements.txt in a subdirectory enables pip cache" "$py" true false false

pyproj="$WORK/pyproj"; mkdir -p "$pyproj"; echo "[project]" > "$pyproj/pyproject.toml"
check "pyproject.toml enables pip cache" "$pyproj" true false false

node="$WORK/node"; mkdir -p "$node"; echo "{}" > "$node/package-lock.json"
check "package-lock.json enables npm cache" "$node" false true false

go="$WORK/go"; mkdir -p "$go"; echo "module x" > "$go/go.sum"
check "go.sum enables go cache" "$go" false false true

ignored="$WORK/ignored"; mkdir -p "$ignored/node_modules/dep" "$ignored/.git"
echo "{}" > "$ignored/node_modules/dep/package-lock.json"; echo "x" > "$ignored/.git/requirements.txt"
check "files under node_modules and .git are ignored" "$ignored" false false false

if [ "$failures" -ne 0 ]; then
  echo "$failures setup-env test(s) failed"
  exit 1
fi
echo "All osdo-setup-env tests passed"
