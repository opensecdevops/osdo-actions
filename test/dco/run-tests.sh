#!/usr/bin/env bash
# Tests for .github/scripts/check-dco.py. Run from the repository root.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHECKER="$ROOT/.github/scripts/check-dco.py"
FIXTURES="$ROOT/test/fixtures/dco"
failures=0

expect_exit() {
  local name="$1" fixture="$2" want="$3" got
  python3 -I "$CHECKER" "$FIXTURES/$fixture" >/dev/null 2>&1
  got=$?
  if [ "$got" -eq "$want" ]; then
    echo "PASS $name (exit $got)"
  else
    echo "FAIL $name: want exit $want, got $got"
    failures=$((failures + 1))
  fi
}

expect_exit "signed-off commits pass, merge commit exempt" pass.json 0
expect_exit "commit without sign-off fails" fail-missing.json 1
expect_exit "sign-off for another identity fails" fail-mismatch.json 1
expect_exit "empty commit list fails closed" empty.json 1
expect_exit "malformed input is an error" malformed.json 2
expect_exit "missing file is an error" does-not-exist.json 2

if [ "$failures" -ne 0 ]; then
  echo "$failures DCO test(s) failed"
  exit 1
fi
echo "All DCO tests passed"
