#!/usr/bin/env bash
# Tests for scripts/run-slither.sh with a stub slither on PATH, so no solc or
# Slither install is needed. Covers: findings are counted, and a run that does not
# produce a successful report fails the step.
set -uo pipefail

ACTION_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$(cd "$(mktemp -d)" && pwd -P)"
trap 'rm -rf "$WORK"' EXIT

failures=0
pass() { echo "PASS $1"; }
fail() { echo "FAIL $1"; failures=$((failures + 1)); }

mkdir -p "$WORK/bin" "$WORK/contracts"
echo "contract C {}" > "$WORK/contracts/C.sol"

# Stub slither: writes the JSON named by STUB_JSON (if set) to the --json path, then exits STUB_RC.
cat > "$WORK/bin/slither" <<'STUB'
#!/usr/bin/env bash
json=""
while [ $# -gt 0 ]; do
  case "$1" in --json) json="$2"; shift ;; esac
  shift
done
if [ -n "${STUB_JSON:-}" ] && [ -n "$json" ]; then
  printf '%s' "$STUB_JSON" > "$json"
fi
echo "stub slither ran"
exit "${STUB_RC:-0}"
STUB
chmod +x "$WORK/bin/slither"

run_script() {  # run_script <results-dir>; sets RC, leaves GITHUB_OUTPUT in $WORK/output
  : > "$WORK/output"
  env -i PATH="$WORK/bin:/usr/bin:/bin" GITHUB_OUTPUT="$WORK/output" \
    OSDO_RESULTS="$1" OSDO_CONTRACTS="$WORK/contracts" \
    STUB_JSON="${STUB_JSON:-}" STUB_RC="${STUB_RC:-0}" \
    bash "$ACTION_DIR/scripts/run-slither.sh" > "$WORK/stdout" 2>&1
  RC=$?
}

HIGH_JSON='{"success":true,"error":null,"results":{"detectors":[{"check":"reentrancy-eth","impact":"High","confidence":"Medium"},{"check":"arbitrary-send-eth","impact":"High","confidence":"Medium"},{"check":"solc-version","impact":"Informational","confidence":"High"}]}}'

# 1. Findings: exit 255 with a successful report is a pass, and counts are written.
STUB_JSON="$HIGH_JSON" STUB_RC=255 run_script "$WORK/r1"
if [ "$RC" -eq 0 ] && grep -qx "high=2" "$WORK/output" && grep -qx "critical=0" "$WORK/output"; then
  pass "findings with a successful report are counted (exit 255 is not treated as failure)"
else
  fail "findings case wrong (rc=$RC)"; cat "$WORK/stdout"
fi

# 2. No report at all (compile or import failure) fails the step.
STUB_JSON="" STUB_RC=1 run_script "$WORK/r2"
if [ "$RC" -ne 0 ] && grep -q "did not produce a successful report" "$WORK/stdout"; then
  pass "missing report fails the step"
else
  fail "missing report did not fail (rc=$RC)"
fi

# 3. A report marked unsuccessful fails the step.
STUB_JSON='{"success":false,"error":"Invalid solc compilation"}' STUB_RC=1 run_script "$WORK/r3"
if [ "$RC" -ne 0 ]; then
  pass "unsuccessful report fails the step"
else
  fail "unsuccessful report did not fail the step"
fi

# 4. A successful report with no detectors is a clean pass with zero counts.
STUB_JSON='{"success":true,"error":null,"results":{}}' STUB_RC=0 run_script "$WORK/r4"
if [ "$RC" -eq 0 ] && grep -qx "high=0" "$WORK/output"; then
  pass "successful empty report counts as zero findings"
else
  fail "empty report case wrong (rc=$RC)"
fi

if [ "$failures" -ne 0 ]; then
  echo "$failures smart-contract test(s) failed"
  exit 1
fi
echo "All osdo-smart-contract-audit tests passed"
