#!/usr/bin/env bash
# Tests for scripts/run-osv.sh with a stub osv-scanner on PATH.
# Covers: normal results, "No package sources found" as a clean result, and every
# failure that must fail the step (unexpected exit, missing report, bad report).
set -uo pipefail

ACTION_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$(cd "$(mktemp -d)" && pwd -P)"
trap 'rm -rf "$WORK"' EXIT
failures=0
pass() { echo "PASS $1"; }
fail() { echo "FAIL $1"; failures=$((failures + 1)); }

mkdir -p "$WORK/bin" "$WORK/tree"
cat > "$WORK/bin/osv-scanner" <<'STUB'
#!/usr/bin/env bash
out=""
while [ $# -gt 0 ]; do
  case "$1" in --output) out="$2"; shift ;; esac
  shift
done
if [ -n "${STUB_JSON:-}" ] && [ -n "$out" ]; then printf '%s' "$STUB_JSON" > "$out"; fi
[ -n "${STUB_MSG:-}" ] && echo "$STUB_MSG"
exit "${STUB_RC:-0}"
STUB
chmod +x "$WORK/bin/osv-scanner"

VULN_JSON='{"results":[{"source":{"path":"package-lock.json"},"packages":[{"package":{"name":"left-pad","version":"1.0.0","ecosystem":"npm"},"vulnerabilities":[{"id":"GHSA-high","database_specific":{"severity":"HIGH"}},{"id":"GHSA-crit","database_specific":{"severity":"CRITICAL"}}]}]}]}'

run_script() {  # run_script <results-dir>; sets RC, output in $WORK/output
  : > "$WORK/output"
  env -i PATH="$WORK/bin:/usr/bin:/bin" GITHUB_OUTPUT="$WORK/output" \
    OSDO_RESULTS="$1" OSDO_SCAN_PATH="$WORK/tree" \
    STUB_JSON="${STUB_JSON:-}" STUB_RC="${STUB_RC:-0}" STUB_MSG="${STUB_MSG:-}" \
    bash "$ACTION_DIR/scripts/run-osv.sh" > "$WORK/stdout" 2>&1
  RC=$?
}

# 1. Vulnerabilities found (exit 1 with a report) are counted, not failed here.
STUB_JSON="$VULN_JSON" STUB_RC=1 run_script "$WORK/r1"
if [ "$RC" -eq 0 ] && grep -qx "osv-total=1" "$WORK/output" && grep -qx "osv-critical=1" "$WORK/output" \
  && grep -qx "osv-high=1" "$WORK/output" && grep -qx "osv-no-sources=false" "$WORK/output"; then
  pass "vulnerability report is counted by severity"
else
  fail "vulnerability report counts wrong (rc=$RC)"; cat "$WORK/stdout"
fi

# 2. Clean scan (exit 0 with an empty report) gives zero findings.
STUB_JSON='{"results":[]}' STUB_RC=0 run_script "$WORK/r2"
if [ "$RC" -eq 0 ] && grep -qx "osv-total=0" "$WORK/output"; then
  pass "clean report gives zero findings"
else
  fail "clean report case wrong (rc=$RC)"
fi

# 3. "No package sources found" (exit 128) is a clean result with an explicit notice,
#    and it does not need a report file.
STUB_JSON="" STUB_RC=128 STUB_MSG="No package sources found, --help for usage information." run_script "$WORK/r3"
if [ "$RC" -eq 0 ] && grep -qx "osv-total=0" "$WORK/output" && grep -qx "osv-no-sources=true" "$WORK/output" \
  && grep -q "::notice" "$WORK/stdout"; then
  pass "no package sources is a clean result with a notice"
else
  fail "no-package-sources case wrong (rc=$RC)"; cat "$WORK/stdout"
fi

# 4. Exit 128 for any other reason fails the step.
STUB_JSON="" STUB_RC=128 STUB_MSG="something else went wrong" run_script "$WORK/r4"
if [ "$RC" -ne 0 ] && grep -q "without the 'No package sources found' message" "$WORK/stdout"; then
  pass "exit 128 without the no-sources message fails"
else
  fail "unexplained exit 128 did not fail (rc=$RC)"
fi

# 5. A scanner error (exit 2) fails the step, even when it wrote a partial report.
STUB_JSON="$VULN_JSON" STUB_RC=2 STUB_MSG="error: cannot read lockfile" run_script "$WORK/r5"
if [ "$RC" -ne 0 ] && grep -q "osv-scanner failed with exit 2" "$WORK/stdout"; then
  pass "scanner error fails the step"
else
  fail "scanner error did not fail (rc=$RC)"
fi

# 6. Success without a report fails the step (a missing file must never mean zero).
STUB_JSON="" STUB_RC=0 run_script "$WORK/r6"
if [ "$RC" -ne 0 ] && grep -q "wrote no report" "$WORK/stdout"; then
  pass "missing report after a success fails the step"
else
  fail "missing report did not fail (rc=$RC)"
fi

# 7. A report that is not valid JSON fails the step.
STUB_JSON='not json' STUB_RC=1 run_script "$WORK/r7"
if [ "$RC" -ne 0 ]; then
  pass "malformed report fails the step"
else
  fail "malformed report did not fail"
fi

if [ "$failures" -ne 0 ]; then
  echo "$failures osdo-sca test(s) failed"
  exit 1
fi
echo "All osdo-sca tests passed"
