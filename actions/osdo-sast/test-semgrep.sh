#!/usr/bin/env bash
# Tests for scripts/run-semgrep.sh with a stub semgrep on PATH. The stub rejects
# --json combined with --sarif, as real semgrep does, so the flag regression is caught.
set -uo pipefail

ACTION_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$(cd "$(mktemp -d)" && pwd -P)"
trap 'rm -rf "$WORK"' EXIT
failures=0
pass() { echo "PASS $1"; }
fail() { echo "FAIL $1"; failures=$((failures + 1)); }

mkdir -p "$WORK/bin" "$WORK/src"
echo "print('x')" > "$WORK/src/app.py"
cat > "$WORK/bin/semgrep" <<'STUB'
#!/usr/bin/env bash
echo "$*" >> "$STUB_ARGS_LOG"
json=""; sarif=""; has_json=false; has_sarif=false
while [ $# -gt 0 ]; do
  case "$1" in
    --json) has_json=true ;;
    --sarif) has_sarif=true ;;
    --output) json="$2"; shift ;;
    --sarif-output) sarif="$2"; shift ;;
  esac
  shift
done
if [ "$has_json" = true ] && [ "$has_sarif" = true ]; then
  echo "[ERROR]: Mutually exclusive options --json/--emacs/--vim/--sarif" >&2
  exit 2
fi
[ -n "${STUB_JSON:-}" ] && [ -n "$json" ] && printf '%s' "$STUB_JSON" > "$json"
[ -n "${STUB_SARIF:-}" ] && [ -n "$sarif" ] && printf '%s' "$STUB_SARIF" > "$sarif"
exit "${STUB_RC:-0}"
STUB
chmod +x "$WORK/bin/semgrep"

RESULTS_JSON='{"results":[{"check_id":"a","extra":{"severity":"ERROR"}},{"check_id":"b","extra":{"severity":"WARNING"}},{"check_id":"c","extra":{"severity":"ERROR"}}]}'
SARIF_JSON='{"runs":[]}'

run_script() {  # run_script <results-dir> <rules>; sets RC, output in $WORK/output
  : > "$WORK/output"; : > "$WORK/args.log"
  env -i PATH="$WORK/bin:/usr/bin:/bin" GITHUB_OUTPUT="$WORK/output" STUB_ARGS_LOG="$WORK/args.log" \
    OSDO_RESULTS="$1" OSDO_PATH="$WORK/src" OSDO_RULES="$2" \
    STUB_JSON="${STUB_JSON:-}" STUB_SARIF="${STUB_SARIF:-}" STUB_RC="${STUB_RC:-0}" \
    bash "$ACTION_DIR/scripts/run-semgrep.sh" > "$WORK/stdout" 2>&1
  RC=$?
}

# 1. auto expands to two --config arguments, uses --json --output with --sarif-output,
#    and counts come from the report.
STUB_JSON="$RESULTS_JSON" STUB_SARIF="$SARIF_JSON" run_script "$WORK/r1" auto
if [ "$RC" -eq 0 ] && grep -qx "semgrep-total=3" "$WORK/output" && grep -qx "semgrep-errors=2" "$WORK/output" \
  && grep -qx "semgrep-warnings=1" "$WORK/output" \
  && grep -q -- "--x-ignore-semgrepignore-files" "$WORK/args.log" \
  && grep -q -- "--config p/security-audit --config p/secrets" "$WORK/args.log" \
  && grep -q -- "--json --output" "$WORK/args.log" && grep -q -- "--sarif-output" "$WORK/args.log"; then
  pass "auto ruleset is two --config arguments and counts come from the JSON report"
else
  fail "auto/flags case wrong (rc=$RC)"; cat "$WORK/stdout"; cat "$WORK/args.log"
fi

# 2. Standalone --sarif is never passed (it is mutually exclusive with --json).
if ! grep -qE -- "(^| )--sarif( |$)" "$WORK/args.log"; then
  pass "semgrep is not called with the mutually exclusive --sarif flag"
else
  fail "semgrep was called with --sarif"
fi

# 3. An explicit ruleset is passed as a single --config.
STUB_JSON="$RESULTS_JSON" STUB_SARIF="$SARIF_JSON" run_script "$WORK/r3" "p/python"
if [ "$RC" -eq 0 ] && grep -q -- "--config p/python " "$WORK/args.log"; then
  pass "explicit ruleset is passed as one --config"
else
  fail "explicit ruleset case wrong (rc=$RC)"
fi

# 4. A semgrep failure fails the step, even when a partial report exists.
STUB_JSON="$RESULTS_JSON" STUB_SARIF="$SARIF_JSON" STUB_RC=2 run_script "$WORK/r4" auto
if [ "$RC" -ne 0 ] && grep -q "semgrep scan failed with exit 2" "$WORK/stdout"; then
  pass "semgrep failure fails the step"
else
  fail "semgrep failure did not fail (rc=$RC)"
fi

# 5. A successful run with no JSON report fails instead of reporting zero findings.
STUB_JSON="" STUB_SARIF="$SARIF_JSON" run_script "$WORK/r5" auto
if [ "$RC" -ne 0 ] && grep -q "wrote no JSON report" "$WORK/stdout"; then
  pass "missing JSON report fails the step"
else
  fail "missing JSON report did not fail (rc=$RC)"
fi

# 6. A successful run with no SARIF report fails the step.
STUB_JSON="$RESULTS_JSON" STUB_SARIF="" run_script "$WORK/r6" auto
if [ "$RC" -ne 0 ] && grep -q "wrote no SARIF report" "$WORK/stdout"; then
  pass "missing SARIF report fails the step"
else
  fail "missing SARIF report did not fail (rc=$RC)"
fi

# 7. A report without a results array fails the step.
STUB_JSON='{"errors":[]}' STUB_SARIF="$SARIF_JSON" run_script "$WORK/r7" auto
if [ "$RC" -ne 0 ] && grep -q "no results array" "$WORK/stdout"; then
  pass "report without results array fails the step"
else
  fail "malformed report did not fail (rc=$RC)"
fi

if [ "$failures" -ne 0 ]; then
  echo "$failures osdo-sast test(s) failed"
  exit 1
fi
echo "All osdo-sast tests passed"
