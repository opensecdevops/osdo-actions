#!/usr/bin/env bash
# Tests for the osdo-llm-scan checker (scripts/llm_checks.py) against the
# fixtures in test/fixtures/llm-scan. Needs python3 and shellcheck on PATH.
# Semgrep is not exercised here; it runs in the action step itself.
set -uo pipefail

ACTION_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$ACTION_DIR/../.." && pwd)"
CHECKER="$ACTION_DIR/scripts/llm_checks.py"
FIXTURES="$ROOT/test/fixtures/llm-scan"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

failures=0
pass() { echo "PASS $1"; }
fail() { echo "FAIL $1"; failures=$((failures + 1)); }

has_rule() {  # has_rule <findings-file> <rule-id>
  [ -f "$1" ] && awk -F'\t' -v r="$2" '$3 == r { found = 1 } END { exit !found }' "$1"
}
row_count() { [ -f "$1" ] && wc -l < "$1" | tr -d ' ' || echo 0; }

# Run the checker; sets RC and leaves stdout in $WORK/out.
run() { python3 -I "$CHECKER" "$@" > "$WORK/out" 2> "$WORK/err"; RC=$?; }

# 1. Every check fires on the malicious fixtures.
MAL="$WORK/malicious.tsv"
run scan --source "$FIXTURES/malicious" --findings "$MAL"
expected_rules=(
  prose-ignore-instructions prose-role-override prose-hide-from-user prose-reveal-system-prompt
  prose-chat-template-token prose-hidden-html-comment prose-encoded-injection
  hidden-unicode-tag-chars hidden-zero-width-or-bidi-mark hidden-bidi-override
  mcp-shell-server mcp-inline-secret mcp-non-https-url unparseable-mcp-manifest
  unrestricted-bash tool-wildcard bash-permission-allow
  prompt-fstring-user-input insecure-pickle-deserialization llm-output-to-eval-exec
  pii-field-in-llm-prompt shellcheck:SC2086
)
missing=()
for rule in "${expected_rules[@]}"; do
  has_rule "$MAL" "$rule" || missing+=("$rule")
done
if [ "$RC" -eq 0 ] && [ "${#missing[@]}" -eq 0 ]; then
  pass "malicious fixtures trigger all ${#expected_rules[@]} expected rules"
else
  fail "malicious fixtures missing rules: ${missing[*]:-none} (rc=$RC)"; cat "$WORK/err"
fi

# 2. Clean fixtures produce no findings at all.
CLEAN="$WORK/clean.tsv"
run scan --source "$FIXTURES/clean" --findings "$CLEAN"
if [ "$RC" -eq 0 ] && [ "$(row_count "$CLEAN")" -eq 0 ]; then
  pass "clean fixtures produce zero findings"
else
  fail "clean fixtures produced $(row_count "$CLEAN") finding(s) (rc=$RC)"; cat "$CLEAN" 2>/dev/null
fi

# 3. Each check can be disabled, and disabling one removes only its rules.
NOPROSE="$WORK/noprose.tsv"
OSDO_CHECK_PROSE_INJECTION=false OSDO_CHECK_HIDDEN_UNICODE=true \
  run scan --source "$FIXTURES/malicious" --findings "$NOPROSE"
if [ "$RC" -eq 0 ] && ! has_rule "$NOPROSE" prose-ignore-instructions \
  && has_rule "$NOPROSE" hidden-unicode-tag-chars; then
  pass "OSDO_CHECK_PROSE_INJECTION=false removes prose rules and keeps unicode rules"
else
  fail "disabling prose checks did not isolate them (rc=$RC)"
fi

# 4. Invalid boolean for a check is an error, not a silent default.
OSDO_CHECK_TOOL_SCOPE=yes run scan --source "$FIXTURES/clean" --findings "$WORK/bad.tsv"
if [ "$RC" -eq 2 ]; then
  pass "invalid check flag value exits 2"
else
  fail "invalid check flag value exited $RC, expected 2"
fi

# 5. A missing source directory is an error.
run scan --source "$FIXTURES/does-not-exist" --findings "$WORK/missing.tsv"
if [ "$RC" -eq 2 ] && grep -q "source path is not a directory" "$WORK/err"; then
  pass "missing source directory exits 2"
else
  fail "missing source directory exited $RC, expected 2"
fi

# 6. Without shellcheck, the shell check fails instead of passing silently.
NOSHELLCHECK="$WORK/nobin"
mkdir -p "$NOSHELLCHECK"
ln -s "$(command -v python3)" "$NOSHELLCHECK/python3"
PATH="$NOSHELLCHECK" run scan --source "$FIXTURES/clean" --findings "$WORK/noshell.tsv"
if [ "$RC" -eq 2 ] && grep -q "shellcheck is required" "$WORK/err"; then
  pass "missing shellcheck exits 2 with a reason"
else
  fail "missing shellcheck exited $RC, expected 2"
fi

# 7. An unparseable Semgrep SARIF file is an error.
printf 'not json' > "$WORK/bad.sarif"
run sarif --sarif "$WORK/bad.sarif" --findings "$WORK/sarif-bad.tsv"
if [ "$RC" -eq 2 ]; then
  pass "unparseable SARIF exits 2"
else
  fail "unparseable SARIF exited $RC, expected 2"
fi

# 8. SARIF results map to categories and severities.
cat > "$WORK/ok.sarif" <<'JSON'
{"runs":[{"results":[
  {"ruleId":"semgrep-llm.prompt-injection-risk","level":"error",
   "message":{"text":"user input in prompt"},
   "locations":[{"physicalLocation":{"artifactLocation":{"uri":"app.py"},"region":{"startLine":3}}}]},
  {"ruleId":"python.lang.security.generic","level":"warning","message":{"text":"generic"}}
]}]}
JSON
run sarif --sarif "$WORK/ok.sarif" --findings "$WORK/sarif.tsv"
if [ "$RC" -eq 0 ] \
  && awk -F'\t' '$1 == "LLM01" && $2 == "HIGH" && $3 == "semgrep:semgrep-llm.prompt-injection-risk" && $4 == "app.py:3" { ok = 1 } END { exit !ok }' "$WORK/sarif.tsv" \
  && awk -F'\t' '$1 == "CODE" && $2 == "MEDIUM" { ok = 1 } END { exit !ok }' "$WORK/sarif.tsv"; then
  pass "SARIF results map to LLM01/HIGH and CODE/MEDIUM"
else
  fail "SARIF mapping wrong (rc=$RC)"; cat "$WORK/sarif.tsv" 2>/dev/null
fi

# 9. Provider detection.
PROV="$WORK/provider"
mkdir -p "$PROV" && echo "import openai" > "$PROV/app.py"
run provider --source "$PROV"
if [ "$RC" -eq 0 ] && grep -qx "provider=openai" "$WORK/out"; then
  pass "provider detection reports openai"
else
  fail "provider detection output: $(cat "$WORK/out")"
fi

# 10. Consolidation counts by severity and category and applies the threshold.
printf 'LLM01\tHIGH\tr1\ta:1\tm\nLLM06\tMEDIUM\tr2\ta:2\tm\n' > "$WORK/one.tsv"
run consolidate --findings "$WORK/one.tsv" --threshold HIGH
if [ "$RC" -eq 0 ] && grep -qx "passed=false" "$WORK/out" \
  && grep -qx "vulnerabilities-found=2" "$WORK/out" \
  && grep -qx 'findings-by-category={"CODE": 0, "LLM01": 1, "LLM02": 0, "LLM05": 0, "LLM06": 1, "LLM07": 0, "LLM08": 0, "SHELL": 0}' "$WORK/out"; then
  pass "consolidate: HIGH threshold fails on a HIGH finding and counts by category"
else
  fail "consolidate HIGH threshold output wrong"; cat "$WORK/out"
fi

run consolidate --findings "$WORK/one.tsv" --threshold CRITICAL
if [ "$RC" -eq 0 ] && grep -qx "passed=true" "$WORK/out"; then
  pass "consolidate: CRITICAL threshold passes with only HIGH and MEDIUM findings"
else
  fail "consolidate CRITICAL threshold wrong"
fi

run consolidate --findings "$WORK/one.tsv" --threshold NONE
if [ "$RC" -eq 2 ]; then
  pass "consolidate rejects an unknown threshold"
else
  fail "consolidate accepted an unknown threshold (rc=$RC)"
fi

# 10b. A missing findings file must not read as a clean scan.
run consolidate --findings "$WORK/never-written.tsv" --threshold HIGH
if [ "$RC" -eq 2 ] && ! grep -q "passed=true" "$WORK/out"; then
  pass "consolidate fails closed when the findings file is missing"
else
  fail "consolidate accepted a missing findings file (rc=$RC)"
fi

# 11. A PII finding blocks the gate (it is consolidated, not ignored).
run scan --source "$FIXTURES/malicious/app" --findings "$WORK/pii.tsv"
run consolidate --findings "$WORK/pii.tsv" --threshold HIGH
if grep -qx "passed=false" "$WORK/out" && grep -q "^LLM06" "$WORK/pii.tsv"; then
  pass "PII findings are included in the consolidated gate"
else
  fail "PII finding did not affect the gate"
fi

if [ "$failures" -ne 0 ]; then
  echo "$failures osdo-llm-scan test(s) failed"
  exit 1
fi
echo "All osdo-llm-scan tests passed"
