#!/usr/bin/env bash
# Runs Semgrep and records finding counts in $GITHUB_OUTPUT.
#
# Output uses --json --output plus --sarif-output. Semgrep rejects --json together
# with --sarif. A run counts only if both reports were written and are valid JSON;
# a missing report is a failure, never a zero count.
set -euo pipefail

fail() {
  echo "::error::$*" >&2
  exit 1
}

: "${OSDO_RESULTS:?OSDO_RESULTS is required}"
: "${OSDO_PATH:?OSDO_PATH is required}"
: "${OSDO_RULES:?OSDO_RULES is required}"
command -v semgrep > /dev/null 2>&1 || fail "semgrep is not on PATH"
command -v jq > /dev/null 2>&1 || fail "jq is required to read the semgrep report"

# "auto" expands to the default rulesets. Each ruleset is its own --config argument.
rules="$OSDO_RULES"
if [ "$rules" = "auto" ]; then
  rules="p/security-audit p/secrets"
fi
configs=()
for cfg in $rules; do
  configs+=(--config "$cfg")
done
[ "${#configs[@]}" -gt 0 ] || fail "no semgrep rulesets given"

mkdir -p "$OSDO_RESULTS/sast"
json="$OSDO_RESULTS/sast/semgrep.json"
sarif="$OSDO_RESULTS/sast/semgrep.sarif"
rm -f "$json" "$sarif"

set +e
# --x-ignore-semgrepignore-files stops semgrep's built-in .semgrepignore defaults from
# silently skipping test/ and fixture directories. Without it, a repository that keeps
# code under those names gets zero files scanned and a clean-looking result. The flag is
# internal to semgrep, so the version is pinned in the action and the E2E test checks
# that a vulnerable file under test/ is still reported.
semgrep scan --x-ignore-semgrepignore-files "${configs[@]}" --json --output "$json" --sarif-output "$sarif" "$OSDO_PATH"
rc=$?
set -e
[ "$rc" -eq 0 ] || fail "semgrep scan failed with exit $rc"

[ -s "$json" ] || fail "semgrep wrote no JSON report to $json"
[ -s "$sarif" ] || fail "semgrep wrote no SARIF report to $sarif"
jq -e 'type == "object" and (.results | type == "array")' "$json" > /dev/null \
  || fail "semgrep JSON report has no results array"

total="$(jq '.results | length' "$json")"
errors="$(jq '[.results[] | select(.extra.severity == "ERROR")] | length' "$json")"
warnings="$(jq '[.results[] | select(.extra.severity == "WARNING")] | length' "$json")"

{
  echo "semgrep-total=$total"
  echo "semgrep-errors=$errors"
  echo "semgrep-warnings=$warnings"
} >> "${GITHUB_OUTPUT:-/dev/stdout}"
echo "📊 Semgrep found: $total findings ($errors errors, $warnings warnings)"
