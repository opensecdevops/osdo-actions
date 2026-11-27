#!/usr/bin/env bash
# Runs osv-scanner and records counts in $GITHUB_OUTPUT.
#
# Exit codes handled: 0 (no vulnerabilities) and 1 (vulnerabilities; report written)
# are normal. Exit 128 with "No package sources found" means the tree has no
# supported manifests: a clean result with zero findings and an explicit notice.
# Any other failure fails the step, and so does a success without a report.
set -euo pipefail

fail() {
  echo "::error::$*" >&2
  exit 1
}

: "${OSDO_RESULTS:?OSDO_RESULTS is required}"
: "${OSDO_SCAN_PATH:?OSDO_SCAN_PATH is required}"
command -v osv-scanner > /dev/null 2>&1 || fail "osv-scanner is not on PATH"
command -v jq > /dev/null 2>&1 || fail "jq is required to read the osv-scanner report"

mkdir -p "$OSDO_RESULTS/sca"
json="$OSDO_RESULTS/sca/osv.json"
log="$OSDO_RESULTS/sca/osv.log"
rm -f "$json" "$log"

set +e
osv-scanner --format json --output "$json" -r "$OSDO_SCAN_PATH" > "$log" 2>&1
rc=$?
set -e

no_sources=false
case "$rc" in
  0|1) ;;
  128)
    if grep -q "No package sources found" "$log"; then
      no_sources=true
      echo "::notice title=OSV-Scanner::No package sources found under $OSDO_SCAN_PATH. Nothing to check; counted as zero findings."
    else
      cat "$log" >&2
      fail "osv-scanner exited 128 without the 'No package sources found' message"
    fi
    ;;
  *)
    cat "$log" >&2
    fail "osv-scanner failed with exit $rc"
    ;;
esac

if [ "$no_sources" = true ]; then
  total=0
  critical=0
  high=0
else
  [ -s "$json" ] || fail "osv-scanner exited $rc but wrote no report to $json"
  jq -e 'type == "object"' "$json" > /dev/null || fail "osv-scanner report is not a JSON object"
  total="$(jq '[.results[]?.packages[]?] | length' "$json")"
  critical="$(jq '[.results[]?.packages[]?.vulnerabilities[]? | select(.database_specific.severity == "CRITICAL" or (.severity[]?.score // 0) >= 9.0)] | length' "$json")"
  high="$(jq '[.results[]?.packages[]?.vulnerabilities[]? | select(.database_specific.severity == "HIGH" or ((.severity[]?.score // 0) >= 7.0 and (.severity[]?.score // 0) < 9.0))] | length' "$json")"
fi

{
  echo "osv-total=$total"
  echo "osv-critical=$critical"
  echo "osv-high=$high"
  echo "osv-no-sources=$no_sources"
} >> "${GITHUB_OUTPUT:-/dev/stdout}"
echo "📊 OSV-Scanner found: $total vulnerable packages ($critical critical, $high high)"
