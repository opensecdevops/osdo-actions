#!/usr/bin/env bash
# Runs Slither and records finding counts. Succeeds only when Slither wrote a
# successful JSON report. Slither exits 255 when it reports findings, so its exit
# code alone is not used; a compile or import failure leaves no report and fails.
set -euo pipefail

fail() {
  echo "::error::$*" >&2
  exit 1
}

: "${OSDO_RESULTS:?OSDO_RESULTS is required}"
: "${OSDO_CONTRACTS:?OSDO_CONTRACTS is required}"

echo "🔍 Running Slither static analysis..."
if ! command -v slither > /dev/null 2>&1; then
  pip install "slither-analyzer==0.11.6"
fi
command -v jq > /dev/null 2>&1 || fail "jq is required to read the Slither report"

mkdir -p "$OSDO_RESULTS"
json="$OSDO_RESULTS/slither.json"
sarif="$OSDO_RESULTS/slither.sarif"
log="$OSDO_RESULTS/slither.log"
rm -f "$json" "$sarif" "$log"

set +e
slither "$OSDO_CONTRACTS" --sarif "$sarif" --json "$json" \
  --solc-remaps "@openzeppelin=node_modules/@openzeppelin" > "$log" 2>&1
rc=$?
set -e

if [ ! -s "$json" ] || [ "$(jq -r '.success' "$json" 2>/dev/null)" != "true" ]; then
  if [ -f "$log" ]; then cat "$log" >&2; fi
  fail "Slither did not produce a successful report (exit $rc). Compiler or import errors are the usual cause."
fi

critical="$(jq '[(.results.detectors // [])[] | select(.impact == "High" and .confidence == "High")] | length' "$json")"
high="$(jq '[(.results.detectors // [])[] | select(.impact == "High")] | length' "$json")"
{
  echo "critical=$critical"
  echo "high=$high"
  echo "sarif=$sarif"
} >> "${GITHUB_OUTPUT:-/dev/stdout}"
echo "✅ Slither analysis complete (exit $rc, critical=$critical, high=$high)"
