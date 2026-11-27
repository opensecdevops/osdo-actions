#!/usr/bin/env bash
# Tests for osdo-sign scripts using a stub cosign on PATH, so no Sigstore
# service or cosign binary is needed. Checks the exact arguments passed to
# cosign, the fail-closed guards, and that verification failures fail the step.
set -uo pipefail

ACTION_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

failures=0
pass() { echo "PASS $1"; }
fail() { echo "FAIL $1"; failures=$((failures + 1)); }

# Stub cosign: logs its arguments; writes a bundle for sign-blob; fails
# verify-blob when the blob name contains "tampered".
mkdir -p "$WORK/bin"
cat > "$WORK/bin/cosign" <<'STUB'
#!/usr/bin/env bash
echo "$*" >> "$COSIGN_LOG"
case "$1" in
  sign-blob)
    bundle="" 
    while [ $# -gt 0 ]; do
      case "$1" in --bundle) bundle="$2"; shift ;; esac
      shift
    done
    [ -n "$bundle" ] && echo '{"stub":true}' > "$bundle"
    ;;
  verify-blob)
    case "$*" in *tampered*) exit 1 ;; esac
    ;;
esac
exit 0
STUB
chmod +x "$WORK/bin/cosign"

run_script() {
  # usage: run_script <script> <env assignments...>; sets RC to the exit code
  local script="$1"; shift
  : > "$WORK/cosign.log"
  : > "$WORK/output"
  env -i PATH="$WORK/bin:/usr/bin:/bin" COSIGN_LOG="$WORK/cosign.log" \
    GITHUB_OUTPUT="$WORK/output" ACTIONS_ID_TOKEN_REQUEST_URL="https://token.example" \
    "$@" bash "$ACTION_DIR/scripts/$script" > "$WORK/stdout" 2>&1
  RC=$?
}

cd "$WORK" || exit 1
echo "firmware" > app.bin
echo "chart" > chart.tgz
echo "tampered" > tampered.bin

# 1. Signs every artifact with the expected cosign arguments.
run_script sign.sh OSDO_METHOD=cosign OSDO_VERIFY=false OSDO_ARTIFACTS=$'app.bin\nchart.tgz'
if [ "$RC" -eq 0 ] \
  && grep -qx "sign-blob --yes --bundle app.bin.sigstore.json app.bin" "$WORK/cosign.log" \
  && grep -qx "sign-blob --yes --bundle chart.tgz.sigstore.json chart.tgz" "$WORK/cosign.log" \
  && grep -q "app.bin.sigstore.json" "$WORK/output"; then
  pass "sign.sh signs each artifact with --yes --bundle and publishes bundle paths"
else
  fail "sign.sh signs each artifact with --yes --bundle and publishes bundle paths"
  cat "$WORK/stdout"
fi

# 2. Refuses to run without an OIDC token (no secrets fallback).
run_script sign.sh OSDO_METHOD=cosign OSDO_VERIFY=false OSDO_ARTIFACTS=app.bin ACTIONS_ID_TOKEN_REQUEST_URL=
if [ "$RC" -ne 0 ] && grep -q "id-token: write" "$WORK/stdout" && [ ! -s "$WORK/cosign.log" ]; then
  pass "sign.sh fails without id-token and never calls cosign"
else
  fail "sign.sh fails without id-token and never calls cosign"
fi

# 3. Refuses verification without a certificate identity, before signing.
run_script sign.sh OSDO_METHOD=cosign OSDO_VERIFY=true OSDO_IDENTITY_RE= OSDO_ARTIFACTS=app.bin
if [ "$RC" -ne 0 ] && [ ! -s "$WORK/cosign.log" ]; then
  pass "sign.sh requires certificate-identity-regexp when verify is true"
else
  fail "sign.sh requires certificate-identity-regexp when verify is true"
fi

# 4. Rejects methods other than keyless cosign.
run_script sign.sh OSDO_METHOD=gpg OSDO_VERIFY=false OSDO_ARTIFACTS=app.bin
if [ "$RC" -ne 0 ] && [ ! -s "$WORK/cosign.log" ]; then
  pass "sign.sh rejects unsupported method"
else
  fail "sign.sh rejects unsupported method"
fi

# 5. A missing artifact fails the step.
run_script sign.sh OSDO_METHOD=cosign OSDO_VERIFY=false OSDO_ARTIFACTS=missing.bin
if [ "$RC" -ne 0 ]; then
  pass "sign.sh fails on a missing artifact"
else
  fail "sign.sh fails on a missing artifact"
fi

# 6. verify.sh passes the identity regexp and issuer to cosign.
run_script sign.sh OSDO_METHOD=cosign OSDO_VERIFY=false OSDO_ARTIFACTS=app.bin
run_script verify.sh OSDO_IDENTITY_RE='^https://github.com/org/repo/\.github/workflows/release\.yml@refs/tags/v.*$' \
  OSDO_ISSUER=https://token.actions.githubusercontent.com OSDO_BUNDLES=app.bin.sigstore.json
if [ "$RC" -eq 0 ] && grep -qF -- "--certificate-identity-regexp ^https://github.com/org/repo/" "$WORK/cosign.log" \
  && grep -qF -- "--certificate-oidc-issuer https://token.actions.githubusercontent.com" "$WORK/cosign.log" \
  && grep -qF -- "verify-blob --bundle app.bin.sigstore.json" "$WORK/cosign.log" \
  && grep -q "verified=true" "$WORK/output"; then
  pass "verify.sh checks identity regexp and issuer and reports verified=true"
else
  fail "verify.sh checks identity regexp and issuer and reports verified=true"
  cat "$WORK/stdout"
fi

# 7. verify.sh requires an identity regexp.
run_script verify.sh OSDO_IDENTITY_RE= OSDO_ISSUER=https://token.actions.githubusercontent.com OSDO_BUNDLES=app.bin.sigstore.json
if [ "$RC" -ne 0 ]; then
  pass "verify.sh requires certificate-identity-regexp"
else
  fail "verify.sh requires certificate-identity-regexp"
fi

# 8. A failed verification fails the step and reports verified=false.
run_script sign.sh OSDO_METHOD=cosign OSDO_VERIFY=false OSDO_ARTIFACTS=tampered.bin
run_script verify.sh OSDO_IDENTITY_RE='.*' OSDO_ISSUER=https://token.actions.githubusercontent.com OSDO_BUNDLES=tampered.bin.sigstore.json
if [ "$RC" -ne 0 ] && grep -q "verified=false" "$WORK/output"; then
  pass "verify.sh fails the step when a bundle does not verify"
else
  fail "verify.sh fails the step when a bundle does not verify"
fi

if [ "$failures" -ne 0 ]; then
  echo "$failures osdo-sign test(s) failed"
  exit 1
fi
echo "All osdo-sign tests passed"
