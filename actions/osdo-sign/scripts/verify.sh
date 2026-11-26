#!/usr/bin/env bash
# Verifies each bundle against the artifact it covers, pinned to the expected
# certificate identity and OIDC issuer. Any failure fails the step.
set -euo pipefail

fail() {
  echo "::error::osdo-sign verify: $*" >&2
  exit 1
}

[ -n "${OSDO_IDENTITY_RE:-}" ] || fail "certificate-identity-regexp is required for verification"
[ -n "${OSDO_ISSUER:-}" ] || fail "certificate-oidc-issuer must not be empty"
[ -n "${OSDO_BUNDLES:-}" ] || fail "no bundles to verify"
command -v cosign >/dev/null 2>&1 || fail "cosign not found on PATH"

verified=true
while IFS= read -r bundle; do
  [ -n "$bundle" ] || continue
  artifact="${bundle%.sigstore.json}"
  [ -f "$artifact" ] || fail "artifact missing for bundle $bundle"
  if cosign verify-blob \
      --bundle "$bundle" \
      --certificate-identity-regexp "$OSDO_IDENTITY_RE" \
      --certificate-oidc-issuer "$OSDO_ISSUER" \
      "$artifact"; then
    echo "verified $artifact"
  else
    echo "::error::signature verification failed for $artifact"
    verified=false
  fi
done <<< "$OSDO_BUNDLES"

{
  echo "verified=$verified"
} >> "${GITHUB_OUTPUT:-/dev/stdout}"

[ "$verified" = "true" ] || exit 1
