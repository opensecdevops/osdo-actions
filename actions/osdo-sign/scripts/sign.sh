#!/usr/bin/env bash
# Keyless cosign signing. Writes <artifact>.sigstore.json next to each artifact
# and publishes the bundle paths as the `bundle-paths` step output.
set -euo pipefail

fail() {
  echo "::error::osdo-sign: $*" >&2
  exit 1
}

[ "${OSDO_METHOD:-cosign}" = "cosign" ] \
  || fail "unsupported method '${OSDO_METHOD}': only keyless cosign is supported"

[ -n "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ] \
  || fail "no OIDC token available. Add 'permissions: id-token: write' to the job; keyless signing needs it."

if [ "${OSDO_VERIFY:-true}" = "true" ] && [ -z "${OSDO_IDENTITY_RE:-}" ]; then
  fail "certificate-identity-regexp is required when verify is true. Set it, or set verify: 'false' explicitly."
fi

command -v cosign >/dev/null 2>&1 || fail "cosign not found on PATH"

bundles=()
while IFS= read -r artifact; do
  artifact="${artifact%$'\r'}"
  case "$artifact" in
    ""|\#*) continue ;;
  esac
  [ -f "$artifact" ] || fail "artifact not found: $artifact"
  bundle="${artifact}.sigstore.json"
  cosign sign-blob --yes --bundle "$bundle" "$artifact" \
    || fail "cosign sign-blob failed for $artifact"
  [ -s "$bundle" ] || fail "cosign did not write bundle $bundle"
  bundles+=("$bundle")
  echo "signed $artifact -> $bundle"
done <<< "${OSDO_ARTIFACTS:-}"

[ "${#bundles[@]}" -gt 0 ] || fail "no artifacts given in the artifact input"

{
  echo "bundle-paths<<OSDO_BUNDLES_EOF"
  printf '%s\n' "${bundles[@]}"
  echo "OSDO_BUNDLES_EOF"
} >> "${GITHUB_OUTPUT:-/dev/stdout}"
