# Releasing OSDO Actions

## Versioning

- Releases use repository-level tags `vMAJOR.MINOR.PATCH` (semver).
- Tags are immutable. They are never moved, deleted or re-pointed. To fix a
  released version, publish a new patch version.
- Each release has a GitHub release generated from the tagged commit.

## Cutting a release (maintainers)

1. Confirm the commit on `main` has passing CI.
2. Go to Actions, then "Release (manual)", then "Run workflow" on `main`, and
   enter `version` as `vX.Y.Z`.
3. The workflow creates the tag on that commit and the GitHub release. It fails
   if the tag already exists, and it refuses to run on any branch other than
   `main`.

## Consuming the actions (pin by tag and SHA)

Reference each action by its full 40-character commit SHA, and keep the tag in
a comment so the pin stays readable:

```yaml
- uses: opensecdevops/osdo-actions/actions/osdo-sast@<full-40-char-commit-sha> # v1.2.0
```

Resolve a release tag to its commit SHA:

```sh
git ls-remote --tags https://github.com/opensecdevops/osdo-actions.git refs/tags/v1.2.0
```

Release tags are lightweight tags, so the SHA printed is the commit to pin.
Dependabot or Renovate can update the pin when a new tag is published.

## Relationship to the existing per-action tags

`.github/workflows/publish.yml` also creates per-action tags of the form
`<action>/vX.Y.Z` when `actions/**` changes on `main`, and supports manual
dispatch. These tags remain valid. Consumers that want the single
repository-level version should pin the `vX.Y.Z` tags described above.

## Known gap

`.github/workflows/release.yml` (SBOM generation and attestation) runs on tag
pushes. Tags created by "Release (manual)" use `GITHUB_TOKEN`, and GitHub does
not start workflows for events caused by `GITHUB_TOKEN`, so that SBOM step does
not run for these releases. This needs a maintainer decision.
