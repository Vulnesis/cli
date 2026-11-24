# Publishing & Distribution

How releases are built and published. Installing a release is documented at **[docs.vulnes.is/cli/get-started/install](https://docs.vulnes.is/cli/get-started/install/)**.

## Distribution Channels

| Method | Automation | Installation |
|--------|-----------|-------------|
| GitHub Releases | Automated on tags | Direct binary download |
| Go Install | Automated | `go install github.com/vulnetix/cli/v4@latest` |
| Homebrew Tap | Follows the Latest release (tap's `follow-releases.yml`, twice an hour, after the canary) | `brew install vulnetix/tap/vulnetix` |
| Scoop Bucket | Follows the Latest release (bucket's `follow-releases.yml`, twice an hour, after the canary) | `scoop install vulnetix` |
| Nix Flake | Auto-merge PR from the release | `nix profile install github:Vulnesis/cli` |
| GitHub Actions | In-repo | `uses: Vulnesis/cli@v4` (the major tag moves to each newest release of that major; the action installs the newest release of the same major by default) |

See [Install](https://docs.vulnes.is/cli/get-started/install/) for every channel's install steps.

## Majors, Latest and the package managers

`release.yml` publishes every tag it is given, but only the newest stable tag
across every major becomes the GitHub Latest release, moves its major tag
(`MAJOR=${VERSION%%.*}`, so `v3` or `v4`) and opens the flake bump. Once v4
ships, a v3 patch release is still published with its binaries, but the `v3`
tag, Latest and the package managers stay where they are, so
`uses: Vulnesis/cli@v3` keeps its last v3 release and nothing rolls back.

## Permissions

Every job uses this repository's `GITHUB_TOKEN` with an explicit `permissions:`
block, and no job holds a token for another repository:

- **Go modules.** `vdb-sca-match` and `vdb-manifest` are public modules under
  `github.com/Vulnesis/*`, so the builds fetch them through the module proxy
  with no `GOPRIVATE` and no token.
- **Binaries between jobs.** They pass as Actions artifacts (`cross-binaries`,
  `darwin-binaries`, kept for a day). They used to go through an S3 stage on the
  Vulnetix AWS account, whose role does not trust Vulnesis repositories (the
  v4.25.0 release failed there).
- **The flake.** `main` takes changes only through a pull request (ruleset
  `protect-main`), so `update-flake` pushes `chore/flake-<version>`, opens a PR
  with `pull-requests: write` and turns on auto-merge. If auto-merge is not
  available, the PR waits for a merge by hand.
- **Homebrew and Scoop.** `Vulnesis/homebrew-tap` and `Vulnesis/scoop-bucket`
  each run `follow-releases.yml` at :07 and :37 with their own token. It moves
  `vulnetix` to the Latest release once that release run's `canary` job has
  passed, and never moves it back. To pick up a release sooner, run
  `gh workflow run follow-releases.yml -R Vulnesis/homebrew-tap` (and the same
  for `Vulnesis/scoop-bucket`).

The Go module path in the build ldflags, the `go install` test and the TEA
channel is read from `go.mod` (`go list -m`), so a major bump needs no edit to
the workflow.

## Build provenance and TEA

Every release carries signed SLSA v1 provenance, `provenance.sigstore.json`,
and is published to the Transparency Exchange API. The `provenance` job calls
`.github/workflows/slsa-provenance.yml`, which belai's release workflow calls
too. It signs one statement whose subjects are every line of the release's
`checksums.txt` plus `checksums.txt` itself, verifies the bundle, and uploads it
to the release. `publish-tea` then attaches it to the TEA release as an
attestation, beside the SBOM and the distributions.

Both repositories are public, so the bundle carries a Rekor entry. The signing
identity is the reusable workflow, not the caller. The statement is signed
provenance of the build workflow on this organisation's runners (the
`runner_environment` field says so); it is not an isolated builder, so it is not
SLSA Build L3.

A public TEA product cannot be unpublished, so `publish-tea` waits for the
bundle: it runs only when `provenance` succeeded (and, for the newest release,
when `update-flake` did, which needs the canary, which needs provenance).
A failed `provenance` job is re-run (`gh run rerun <run-id> --failed`), and
everything after it runs again.

Release assets are uploaded by release id (`scripts/release-asset-upload.sh`),
never with `gh release upload <tag>`. The uploads use the job's `GITHUB_TOKEN`,
whose REST quota is the repository installation's, shared with every scan on
the same push. When it is spent, gh's lookup of a release by tag prints
`release not found` for a published release (it prefers that answer when its
REST lookup and its GraphQL draft lookup both fail, cli/cli#13723), which
failed v4.24.8, v4.24.32 and v4.24.34. The script resolves the id over
GraphQL, which has its own quota, waits for a spent REST quota to reset (up to
65 minutes) and honours `Retry-After`, and every error names its HTTP status.

Preview a release before publishing it. Do not re-dispatch an existing tag for
that: it rebuilds the binaries and replaces the release assets. Run the CLI
locally against the release's own checksums instead; `--dry-run` publishes
nothing:

```sh
gh release download vX.Y.Z --repo Vulnesis/cli --pattern checksums.txt
vulnetix tea release vulnetix.cdx.json provenance.sigstore.json --dry-run \
  --version vX.Y.Z --product Vulnesis/cli \
  --checksums checksums.txt --exclude checksums.txt \
  --base-url https://github.com/Vulnesis/cli/releases/download/vX.Y.Z
```

Verify a downloaded binary against the bundle (use `Vulnesis/belai` for belai):

```sh
gh release download vX.Y.Z --repo Vulnesis/cli --pattern provenance.sigstore.json --pattern 'vulnetix-linux-amd64'
cosign verify-blob-attestation \
  --bundle provenance.sigstore.json --new-bundle-format \
  --type slsaprovenance1 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/Vulnesis/cli/\.github/workflows/slsa-provenance\.yml@' \
  --digest "$(sha256sum vulnetix-linux-amd64 | cut -d' ' -f1)" --digestAlg sha256
```

## Recovering a tag with no Release

`auto-version.yml` creates the tag and then dispatches `release.yml`, because a
tag pushed with `GITHUB_TOKEN` does not itself trigger another workflow. If the
`release` job then fails — most often *"The job was not acquired by Runner of
type hosted"*, a GitHub runner-allocation flake — the tag exists but no Release
is published, and `test-go-install` and `update-flake` are skipped. Homebrew,
Scoop and Nix stay on the previous version. The same happens when the dispatch
itself fails: v4.25.0 to v4.26.1 were tagged on 2026-11-21 to 2026-11-23 with no
release, because the runner had no `gh`. Only the newest such tag needs a
release, since it carries every earlier change.

Re-dispatch for that exact tag. The "Create or update Release" step is
idempotent: it creates the tag if missing, and uploads with `--clobber` when the
release already exists.

```sh
gh workflow run release.yml -f version=vX.Y.Z
gh run watch "$(gh run list --workflow=release.yml -L1 --json databaseId -q '.[0].databaseId')"
gh release view vX.Y.Z --json assets -q '.assets[].name'
```

If only the package-manager fan-out failed, mirror it locally instead — this is
what the `update-packages` job does:

```sh
just update-packages vX.Y.Z
```

Every job now carries a `timeout-minutes`, so a stuck runner fails in minutes
rather than blocking a release for forty.
