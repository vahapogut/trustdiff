# Security policy

trustdiff reads untrusted input by design: lockfiles from pull requests, metadata from public registries, configuration files in repositories it audits. A bug that turns any of that into code execution, into a finding that is hidden or reported as a pass, or into a write outside the intended file is a security issue. Please report it privately.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability.

1. Preferred: GitHub private vulnerability reporting on this repository, at <https://github.com/vahapogut/trustdiff/security/advisories/new>. The report is visible only to you and the maintainer.
2. Fallback: email <vahapogut@gmail.com> with "trustdiff security" in the subject line. If you want to encrypt the details, send a first message without them and ask for a key.

The maintainer (@vahapogut) is the only person who reads these reports.

### What to include

- The output of `trustdiff version`, or the commit you built from, and your operating system.
- The exact command line, the policy file if one was used, and the input that triggers the problem: a package ref, a lockfile, a repository layout, or a recorded registry response. A minimal reproduction in the style of the fixtures under `testdata/` is ideal. Never include a real credential or token.
- What happened, what should have happened, and the impact you see: code execution, a finding that was hidden or shown as a pass, a file written outside the target, data leaving the machine.
- Whether the problem is already public somewhere.

### What counts

In scope: anything reachable from the inputs trustdiff processes (registry and advisory responses, lockfiles, manifests, policy files, package manager configuration, git refs given on the command line, the disk cache), and the release pipeline (a way to bypass signing, provenance or checksums, or to tamper with a build dependency).

Out of scope: vulnerabilities in the packages trustdiff reports on (report those to the package or to OSV), and findings trustdiff misses because a registry does not expose the data. Those are ordinary bugs; open an issue. A check that reports a pass for data it never evaluated is in scope.

## Response targets

- Acknowledgement within 3 days of the report.
- For a confirmed issue, a fix or a written mitigation plan with a date within 14 days. Fixes ship as a patch release of the latest minor line, with a GitHub security advisory and a Security entry in `CHANGELOG.md`.
- Coordinated disclosure: please keep the details private until the fix is released or 90 days have passed, whichever comes first. You are credited in the advisory and the changelog unless you ask not to be.

There is no bug bounty. The project cannot pay for reports; it can thank you and credit you.

## Supported versions

During 0.x only the latest minor release line receives security fixes, as a patch release of that line. Earlier minors are not patched; upgrade to the latest release.

| Version | Supported |
|---|---|
| Latest 0.N.x | Yes |
| Earlier 0.x lines | No |

`go install github.com/vahapogut/trustdiff/cmd/trustdiff@latest` builds the latest tag.

## How this project protects itself

- No telemetry, no auto-update, no analytics, no phone-home of any kind. The only network calls are the registry and advisory requests needed for the packages you ask about, and `--offline` turns those off.
- Standard library first. Six third-party modules are allowed (`github.com/spf13/cobra`, `go.yaml.in/yaml/v3`, `github.com/BurntSushi/toml`, `golang.org/x/term`, `golang.org/x/time`, `golang.org/x/mod`) and CI fails when the direct dependency count exceeds six. CGO is disabled.
- Every GitHub Action is pinned to a full 40-character commit SHA. Build provenance comes from GitHub's native attestation action rather than a reusable workflow that must be referenced by tag, so the pin rule has no exception.
- Dependabot watches Go modules and GitHub Actions with a 7 day cooldown, so a version that gets pulled shortly after publication is never proposed here.
- CI runs `govulncheck`, `gosec` and `golangci-lint` on every push and pull request, plus a binary size gate.
- Reproducible builds: goreleaser with `-trimpath`, `CGO_ENABLED=0`, `-ldflags=-s -w`, `-buildvcs=false` and `SOURCE_DATE_EPOCH` taken from the commit, so the six archives can be rebuilt and compared byte for byte. The same tag was built twice, hours apart, and all six came out identical. The SPDX documents are not reproducible, and `checksums.txt` is not either because it hashes them: every SPDX document carries a `documentNamespace` that has to be unique to that document and a `created` timestamp, so two runs of syft over the same bytes produce different documents by design. The archive lines inside `checksums.txt` do not change, and cosign signs the `checksums.txt` a run publishes, so the SPDX documents that run wrote are covered by its signature. The release job installs the exact Go version `go.mod` names in its `toolchain` directive, with no `check-latest`, because a floating patch release would have made the byte for byte claim false the moment a new one shipped: the same tag rebuilt a month later would have been built by a different compiler. The other jobs float forward on purpose, so `govulncheck` reads the newest standard library rather than the one this pin freezes.
- The signing identity is `release.yml@refs/tags/v*`, so whoever can push a `v*` tag can produce a release that verifies. `docs/releasing.md` section 7 says how to restrict tag creation and put a required reviewer on the release job; those are repository settings rather than files, so read that section rather than assuming they are in place.
- Releases are built only by the tag-triggered release workflow (`.github/workflows/release.yml`). `contents: write`, `id-token: write` and `attestations: write` are granted to the release job alone; the workflow default is `contents: read`. Artifacts are signed with cosign (keyless, Sigstore, bundle format), attested with GitHub build provenance, listed in `checksums.txt` and accompanied by an SPDX SBOM per archive.
- Secret scanning and push protection are enabled on the repository.

## Verifying a download

Every release publishes `checksums.txt`, its cosign bundle `checksums.txt.sigstore.json`, one archive per platform (`trustdiff_<version>_<os>_<arch>.tar.gz`, `.zip` on Windows) and an SPDX SBOM next to each archive. Download the archive for your platform together with the two checksum files, then run the three steps below from the download directory. Substitute the archive name you downloaded for `trustdiff_0.5.2_linux_amd64.tar.gz`.

1. Verify the signature on the checksum file. This needs cosign v3 or later. The identity is the release workflow of this repository, running on a version tag.

   ```sh
   cosign verify-blob \
     --bundle checksums.txt.sigstore.json \
     --certificate-identity-regexp '^https://github\.com/vahapogut/trustdiff/\.github/workflows/release\.yml@refs/tags/v' \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com \
     checksums.txt
   ```

2. Verify the archive against the signed checksum file.

   ```sh
   sha256sum --check --ignore-missing checksums.txt          # Linux
   shasum -a 256 --check --ignore-missing checksums.txt      # macOS
   ```

   On Windows, compare the two outputs by eye:

   ```powershell
   (Get-FileHash .\trustdiff_0.5.2_windows_amd64.zip -Algorithm SHA256).Hash
   Select-String windows_amd64 .\checksums.txt
   ```

3. Verify the build provenance with the GitHub CLI. This confirms the archive was built by this repository's release workflow from the tagged commit.

   ```sh
   gh attestation verify trustdiff_0.5.2_linux_amd64.tar.gz \
     --owner vahapogut \
     --signer-workflow vahapogut/trustdiff/.github/workflows/release.yml
   ```

If any step fails, do not run the binary, and report it through the channels above.
