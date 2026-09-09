# Releasing trustdiff

A release is one annotated git tag. Everything that follows the tag is done by
`.github/workflows/release.yml`, which is the only job in this repository allowed
to write releases. Nobody builds a release on a laptop and uploads it.

Read this page top to bottom the first time. The steps that need a human are
marked **manual**; there are five of them and three are one-time setup for the
Homebrew tap and the Scoop bucket.

Pinned versions live in `tools.mk` and are repeated in the release workflow:
goreleaser v2.18.1, cosign v3.1.3, syft v1.51.1. Bump them in `tools.mk` first,
then in the workflow, never only in one place.

## 1. Before the tag

Run these on the commit you intend to tag, with the working tree clean.

1. `make lint`, `make vet`, `make test`, `make vuln`, `make sec`. The CI
   workflow runs the same set plus the cross-platform test matrix, the binary
   size budget and the direct dependency budget; wait for it to be green on the
   commit rather than tagging on top of a red one.
2. `make test-integration` at least once. It hits the live registries, so CI
   does not run it on every push, and a release is the moment to know that the
   adapters still agree with what the registries return.
3. `goreleaser check`. It validates `.goreleaser.yaml` against the pinned
   goreleaser and fails on any key that version has deprecated, which is how a
   configuration that still works today but will break on the next bump gets
   caught before the tag rather than after it.
4. `make snapshot`. This is `goreleaser release --snapshot --clean
   --skip=sign,publish,sbom`: the full build with no signing, no SBOM and no
   upload, and it needs neither cosign nor syft nor a token. Look in `dist/` for
   six archives, `checksums.txt`, `homebrew/Casks/trustdiff.rb` and
   `scoop/bucket/trustdiff.json`. Unpack one archive and run the binary.
5. `make demo` still prints what `docs/demo-repo.md` says it prints.
6. **Manual.** `CHANGELOG.md`: move the entries under `Unreleased` to a new
   `## [X.Y.Z] - YYYY-MM-DD` heading, leave `Unreleased` empty, and update the
   link definitions at the bottom of the file.
7. **Manual.** `README.md`: the version sentence near the top, and the archive
   names used as examples in the Install section, name the release that is about
   to exist.
8. Commit the changelog and readme edits as `chore(release): X.Y.Z`.

`action.yml` is *not* touched here. Its pinned version and its sha256 table can
only be filled in after the archives exist, which is step 5 below.

## 2. The tag

**Manual.** The tag is annotated, and its name is the version with a leading
`v`.

```sh
git tag -a v0.4.0 -m "trustdiff v0.4.0"
git push origin v0.4.0
```

A tag with a suffix, for example `v0.4.0-rc.1`, is a prerelease. goreleaser
marks the GitHub release as a prerelease on its own because `release.prerelease`
is `auto`, and for the same reason it leaves the Homebrew tap and the Scoop
bucket untouched for such a tag. That is what makes a release candidate safe to
push: it exercises the whole pipeline without moving what `brew upgrade` and
`scoop update` would hand to a user.

A plain tag that must not be marked latest, such as a backport, is corrected
afterwards with `gh release edit <tag> --prerelease`.

## 3. What the release workflow does on its own

Pushing the tag starts one job. It needs no input and no approval.

1. Checks out the tagged commit with full history and no persisted credentials.
2. Installs Go 1.26.x, cosign v3.1.3 and syft v1.51.1.
3. Sets `SOURCE_DATE_EPOCH` to the tagged commit's committer timestamp, so the
   archives are reproducible from the commit alone.
4. Runs `goreleaser release --clean`, which:
   - runs the release preflight and stops before building if the token cannot
     publish or the tag already has an immutable release;
   - builds six binaries (linux, darwin and windows on amd64 and arm64) with
     `CGO_ENABLED=0`, `-trimpath` and the version, commit and commit date linked
     in;
   - packs six archives, each carrying `LICENSE` and `README.md`;
   - writes `checksums.txt` over all of them;
   - writes one SPDX SBOM per archive with syft, with no network enrichment;
   - signs `checksums.txt` with keyless cosign and writes
     `checksums.txt.sigstore.json`. The signing certificate comes from the
     workflow's own OIDC identity, so there is no key to store or rotate;
   - creates the GitHub release with notes grouped from the commit subjects;
   - writes the Homebrew cask and the Scoop manifest, and uploads them only if
     `TAP_GITHUB_TOKEN` is in the environment. See section 6.
5. Attests build provenance for the archives and `checksums.txt` with GitHub's
   own attestation action.

If the job goes red, find out how far it got before you touch anything. A
failure before the release is created leaves nothing behind but the tag: delete
the tag locally and remotely, fix the cause and tag again. A failure after the
release is created, which is what a bad tap token looks like, leaves a complete
release in place, and section 6.4 says what to do with it.

## 4. Verify the release

Do this from an empty directory, as a stranger would. These are the same
commands `SECURITY.md` gives to anyone downloading a release, and running them
yourself is how you find out that the instructions in that file still work.
Substitute the version you released.

Download the archive for your platform, `checksums.txt` and
`checksums.txt.sigstore.json` from the release page, then:

1. Verify the signature on the checksum file. cosign v3 or later.

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
   (Get-FileHash .\trustdiff_0.4.0_windows_amd64.zip -Algorithm SHA256).Hash
   Select-String windows_amd64 .\checksums.txt
   ```

3. Verify the build provenance.

   ```sh
   gh attestation verify trustdiff_0.4.0_linux_amd64.tar.gz \
     --owner vahapogut \
     --signer-workflow vahapogut/trustdiff/.github/workflows/release.yml
   ```

4. Unpack the archive and run `trustdiff version`. The version, the commit and
   the commit date it prints must be the tag you pushed.

If any of these fail, the release is not usable. Do not paper over it: delete
the release and the tag, fix the pipeline, and tag again.

## 5. Fill in the action's checksum table

`action.yml` downloads a published archive rather than building from source, and
it verifies what it downloads. For the version it defaults to, it holds the
sha256 of every archive inline, which means the action does not have to trust
anything at run time. That table can only be written after the release exists.

1. Keep the verified `checksums.txt` from section 4. Do not fetch a fresh one
   for this step; the point of the table is that it comes from a file whose
   cosign signature you checked.
2. In `action.yml`, set the `version` input's `default:` to the new tag.
3. Set `pinned_version=` in the "Resolve the release archive for this runner"
   step to the same tag. It appears twice in the file and both must change.
4. Replace all six values in the `case "${os}_${arch}"` table with the ones from
   `checksums.txt`, matching each line by archive name. Copy them; do not retype
   them.
5. `git diff action.yml` and read it. Six hashes changed, two version strings
   changed, nothing else.
6. Commit as `chore(action): pin v0.4.0 and checksums`.

Leaving an entry as `pending` is safe but slower for every caller: the action
falls back to verifying the release's `checksums.txt` with cosign at run time,
which proves the same thing over a longer path. It is a fallback, not a resting
place.

## 6. The Homebrew tap and the Scoop bucket

`.goreleaser.yaml` has a `homebrew_casks` block pointing at
`vahapogut/homebrew-tap` and a `scoops` block pointing at
`vahapogut/scoop-bucket`. Both are guarded by the same environment variable:

```yaml
skip_upload: '{{ if isEnvSet "TAP_GITHUB_TOKEN" }}auto{{ else }}true{{ end }}'
```

**When `TAP_GITHUB_TOKEN` is not set, the release still succeeds.** goreleaser
writes the cask to `dist/homebrew/Casks/trustdiff.rb` and the manifest to
`dist/scoop/bucket/trustdiff.json`, logs `brew.skip_upload is set` and
`scoop.skip_upload is set`, and moves on. Neither file is uploaded anywhere, and
nothing else in the pipeline depends on them. This is the current state of the
project: the two repositories do not exist yet, so the guard is what keeps every
release green until they do.

Three things need the owner's own hands, in this order. None of them can be done
from this repository.

### 6.1 Manual: create the two repositories

Both are public and empty, with `main` as the default branch. goreleaser creates
the files inside them on the first release that has the token.

```sh
gh repo create vahapogut/homebrew-tap  --public --description "Homebrew tap for trustdiff"
gh repo create vahapogut/scoop-bucket  --public --description "Scoop bucket for trustdiff"
```

The name `homebrew-tap` is not decorative. It is what makes the tap addressable
as `vahapogut/tap`, which is the form in the README. The cask lands in `Casks/`
and the Scoop manifest in `bucket/`, which are the directories the two blocks in
`.goreleaser.yaml` name.

Before creating them, re-check that the name is still free: no `trustdiff` in
homebrew-core or homebrew-cask, and no `trustdiff` in the main or extras Scoop
buckets. Section 9 of `docs/PLAN.md` records `installgate` as the fallback name
and asks for this check right before this task.

### 6.2 Manual: create the token

A fine-grained personal access token, not a classic one.

| Setting | Value |
|---|---|
| Resource owner | `vahapogut` |
| Repository access | Only select repositories: `vahapogut/homebrew-tap` and `vahapogut/scoop-bucket` |
| Repository permissions | Contents: **Read and write** |
| Everything else | Leave at No access |
| Expiration | Set one, and put the renewal date in a calendar |

Contents write on those two repositories is the whole permission set. The token
must not be able to reach `vahapogut/trustdiff`; the release job already has the
automatic `GITHUB_TOKEN` for that, and a token that can do both jobs is a token
whose leak costs twice as much. Nothing in the tap or the bucket needs issues,
pull requests, workflows or metadata write.

### 6.3 Manual: store it as a secret and hand it to goreleaser

Store the token as a repository secret on `vahapogut/trustdiff` named
`TAP_GITHUB_TOKEN`:

```sh
gh secret set TAP_GITHUB_TOKEN --repo vahapogut/trustdiff
```

Then add one line to the goreleaser step in `.github/workflows/release.yml`, so
that the secret actually reaches the process. The guard reads an environment
variable rather than a command line flag precisely so that this line is the only
place the decision is visible:

```yaml
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          TAP_GITHUB_TOKEN: ${{ secrets.TAP_GITHUB_TOKEN }}
          SOURCE_DATE_EPOCH: ${{ steps.epoch.outputs.epoch }}
```

An unset secret expands to the empty string in a workflow, and the guard treats
an empty value as absent, so removing the secret is enough to turn tap
publishing off again without editing the configuration.

### 6.4 What the first release with the token looks like

Push a release candidate first, for example `v0.4.0-rc.1`. Because
`skip_upload` is `auto` when the token is present, goreleaser will log
`prerelease detected with 'auto' upload, skipping homebrew publish` and the same
for Scoop. That proves the guard, the tag parsing and the generated files, and
it leaves the tap alone. Download the cask and the manifest from the job's
`dist/` output and read them.

The first stable tag is the first real write. Afterwards:

- `vahapogut/homebrew-tap` has a commit named `Brew cask update for trustdiff
  version v0.4.0` adding `Casks/trustdiff.rb`.
- `vahapogut/scoop-bucket` has a commit named `Scoop update for trustdiff
  version v0.4.0` adding `bucket/trustdiff.json`.
- `brew install vahapogut/tap/trustdiff` on macOS, then `trustdiff version`.
  Homebrew installs casks on macOS only; the Linux entries goreleaser writes
  into the cask are never used, and Linux users take the archive or
  `go install`.
- `scoop bucket add trustdiff https://github.com/vahapogut/scoop-bucket` and
  `scoop install trustdiff` on Windows, then `trustdiff version`.

Two things to expect the first time:

- **macOS Gatekeeper.** The binaries are signed with cosign, which macOS knows
  nothing about, and they are not notarized with an Apple Developer ID. Homebrew
  marks a cask download as quarantined, so the first run may be refused.
  goreleaser documents a `hooks.post.install` that strips the quarantine
  attribute with `xattr`, and this project does not use it, because stripping a
  macOS security attribute by default is not a thing a supply chain tool should
  ship. Decide before the first stable tag whether to notarize, to add a
  `caveats` stanza that tells the user what they are seeing, or to accept it.
- **A bad token.** The GitHub release is published before the tap is written, so
  a token that cannot write to the tap leaves a complete, correct release behind
  and turns the job red at the very end. The release does not need to be redone;
  fix the token and either re-run the job or push the cask by hand.

## 7. After the release

1. Announce nothing automatically. There is no announce step and none is wanted.
2. Open the milestone for the next version and move anything that slipped.
3. Check that the release page lists six archives, six SBOMs, `checksums.txt`
   and `checksums.txt.sigstore.json`. Twelve files plus two.
