# Releasing trustdiff

A release is one annotated git tag. Everything that follows the tag is done by
`.github/workflows/release.yml`, which is the only job in this repository allowed
to write releases. Nobody builds a release on a laptop and uploads it.

Read this page top to bottom the first time. The steps that need a human are
marked **manual**. Two of them recur on every release, the changelog and the
readme edits before the tag and the tag itself. The rest are one-time setup: two
for the Homebrew tap and the Scoop bucket in section 6, and three for the npm
package in section 8. None of the one-time steps blocks a release; a tag with
none of them done still produces a complete, signed, verifiable release.

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

One command creates both, makes them public, and gives each an initial commit
holding a README and the project's LICENSE:

```sh
sh scripts/create-taps.sh
```

It is safe to run twice; a repository that already exists is left alone. Read it
before running it, as with anything that creates something under your account.

Two things about what it does are deliberate.

**It commits a README rather than leaving the repositories empty.** goreleaser
writes its file through the GitHub contents API, which will initialise a
repository that has no commits, but only when the branch it is configured to push
to is already that repository's default branch. Both blocks in `.goreleaser.yaml`
name `main` explicitly, so a repository created with any other default branch
fails the first release with `could not get ref "refs/heads/main"`. One commit
removes the dependency.

**It does not create `Casks/` or `bucket/`.** goreleaser creates them on the
first publish. Seeding them would need a placeholder file, and a placeholder in
the bucket would be wrong: Scoop counts what a bucket holds with a recursive
listing under `bucket/` that includes hidden files and is not filtered to
`*.json`, so a `.gitkeep` there makes `scoop bucket list` report two manifests
where there is one. README and LICENSE belong at the repository root.

The name `homebrew-tap` is not decorative. Homebrew resolves `brew tap <user>/<x>`
to the repository `<user>/homebrew-<x>`, so `homebrew-tap` is what makes the tap
addressable as `vahapogut/tap`, which is the form in the README. The cask lands in
`Casks/`, which for a cask is the only location Homebrew looks in, and the Scoop
manifest in `bucket/`.

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

### 6.3 Manual: store it as a secret

Store the token as a repository secret on `vahapogut/trustdiff` named
`TAP_GITHUB_TOKEN`:

```sh
gh secret set TAP_GITHUB_TOKEN --repo vahapogut/trustdiff
```

That is the whole step. The goreleaser step in `.github/workflows/release.yml`
already passes `TAP_GITHUB_TOKEN: ${{ secrets.TAP_GITHUB_TOKEN }}` through to the
process, so nothing in this repository has to change: storing the secret is what
flips the behaviour, and the next stable tag publishes.

An unset secret expands to the empty string in a workflow, and the guard treats
an empty value as absent, so removing the secret is enough to turn tap publishing
off again without editing the configuration. That is not incidental. goreleaser's
`isEnvSet` returns true only when the variable is set **and** not empty; a naive
implementation would return true for the empty string a missing secret expands
to, and the guard would invert itself and try an authenticated push with no
token on every release.

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
- `brew install --cask vahapogut/tap/trustdiff` on macOS, then `trustdiff
  version`. The name is given in full because Homebrew 6.0 requires a tap that is
  not one of its own to be trusted before its code runs, and a fully qualified
  name trusts that one cask and nothing else. Homebrew installs casks on macOS
  only; the Linux entries goreleaser writes into the cask are never used, and
  Linux users take the archive or `go install`.
- `scoop bucket add trustdiff https://github.com/vahapogut/scoop-bucket` and
  `scoop install trustdiff` on Windows, then `trustdiff version`.

Two things to expect the first time:

- **macOS Gatekeeper.** The binaries are signed with cosign, which macOS knows
  nothing about, and they are not notarized with an Apple Developer ID. That was
  decided rather than deferred: [docs/adr/0004-macos-notarization.md](adr/0004-macos-notarization.md)
  records why, which comes down to notarization not fixing the Finder case at all
  and probably costing the byte-reproducible macOS archives. The README tells a
  browser-download user what they will see and how to clear it. goreleaser
  documents a `hooks.post.install` that strips the quarantine attribute with
  `xattr`, and this project does not use it: stripping a macOS security check on
  the user's behalf is exactly what a malicious cask would do. Note that the tap is
  not a way around it either: Homebrew marks what a cask installs, which is why it
  used to carry `--no-quarantine`, and that flag was removed rather than kept. A
  cask install and a browser download hit the same wall and take the same one line
  to clear.
- **A bad token.** The GitHub release is published before the tap is written, so
  a token that cannot write to the tap leaves a complete, correct release behind
  and turns the job red at the very end. The release does not need to be redone;
  fix the token and either re-run the job or push the cask by hand.

## 7. After the release

1. Announce nothing automatically. There is no announce step and none is wanted.
2. Open the milestone for the next version and move anything that slipped.
3. Check that the release page lists six archives, six SBOMs, `checksums.txt`
   and `checksums.txt.sigstore.json`. Twelve files plus two.

## 8. The Bun scanner on npm

`integrations/bun-scanner` is published separately, as `@trustdiff/bun-scanner`.
It is not part of the release job and nothing in this repository holds an npm
credential. `.github/workflows/npm-publish.yml` does the work, through npm's
trusted publishing: GitHub mints an OIDC token for that workflow, npm exchanges it
for a short lived credential, and no secret exists to leak. The workflow runs on a
version tag, not on the GitHub release, because a release created by the automatic
`GITHUB_TOKEN` does not start another workflow run.

It stages rather than publishes. Since 2026-09-03 every trusted publishing
configuration can stage by default and direct publishing is opt in per
configuration, and npm recommends leaving it that way. A staged version sits on the
registry where nobody can install it until a person approves it:

```sh
npm stage list @trustdiff/bun-scanner   # what is waiting
npm stage download <stage-id>           # read what the job actually built
npm stage approve <stage-id>            # make it public, asks for a one time password
npm stage reject <stage-id>             # throw it away
```

The package page on npmjs.com does the same through a form. This is the one place
trustdiff can practise what it argues for, so the automatic path is deliberately not
taken; enabling direct publishing on the trusted publisher and changing the stage
step back to `npm publish` is a real trade and belongs in a commit message.

The workflow is idempotent for versions that are already public. It reads the
version from `package.json`, asks the registry whether that version is there, and
skips when it is. Most tags do not change the scanner, so most runs skip, and a skip
is a notice rather than a failure: a red release for "nothing to do" teaches people
to ignore red releases. A version that is staged but not yet approved is not on the
registry, so re-running the job for the same tag tries to stage it twice; approve or
reject the staged version first.

Three things have to be done once, by a person, before any of that can work. None
can be scripted, and all three were confirmed against npm's own documentation on
2026-09-10.

### 8.1 Manual: create the npm organisation

The scope has to exist and it cannot be a personal one. npm gives every account the
scope matching its own name, so `vahapogut` owns `@vahapogut` and nothing else;
`@trustdiff` requires an organisation literally named `trustdiff`. Organisations are
created on npmjs.com only. `npm org` manages the members of one that already exists
and cannot create it, and there is no API for it.

Choose the free plan. It allows unlimited public packages, which is all this needs.
Turn on two-factor authentication on the account first: the next two steps both
require it.

If the name `trustdiff` turns out to be taken, the fallbacks are
`@vahapogut/bun-scanner`, which needs no organisation at all, or the unscoped
`trustdiff-bun-scanner`. Either means editing `name` in
`integrations/bun-scanner/package.json`, the four references in its README, the
`bunfig.toml` example in the root README, and the tarball assertion in the publish
workflow.

### 8.2 Manual: publish the first version by hand

Trusted publishing cannot create a package that does not exist yet. npm/cli issue
8544, "Allow publishing initial version with OIDC", was still open on 2026-09-10,
so version 0.4.0 has to go out from a machine where a person can answer a
two-factor prompt:

```sh
cd integrations/bun-scanner
npm pack --dry-run
npm publish --access public --provenance=false
```

`--provenance=false` is not optional here, and leaving it off is the mistake this
paragraph exists to prevent. `package.json` sets `publishConfig.provenance: true`,
which is right for the workflow and wrong on a laptop: npm generates provenance only
on GitHub Actions and GitLab CI, and anywhere else it aborts the publish with
`Automatic provenance generation not supported for provider`. A flag on the command
line wins over `publishConfig`, which is why this works. `npm publish --dry-run`
will not warn you, because a dry run returns before it reaches that check.

Read what `npm pack --dry-run` lists before publishing. It must be exactly four
files: `LICENSE`, `README.md`, `package.json` and `src/index.ts`. The workflow
asserts the same four on every run, so this is the one time the check is yours to
make.

This first version goes out without a provenance attestation. Every version after it
gets one, because every version after it comes from the workflow.

### 8.3 Manual: add the trusted publisher

With the package on the registry, point it at the workflow that may publish it:

```sh
npm trust github --repo vahapogut/trustdiff --file npm-publish.yml
```

`npm trust` needs npm 11.15.0 or newer and account-level two-factor authentication,
and it will prompt for a one-time password; tokens that bypass two-factor are
explicitly not accepted for it. The package settings page on npmjs.com does the
same thing through a form.

Leave the configuration at its default, which permits staging and not direct
publishing. That is what the workflow expects, and it is what npm recommends.

The file name is part of the contract. npm will only accept a publish that comes
from `.github/workflows/npm-publish.yml` in `vahapogut/trustdiff`, so renaming that
file breaks publishing until the trusted publisher is reconfigured. Afterwards,
restrict token-based publishing on the package, so that a leaked classic token
cannot publish a release the workflow did not build.

From then on, bump `version` in `integrations/bun-scanner/package.json` in the same
commit as the trustdiff release it belongs to, add a line to `CHANGELOG.md`, and the
tag stages it. Approving the staged version is the last step of the release, after
the checks in section 4.
