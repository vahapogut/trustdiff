# Releasing trustdiff

A release is one annotated git tag. Everything that follows the tag is done by
`.github/workflows/release.yml`, which is the only job in this repository allowed
to write releases. Nobody builds a release on a laptop and uploads it.

Read this page top to bottom the first time. The steps that need a human are
marked **manual**. Two of them recur on every release, the changelog and the
readme edits before the tag and the tag itself. The rest are one-time setup: two
for the Homebrew tap and the Scoop bucket in section 6, and three for the npm
package in section 9. All five were done on 2026-09-10, so those sections now read
as a record of what was set up rather than as work waiting to be done. None of them
blocks a release either: a tag with none of them done still produces a complete,
signed, verifiable release.

goreleaser v2.18.1 and cosign v3.1.3 are pinned twice, in `tools.mk` and in the
release workflow, and must be bumped in both. syft v1.51.1 is pinned only in
`.github/workflows/release.yml`, because nothing outside the release job runs it.

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
7. **Manual.** `README.md` and `SECURITY.md`: the version sentence near the top
   of the readme, and the archive names used as examples in both files, name the
   release that is about to exist. Both carry `trustdiff_<version>_<os>_<arch>`
   examples and both go stale silently. `.pre-commit-hooks.yaml` carries a third:
   the `rev:` in its header comment, which a reader copies into their own
   configuration. Bump it only when this release changes what the hook does, since
   it names the first release a reader can pin and get the current behavior from,
   not the newest release that exists. It said `v0.2.0` until v0.5.0 widened the
   `files` pattern from four formats to nine.
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

Pushing the tag starts one job, and the job waits. It runs in the `release`
environment, which has one required reviewer, so nothing is built or signed until a
person approves it: open the run under
[Actions](https://github.com/vahapogut/trustdiff/actions/workflows/release.yml),
press **Review deployments**, tick `release` and **Approve and deploy**. The waiting
run shows the tag it was started for, which is the thing to check before approving.
Section 7 says why the gate is there. Rejecting the deployment leaves the tag in
place and publishes nothing, which is how a tag pushed by mistake is undone: reject
it, then `git push --delete origin <tag>`.

Once approved, the job needs no further input.

0. Refuses to go on when `TAP_GITHUB_TOKEN` is empty and the tag is not a
   prerelease. That is the whole of what went wrong with v0.4.1, and it costs
   nothing to check before anything is built. A prerelease is exempt because it
   publishes no tap at all, which is what makes one safe to push.
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
   - packs six archives, each carrying `LICENSE`, `README.md` and
     `THIRD_PARTY_NOTICES`;
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
6. Reads the cask and the manifest back out of the two tap repositories and
   fails when either still serves the version before this one. goreleaser
   reports a skipped upload as a notice and exits 0, so a tap that was not
   written is invisible in a green job; this is what makes it visible. It reads
   with the job's own `GITHUB_TOKEN`, because both repositories are public and
   the read needs no write credential, and it reads five times ten seconds apart,
   because the contents API is served from a cache that can lag a push. A
   prerelease is exempt for the same reason as step 0.

If the job goes red, find out how far it got before you touch anything. A
failure before the release is created leaves nothing behind but the tag: delete
the tag locally and remotely, fix the cause and tag again. A failure after the
release is created, which is what a bad tap token looks like, leaves the release
published and its assets complete, but steps 5 and 6 never ran: it carries no
build provenance attestation and neither tap was written. `brew upgrade` and
`scoop update` keep handing out the version before it, and the archive anyone
downloads fails the `gh attestation verify` in section 4. Do not re-run the job
before reading section 6.4: a plain re-run rebuilds and re-uploads every
artifact, and the assets are already on the release.

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

Step 3 failing on its own is the exception. If steps 1, 2 and 4 pass and only
the attestation is missing, nothing is wrong with the archives: they are what
the tag built, and the signature over `checksums.txt` covers them. What it says
is that the job stopped before step 5 in section 3, which is where the
attestation is made. Do not delete the tag for this. Section 5 fills in the
action's sha256 table and the README's `uses:` pin from the archives of this
exact release, and once that commit is pushed, deleting the release leaves both
pointing at archives that are gone.

Fix what stopped the job first. Then delete the assets, keep the release and
the tag, and re-run the job:

```sh
gh release view <tag> --json assets --jq '.assets[].name' |
  xargs -n1 gh release delete-asset <tag> --yes
```

The re-run builds the same bytes, because the archives are reproducible from
`SOURCE_DATE_EPOCH` and the toolchain is pinned, so the table stays correct. It
then attests them and writes the two taps. The assets have to go first only
when the tag predates `replace_existing_artifacts` in the `release:` block of
`.goreleaser.yaml`, since goreleaser reads that file out of the tag it is
building. Without the key every upload answers `422 Validation Failed` with
`already_exists` and the job dies before the tap step again. With it, a plain
re-run is enough.

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
   step to the same tag. There is one assignment, and it has to match the
   `default:` above it or the table is never consulted.
4. Replace all six values in the `case "${os}_${arch}"` table with the ones from
   `checksums.txt`, matching each line by archive name. Copy them; do not retype
   them. Then set the ref of the published leg in
   `.github/workflows/action-selftest.yml` to the commit this tag points at,
   `git rev-parse <the tag>^{}`, with the tag itself in the trailing comment. It
   is the one place in the repository that names the reference a caller resolves,
   it is a commit rather than a tag because DR110 reports a tagged `uses:` at
   `warn` and this repository is judged by its own rules, and
   `TestActionSelfTestAlsoRunsThePublishedReference` fails while its comment and
   the `default:` above disagree.
5. `git diff action.yml .github/workflows/action-selftest.yml` and read it. Six
   hashes changed, the `default:` and the `pinned_version=` changed, the two
   example snippets in the header comment changed, the published leg's ref
   changed, nothing else.
6. Commit as `chore(action): pin v0.4.0 and checksums`.
7. Dispatch the `action-selftest` workflow on the default branch, once the commit
   above is pushed. It runs `action.yml` from `./` on ubuntu, macos and windows,
   on both verification routes, against the release that commit just pinned, and
   one more job runs `uses: vahapogut/trustdiff@<the tag>`, which is the only leg
   that loads the manifest a runner resolves rather than the one in the
   workspace. That
   is the first time the new table and the new archives are read by the code that
   reads them for everybody else, and the pinned leg fails rather than falls back
   when the table does not cover the default version. Dispatch it on the branch
   and not on the tag: only the branch carries the pin commit.

If the self-test goes red, what is wrong is `action.yml` and not the release. The
action downloads a published archive, so nothing a runner finds in it touches the
archives, the checksums or the signature: the tag stands, and the fix is a commit
on the branch. Fix it, push, dispatch again, and keep going until all seven legs
are green. The dispatch after the v0.5.0 pin commit is what this looks like. It found
two defects that had shipped in every release since v0.4.0: an expression in the
`base` input's description, which a runner evaluates while it loads the manifest,
at a moment when there is no event, so the action failed with `Unrecognized
named-value: 'github'` before one step of it ran on any runner; and a sha256 line
that `sha256sum` and `shasum` prefix with a backslash when the file name holds
one, which a Windows runner's download path does, so a correct archive was
rejected as not matching. Both sit in the half of the action that only a runner
exercises, which is why nothing caught them until the self-test existed.

One thing this ordering cannot fix: the tag is pushed before the pin commit
exists, so the action at tag `vX.Y.Z` always defaults to the release before it.
That is why the README's workflow example pins `uses:` at a sha on the branch
rather than at the tag: from the pin commit on, the default already is this
release, and the example needs no `version:` input. It is also the only pin a
reader can copy without failing their own `doctor --ci`, since DR110 reports a
tagged `uses:` at `warn`.

So the example carries a sha that exists only once the commits above are pushed,
which makes it the one edit that cannot be made before the tag:

8. **Manual.** Put the sha of the newest `action.yml` commit the self-test passed
   on into the README's workflow example, with a trailing `# vX.Y.Z` comment.
   Where step 7 was green at the first dispatch, that is the pin commit, and
   `git rev-parse HEAD` on the branch gives it. Where step 7 went red it is the
   last fix commit instead: the action at the pin commit is the one the self-test
   rejected, and pinning the example there hands every reader a defect that is
   already fixed on the branch. `git log -1 --format=%H -- action.yml` names it in
   both cases, as long as nothing has touched `action.yml` since the green run.
   Commit it as `docs: pin the readme example at the vX.Y.Z action commit`.
   `internal/cli` `TestREADMEPinsTheActionAtACommit` fails while the example holds
   a tag, so this cannot be forgotten quietly; it checks the shape and not which
   commit, because when the sha is written the newest one is the commit being
   written, so a sha that a later `action.yml` fix leaves behind passes it too.

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

Both repositories exist, and each serves whatever release last reached it. What
the token adds is that the release job writes them itself, instead of somebody
doing it by hand afterwards.

**When `TAP_GITHUB_TOKEN` is not set, the release still succeeds.** goreleaser
writes the cask to `dist/homebrew/Casks/trustdiff.rb` and the manifest to
`dist/scoop/bucket/trustdiff.json`, logs `brew.skip_upload is set` and
`scoop.skip_upload is true`, and moves on. Neither file is uploaded anywhere, and
nothing else in the pipeline depends on them.

One thing needs the owner's own hands, and it is the token in 6.2. A fine grained
personal access token cannot be minted through an API, by design, so nothing here
can create it.

### 6.1 Create the two repositories

Done on 2026-09-10. Both exist, are public, and have `main` as their default
branch. To recreate them, or to set up a tap under another account:

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

### 6.2 Create the token

Done on 2026-09-10. Redo this when the token expires, which is what its expiry date
is for, or when it is rotated for any other reason.

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

### 6.3 Store it as a secret

Done on 2026-09-10. `gh secret list --repo vahapogut/trustdiff` shows
`TAP_GITHUB_TOKEN` and the date it was set.

Store the token as a repository secret on `vahapogut/trustdiff` named
`TAP_GITHUB_TOKEN`:

```sh
gh secret set TAP_GITHUB_TOKEN --repo vahapogut/trustdiff
```

That is the whole step. The goreleaser step in `.github/workflows/release.yml`
already passes `TAP_GITHUB_TOKEN: ${{ secrets.TAP_GITHUB_TOKEN }}` through to the
process, so nothing in this repository has to change: storing the secret is what
flips the behavior, and the next stable tag publishes.

An unset secret expands to the empty string in a workflow, and the guard treats
an empty value as absent, so removing the secret is enough to turn tap publishing
off again without editing the configuration. That is not incidental. goreleaser's
`isEnvSet` returns true only when the variable is set **and** not empty; a naive
implementation would return true for the empty string a missing secret expands
to, and the guard would invert itself and try an authenticated push with no
token on every release.

### 6.3.1 How the tap and the bucket got v0.4.0, v0.4.1 and v0.5.0

The job wrote neither file for v0.4.0 and v0.4.1, and wrote both for v0.5.0 only
on the second run. Each of the three failed in a different place.

v0.4.0 was released before the token existed. v0.4.1 was released with the secret
present but holding an empty value, which `isEnvSet` reads as unset, exactly as
the paragraph above describes: the job logged `brew.skip_upload is set` and
`scoop.skip_upload is true`, went green, and left both repositories serving
v0.4.0.

v0.5.0 was released with a token that was there and could not write. The secret
held a value, so step 0 passed, and goreleaser got the same answer on both
writes: `403 Resource not accessible by personal access token`, on the PUT to
`Casks/trustdiff.rb` and on the PUT to `bucket/trustdiff.json`. The token named
the two repositories and granted nothing on them. Selecting repositories in a
fine-grained token is not the same as granting a permission, and a token with no
permission still reads a public repository, which is why nothing before
goreleaser complained. goreleaser exited 1 with the GitHub release and its
fourteen assets already published, so steps 5 and 6 never ran: the release
carried no build provenance attestation, and nothing read the two repositories
back. They went on serving v0.4.1.

The first re-run changed nothing. goreleaser rebuilds and re-uploads every
artifact, and GitHub answered every upload with `422 Validation Failed` and
`already_exists` because the assets were still on the release, so the job failed
again before it reached the tap. Recovering the release took three things in this
order: the token was regenerated with Contents read and write on the two
repositories, which is what section 6.2 asks for; the fourteen assets were
deleted with `gh release delete-asset`, which leaves the release and the tag
alone; and the job was re-run on the same tag. It wrote both files and attested
the build, and the archives it uploaded are byte for byte the ones that were
deleted, because `SOURCE_DATE_EPOCH` is the tagged commit's timestamp and the
build is reproducible from it.

The v0.4.0 and v0.4.1 files were put into the two repositories by hand. They are
the files goreleaser generates, with every digest taken from the release's own
`checksums.txt` after cosign verified its signature against the release
workflow's identity for that tag, and all six archives were downloaded from the
URLs in those files and checked against them before either was committed. The
commits are named the way goreleaser names its own, so the history reads the same
once the job takes over.

The job has taken over. Both repositories serve v0.5.0 from a goreleaserbot
commit that replaced the file put there by hand, and nothing from the two
versions before it needs undoing.

**Check the log, not the secret list.** `gh secret list` shows a name, not a
value, so a secret set to the empty string looks exactly like a working one. What
tells the two apart is the job's own step header: GitHub prints
`TAP_GITHUB_TOKEN: ***` for a secret that holds something and
`TAP_GITHUB_TOKEN:` with nothing after it for one that does not.

Since v0.4.1 the job checks both ends itself, so this is a way of reading a
failure rather than something to remember: step 0 refuses to build a stable tag
with an empty token, and step 6 reads the two repositories back and fails when
either still serves the version before. Neither can be satisfied by a token that
is present and does not work, which is the one shape left: such a release stops
at goreleaser, after the GitHub release exists, and section 6.4 says what to do
with it.

**Prove the token can write before you tag.** A token that is present and
non-empty passes step 0 whatever it is allowed to do, and the permission itself
is tested only when goreleaser writes the cask and the manifest, which is after
the release is published. v0.5.0 is what that costs: the release went out with
its 14 assets, goreleaser then failed with `403 Resource not accessible by
personal access token` on both repositories, and because it exited 1 the two
steps after it were skipped, so the release carried no build provenance
attestation and both taps went on serving the version before. Ask each
repository what the token may do, with the token in the environment and nothing
else:

```sh
GH_TOKEN=<the token> gh api repos/vahapogut/homebrew-tap --jq .permissions.push
GH_TOKEN=<the token> gh api repos/vahapogut/scoop-bucket --jq .permissions.push
```

A token that may write prints `true` for both repositories, and `false` or
`null` is a token that cannot. The negative answer is the one this buys: it is
certain, it costs nothing, and it catches the failure above before the tag.
A `true` is not a write, and only the release job proves that; reading a tap
proves nothing about writing to it either. Set `GH_TOKEN` on the command itself. With the variable unset,
`gh` uses its own stored login, which owns both repositories and prints `true`
no matter what the secret holds. In PowerShell, set `$env:GH_TOKEN` to the
token, run the two lines, then clear it.

The token needs two things and one without the other is the failure above.
Repository access has to be Only select repositories with
`vahapogut/homebrew-tap` and `vahapogut/scoop-bucket` picked, and repository
permissions has to grant Contents: Read and write. Selecting the repositories
grants nothing by itself; it says where a permission applies, not that there is
one, and a token with no permission still reads a public repository, which is
why nothing but the two writes complained. Section 6.2 is the full table. Run
the two commands again after every rotation and renewal.

### 6.4 What the first release with the token looks like

Push a release candidate first, with the version you are about to release and an
`-rc.1` suffix. Because
`skip_upload` is `auto` when the token is present, goreleaser will log
`prerelease detected with 'auto' upload, skipping homebrew publish` and the same
for Scoop. That proves the guard, the tag parsing and the generated files, and
it leaves the tap alone. The job uploads no `dist/` artifact, so read the two
files where they are generated: check out the tag, run `make snapshot`, and
open `dist/homebrew/Casks/trustdiff.rb` and `dist/scoop/bucket/trustdiff.json`.
The version in them reads `-next` rather than the tag, because that is what a
snapshot stamps.

The first stable tag is the first real write. Afterwards:

- `vahapogut/homebrew-tap` has a commit named `Brew cask update for trustdiff
  version <the tag>` replacing `Casks/trustdiff.rb`. The file is already there,
  put in by hand for the versions section 6.3.1 names, so what tells the job's
  commit from those is its author: goreleaserbot rather than you.
- `vahapogut/scoop-bucket` has the matching `Scoop update for trustdiff version
  <the tag>` replacing `bucket/trustdiff.json`.
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
  a token that cannot write to the tap leaves the release behind with every
  asset uploaded and signed, and turns the job red at the very end. A 403
  `Resource not accessible by personal access token` means the token reaches the
  two repositories and holds no permission on them; section 6.2 has the one
  permission it needs. The release does not need to be redone, but goreleaser
  exiting 1 skips the two steps after it in section 3: the build provenance
  attestation and the tap read-back. Until the job runs to the end, the release
  carries no attestation and both taps still serve the version before.

**Recovering from a failed tap write.** Fix the token first, then take one of
these two.

- **Re-run the job.** `.goreleaser.yaml` sets
  `release.replace_existing_artifacts`, so goreleaser overwrites the assets it
  already uploaded instead of failing on each with `422 Validation Failed` and
  `already_exists`. The job builds from the tagged commit, so on a tag pushed
  before that key was added, delete the assets first, one
  `gh release delete-asset <tag> <asset>` per asset, keeping the release and the
  tag, then re-run. The archives come back byte identical either way, because
  `SOURCE_DATE_EPOCH` is computed from the tagged commit. This is also the only
  way to get the attestation.
- **Push the two files by hand.** Check out the tag, run `make snapshot`, and
  take the two generated files. `make snapshot` stamps a `-next` version, so the
  version, the URLs and the digests in them name a release that does not exist:
  replace all three with the release's own, every digest read from the
  `checksums.txt` you verified in section 4, the way section 6.3.1 describes.
  Commit each to its repository under the name the job would have used, `Brew
  cask update for trustdiff version <the tag>` and `Scoop update for trustdiff
  version <the tag>`. That moves both taps and nothing else; the attestation
  still needs a re-run.

## 7. Who is allowed to make one

The signing identity on every release is
`https://github.com/vahapogut/trustdiff/.github/workflows/release.yml@refs/tags/v*`.
That is what `cosign verify-blob` checks and what `SECURITY.md` tells a stranger to
check, so it is the trust root of this project, and it says in one line what the
root really is: **anyone who can push a `v*` tag to this repository can produce a
release that verifies.** No review stands between a tag and a signed artifact,
because the whole point of the pipeline is that no human touches the build.

Two repository settings close that, and neither is a file in this tree, so neither
can be added by a commit. Both are one-time and both need a person with admin
rights. Both are in place since 2026-09-12: the ruleset is `release tags`, id
23045449, and the environment is `release` with `vahapogut` as its one required
reviewer. What follows is how they were made, so that they can be made again, and
the commands that read back what they are now.

1. **A tag ruleset restricting `v*` creation.** Settings, Rules, Rulesets, New tag
   ruleset: target `refs/tags/v*`, enforcement Active, restrict creations, and put
   the people or the team allowed to release in the bypass list. Through the API:

   ```sh
   gh api repos/vahapogut/trustdiff/rulesets --method POST --input - <<'JSON'
   {
     "name": "release tags",
     "target": "tag",
     "enforcement": "active",
     "conditions": {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}},
     "rules": [{"type": "creation"}],
     "bypass_actors": [{"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}]
   }
   JSON
   ```

   `actor_id: 5` is the admin role. Check what it created with
   `gh api repos/vahapogut/trustdiff/rulesets --jq '.[] | "\(.id) \(.name) \(.target) \(.enforcement)"'`,
   and confirm the bypass list is what you meant before relying on it.

2. **An environment with a required reviewer on the release job.** Settings,
   Environments, New environment named `release`, then add yourself as a required
   reviewer. The job then waits for an approval before it runs, so a tag pushed by
   something that got past the ruleset still cannot sign anything on its own.
   Through the API, which is what this repository used:

   ```sh
   gh api repos/vahapogut/trustdiff/environments/release --method PUT --input - <<'JSON'
   {
     "wait_timer": 0,
     "prevent_self_review": false,
     "can_admins_bypass": false,
     "reviewers": [{"type": "User", "id": 110431024}],
     "deployment_branch_policy": null
   }
   JSON
   ```

   `gh api user --jq .id` gives the id. `prevent_self_review` is false because the
   person who pushes the tag is the person who approves it here, and true would
   leave the one reviewer the environment has unable to approve anything.
   `can_admins_bypass` is false on purpose: the API defaults it to true, and an
   approval that an admin can skip is not a gate against a token that can already
   push a tag. Read it back with

   ```sh
   gh api repos/vahapogut/trustdiff/environments/release \
     --jq '{name, can_admins_bypass, rules: [.protection_rules[] | {type, prevent_self_review, reviewers: [.reviewers[]?.reviewer.login]}]}'
   ```

   The workflow needs one line for this, which is the only part of item 2 that is a
   file change:

   ```yaml
   jobs:
     release:
       name: release
       runs-on: ubuntu-latest
       environment: release
   ```

   Add it once the environment exists. Adding it first makes every release wait on
   an environment that does not, which fails the job with a message about a missing
   environment rather than about a missing approval.

Neither of these makes an existing release less verifiable. They decide who can
make the next one.

## 8. After the release

1. Announce nothing automatically. There is no announce step and none is wanted.
2. Open the milestone for the next version and move anything that slipped.
3. Check that the release page lists six archives, six SBOMs, `checksums.txt`
   and `checksums.txt.sigstore.json`. Twelve files plus two.
4. Check that the release carries its build provenance attestation. Section 4
   step 3 is that check, and a release that fails it is not a release to
   delete: the attestation is made after goreleaser, so anything that turns
   goreleaser red skips it while the archives and the signature stay correct,
   and the release page looks the same either way. Re-run the release job;
   there is nothing to place by hand. A re-run rebuilds and re-uploads every
   artifact, so it reaches the attestation step only if the release will take
   those uploads: without `replace_existing_artifacts` under `release:` in
   `.goreleaser.yaml`, GitHub refuses each one as `already_exists` and the job
   stops at goreleaser again.
5. Check that the tap and the bucket serve the tag you just pushed. The job's
   own step does this and is skipped for the same reason, so read the two files
   back:

   ```sh
   gh api repos/vahapogut/homebrew-tap/contents/Casks/trustdiff.rb \
     --jq .content | base64 -d | sed -n 's/^ *version "\([^"]*\)".*/\1/p'
   gh api repos/vahapogut/scoop-bucket/contents/bucket/trustdiff.json \
     --jq .content | base64 -d | sed -n 's/.*"version": *"\([^"]*\)".*/\1/p'
   ```

   Both must print the tag without its leading `v`. A version before this one
   means goreleaser did not write them, and `brew` and `scoop` are still handing
   out that version; section 6 says how to place them by hand and what the job
   needs to do it itself.

## 9. The Bun scanner on npm

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

Three things have to be done once before any of that can work. One command does the
two that can be scripted and checks the third:

```sh
npm login
sh scripts/publish-scanner.sh
```

It is safe to run twice. It stops with a link if the organization does not exist,
leaves an already published version alone, and leaves an already configured trusted
publisher alone. It handles no credential of its own: npm asks for the one time
password in its own prompt. The three steps, and why each is what it is, were
confirmed against npm's own documentation on 2026-09-10.

### 9.1 Create the npm organization

Done on 2026-09-10: the organization `trustdiff` exists and `vahapogut1` owns it.
This is the one step nothing can do for you, so it is written out in full for the
next scope this project ever needs.

The scope has to exist and it cannot be a personal one. npm gives every account the
scope matching its own name, and the npm account here is `vahapogut1`, so it owns
`@vahapogut1` and nothing else;
`@trustdiff` requires an organization literally named `trustdiff`. Organizations are
created on npmjs.com only. `npm org` manages the members of one that already exists
and cannot create it, and there is no API for it.

Choose the free plan. It allows unlimited public packages, which is all this needs.

Turn on two-factor authentication on the account too, because `npm trust` in 9.3
refuses to run without it. It has to be a passkey or a security key. npm stopped
accepting an authenticator app for a new enrolment, and `npm profile enable-2fa`
answers a request to add one with `Adding a new TOTP 2FA is no longer supported`,
verified on 2026-09-10. The methods it does take are WebAuthn ones: a passkey
through Windows Hello, Touch ID or Face ID, or a hardware key such as a YubiKey.
Add one at `https://www.npmjs.com/settings/<account>/tfa` and keep the recovery
codes somewhere you will still have them if the device is lost.

If the name `trustdiff` turns out to be taken, the fallbacks are
`@vahapogut1/bun-scanner`, which needs no organization at all, or the unscoped
`trustdiff-bun-scanner`. Either means editing `name` in
`integrations/bun-scanner/package.json`, the four references in its README, the
`bunfig.toml` example in the root README, and the tarball assertion in the publish
workflow.

### 9.2 Publish the first version by hand

Done on 2026-09-10: 0.4.0 went out this way, and it is the only version that ever
will. It was packed from the working tree rather than from the `v0.4.0` tag, so its
README was a few commits newer than the tag's; every later version comes from the
workflow, which packs the tag's own checkout.

0.4.1 followed the same day through the workflow, which staged it, and through an
approval, which made it public. That is the whole chain exercised end to end, so
the next scanner release needs nothing from this section.

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

Do not be alarmed when `npm view` answers 404 straight afterwards. A new package under
a new organization takes a few minutes to appear: the publish returns 200, `npm access
get status` already reports it as public, and the registry document is the last thing
to catch up. On 2026-09-10 that took a little over three minutes.

### 9.3 Add the trusted publisher

Done on 2026-09-10, with staging permission only. `npm trust list
@trustdiff/bun-scanner` shows it.

With the package on the registry, point it at the workflow that may publish it:

```sh
npm trust github @trustdiff/bun-scanner \
  --repo vahapogut/trustdiff --file npm-publish.yml --allow-stage-publish
```

Both of the arguments that look optional are not. Without the package name npm
reads the `package.json` of the directory it runs in, which at the repository root
is trustdiff's own and not the scanner's. Without a permission flag it refuses
outright: `trust-cmd.js` throws `At least one permission flag is required
(--allow-publish, --allow-stage-publish)`. There is no default to leave it at.

`--allow-stage-publish` and not `--allow-publish` is the decision, and it is the
one the workflow is written against: it runs `npm stage publish` and nothing else.

`npm trust` needs npm 11.15.0 or newer and account-level two-factor authentication,
and it will prompt for a one-time password; tokens that bypass two-factor are
explicitly not accepted for it. The package settings page on npmjs.com does the
same thing through a form.

The file name is part of the contract. npm will only accept a publish that comes
from `.github/workflows/npm-publish.yml` in `vahapogut/trustdiff`, so renaming that
file breaks publishing until the trusted publisher is reconfigured. Afterwards,
restrict token-based publishing on the package, so that a leaked classic token
cannot publish a release the workflow did not build.

From then on, bump `version` in `integrations/bun-scanner/package.json` in the same
commit as the trustdiff release it belongs to, add a line to `CHANGELOG.md`, and the
tag stages it. Approving the staged version is the last step of the release, after
the checks in section 4.
