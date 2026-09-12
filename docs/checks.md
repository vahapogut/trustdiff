# Checks

trustdiff evaluates a package version with the checks listed here. Every check has a stable id (`TD001`) that reports, SARIF rules and allow entries refer to, and a short name (`young-version`) that the policy file uses. Ids never change meaning; a check that is retired keeps its id.

Levels come from the policy. The defaults quoted in each section are what a run without a `.trustdiff.yaml` uses; every one of them can be set to `block`, `warn`, `info` or `off`, per ecosystem if needed, and `--fail-on` decides which levels turn into exit code 1. See the commented file that `trustdiff policy init` writes.

A check never passes for lack of data. When a registry, OSV, deps.dev or the download counts could not be fetched, or when the registry does not record what the check needs, the check reports `skipped` with the reason, the human report lists it under the card, and the JSON report lists it in `skipped`. A version with no evaluated check gets the verdict `skipped`, not `ok`.

A check that reads two sources holds to that even when one of them answered: if the other could not be reached and the one that did
found nothing, the check reports `skipped` naming the source that was down, because half the evidence is not a clean version. A source
that answered "I do not index this" is an answer, and the check goes on with what the other one said.

A lockfile names a version once per place it installs it, and those places are one subject as long as they agree about where the
version comes from and what guards it. A line that resolves the same version from somewhere else, or drops its hash, is a subject
of its own reported on its own line, because that is a different install however the version reads.

Evidence keys are part of the JSON report (`schema/report.v1.json`, schema `trustdiff.report/1`). Within a schema version keys are added, never renamed or removed. The example under each check is the human report as `trustdiff check` prints it, captured against the live registries on 2026-09-09 unless the section says otherwise.

Ecosystems: npm, PyPI and crates.io from 0.1.0, JSR from 0.4.0. A `jsr:` ref runs the checks JSR carries the data for and reports the rest as skipped with the reason; the applicability table lives in the package comment of `internal/registry/jsr`.

## TD000 expired-allow

**Detects.** An `allow` entry in the policy whose `expires` date has passed and whose `package` pattern matches the evaluated package. It is not a check in the registry sense: the runner emits it before the checks run, always at level `warn`, and it cannot be turned off. The check the entry was written for is evaluated again as if the entry did not exist.

**Why it matters.** Exceptions are the place where a gate rots. An entry written for one reviewed release keeps applying to every later one unless it expires, and an expired entry that stops applying silently is just as bad, because the next finding it was hiding looks like noise. The warning makes the expiry visible in the report until someone renews or removes the entry.

**Evidence.**

| Key | Meaning |
|---|---|
| `check` | the policy name of the check the entry covered |
| `package` | the entry's package pattern |
| `reason` | the entry's reason |
| `expires` | the expiry date, `yyyy-mm-dd` |

**Example.** A policy that allowed `install-script-present` for `cargo:serde` until 2026-06-01:

```
cargo:serde@1.0.210  WARN
  warn
    TD000 expired-allow: allow entry for install-script-present on cargo:serde expired on 2026-06-01
      the policy allowed install-script-present for cargo:serde until 2026-06-01 (reason: build
      script reviewed by @vahap 2025-12-01); today is 2026-09-09, so the exception no longer applies
      and the check is reported again until the entry is renewed or removed
    TD006 install-script-present: Runs code at install time: build.rs
      1.0.210 ships a build script (build.rs), which cargo compiles and runs before building the
      crate
```

**Fix.** Review the package again, then either move `expires` forward or delete the entry. An entry without `expires` never expires; that is allowed, but the policy file comments recommend a date.

**Allow.** Not applicable; the finding is about an allow entry.

## TD001 young-version

**Detects.** A version published less than `cooldown` ago (default `3d`, `7d` for crates.io in the default policy). The publish time comes from the registry; when the registry lists the version without a time, the deps.dev `publishedAt` of the same version is used and the explanation says so. Skipped when the registry was unavailable or no source knows the publish time. Applies to every ecosystem.

**Why it matters.** Compromised releases are found fast and removed fast, so a short waiting period avoids most of them without knowing anything about the attack. The two malicious axios versions of 31 March 2026 (`1.14.1` and `0.30.4`, published through the lead maintainer's stolen credentials) were on the registry for about three hours before removal ([axios post mortem](https://github.com/axios/axios/issues/10636), [Datadog Security Labs](https://securitylabs.datadoghq.com/articles/axios-npm-supply-chain-compromise/)). The malicious nx versions of 26 August 2025 were live for a little over five hours ([Nx post mortem](https://nx.dev/blog/s1ngularity-postmortem)). The Shai-Hulud worm of September 2025 spread through hundreds of packages, and GitHub removed more than 500 of them within days ([GitHub, 22 September 2025](https://github.blog/security/supply-chain-security/our-plan-for-a-more-secure-npm-supply-chain/)). A three day cooldown skips all of these. The package managers now ship the same idea (npm `min-release-age`, pnpm `minimumReleaseAge`, uv `exclude-newer`, pip `--uploaded-prior-to`); this check reports it for the version in front of you, whatever the manager is configured to do.

**Evidence.**

| Key | Meaning |
|---|---|
| `published_at` | RFC 3339 publish time of the version, in UTC |
| `published_at_source` | where the time came from: `registry` or `deps.dev` |
| `age` | time since the publish in the policy spelling (`6h`, `2d12h`); negative when the publish time is after the run clock |
| `age_seconds` | the same as a whole number of seconds |
| `cooldown` | the effective cooldown for the ecosystem, policy spelling (`3d`) |
| `cooldown_seconds` | the same as a whole number of seconds |
| `cooldown_ends_at` | RFC 3339 time at which the version leaves the cooldown |

**Example.** `express@4.19.2` evaluated one day after its release, with the run clock set to `TRUSTDIFF_NOW=2024-03-26T12:00:00Z`:

```
npm:express@4.19.2  WARN
  warn
    TD001 young-version: Published 21h29m23s ago, inside the 3d cooldown
      4.19.2 was published on 2024-03-25T14:30:36Z, 21h29m23s before this run; the cooldown is 3d,
      so the version has been public for too short a time for problems to be noticed and reported,
      and it leaves the cooldown on 2024-03-28T14:30:36Z
```

**Fix.** Wait, or pin the previous version until `cooldown_ends_at`. A security fix that cannot wait is what the allow entry below is for; write the reason down.

**Allow.** Your own packages belong in `cooldown_exclude`, which skips the check for them:

```yaml
cooldown_exclude:
  - "npm:@myorg/*"
```

A one-off exception is an allow entry with an expiry:

```yaml
allow:
  - check: young-version
    package: "npm:express@4.19.2"
    reason: "fixes CVE-2024-29041, reviewed the diff against 4.19.1"
    expires: 2024-04-01
```

`--cooldown 12h` overrides the policy for one run, and `young-version: off` turns the check off.

## TD002 publisher-changed

**Detects.** A version whose publishing account is not among the accounts that published the previous N releases, N being `previous_versions_window` (default 5). The window is built from the registry's version list by publish time, without prereleases and yanked versions, so a backport is compared with the releases that came before it, not with the highest version numbers. Account names are compared case-insensitively. Skipped when the version or its predecessors carry no publisher, or when there is no earlier release. Applies to npm (`_npmUser` per version) and crates.io (`published_by` per version). PyPI records no per-version publisher at all, and is answered from the baseline instead: the identity a PEP 740 attestation names is compared with the identity `.trustdiff/baseline.json` recorded, and a release with no attestation has no identity to compare, which is reported as skipped rather than as a pass.

**Why it matters.** The event-stream backdoor of 2018 started with a change of hands. The author had stopped maintaining the package, gave publish rights to a volunteer, and the volunteer's release `3.3.6` pulled in the malicious `flatmap-stream` that stole Copay wallets ([npm, 26 November 2018](https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident), [Snyk post mortem](https://snyk.io/blog/a-post-mortem-of-the-malicious-event-stream-backdoor/)). The registry still shows the handover: `3.3.5` is the first release by `right9ctrl` after years of releases by `dominictarr`, and that is the example below. The check does not fire when the legitimate account itself is used with a stolen token, as with axios in 2026 and ua-parser-js in 2021; TD004, TD005 and TD007 are there for that case.

**The one case reported below its level.** A package that moves to trusted publishing changes its publishing identity, which is exactly the shape this check is built to catch, and it is also the single most common publisher change happening right now: five of fifty entries of npm's own lockfile were in the middle of that migration on 2026-09-09. Blocking on it teaches people to turn the check off.

So when the evaluated version and the release before it both carry an attestation deps.dev verified, and both name the same source repository, the finding is reported at `info` whatever level the policy sets: the package is still built where it was always built, and it is harder to compromise than it was, not easier.

Where nothing says where either release was built, which is the ordinary state of a package whose earlier releases nobody attested, the finding is reported at `warn` and its evidence carries `evidence_kept`. A scan of npm/cli's lockfile on 2026-09-12 produced 81 `block` findings and 44 of them were exactly that: an ordinary package adopting trusted publishing and failing a gate for the one change that makes it harder to compromise. The finding stays and a run with `--fail-on warn` still fails on it, because a stolen account can register a trusted publisher of its own; what it no longer does is stop a build by itself. The demotion applies only while the release's own publishing evidence is no weaker than the previous one's.

Where the two attestations name different repositories, the finding keeps its level. That is what an account takeover with a trusted publisher of the attacker's own looks like, and the explanation says so.

**The other case reported below its level.** A version published by an account that the release before it already listed as a maintainer is reported at `warn`, with `publisher_is_maintainer` in its evidence. A package with several maintainers releases through whichever of them cut the release, and the registry named this one before the release under review existed, so what changed is which of the package's own maintainers pressed publish. The precision pass of 2026-09-12 measured how much of this check's output that is: of 317 distinct npm findings reported at `block` across ten public lockfiles, a sample of 25 found 11 published by an account the previous release already listed, among them `@jest/pattern` by `simenb`, `micromatch` by `doowb` and `ts-node` by `blakeembrey`.

An account added to the package and then publishing is a different shape and keeps its level, because the previous release's list does not have it in it. That is the event-stream shape exactly: `3.3.4` listed `dominictarr` alone, and `3.3.5` was published by `right9ctrl`.

**Evidence.**

| Key | Meaning |
|---|---|
| `publisher` | account that published the evaluated version |
| `publisher_is_maintainer` | true when the release before this one already listed the publishing account as a maintainer |
| `previous_publishers` | distinct accounts of the previous releases, newest first |
| `previous_versions` | the previous releases that were compared, newest first |
| `previous_releases` | one object per previous release: `version`, `publisher` (empty when not recorded) and `published_at` (RFC 3339) |
| `attested_repository` | the repository a verified attestation names for both this version and the one before it, present only for a migration to trusted publishing that kept building from it |
| `window` | the configured lookback (`previous_versions_window`) |

**Example.** The 2018 handover, as the registry records it today:

```
npm:event-stream@3.3.5  BLOCK
  block
    TD002 publisher-changed: Published by right9ctrl, which published none of the previous 5 versions
      the previous 5 versions (3.3.4, 3.3.3, 3.3.2, 3.3.1, 3.3.0) were published by dominictarr;
      3.3.5 was published by right9ctrl, an account that published none of them
```

**Fix.** Find out who the new account is before installing: the package's repository, its release notes, the maintainer's own announcements. A move to a bot or to a trusted publishing account is normal and shows up once; note it in an allow entry so the next release is compared with a window that already contains the new account.

**Allow.**

```yaml
allow:
  - check: publisher-changed
    package: "npm:event-stream@3.3.5"
    reason: "maintenance handed to right9ctrl, announced in the repository"
    expires: 2019-03-01
```

A larger `previous_versions_window` tolerates packages with several rotating publishers.

## TD003 maintainers-changed

**Detects.** A version whose maintainer set differs from the set recorded at the previous version, listing who was added and who was removed. Names are compared case-insensitively. Skipped without a previous version and when either version records no maintainers at all, since an empty set is more likely missing data than a package that lost every maintainer. Applies to every ecosystem, but only npm records the maintainer set per version (`versions[<v>].maintainers` in the packument). crates.io owners and PyPI roles are current state only, so those two are answered from the baseline: `trustdiff baseline` records the set it saw, and the check compares the registry's set now with the set recorded then.

The baseline way is not tied to a version, which is what makes it worth having: a package whose maintainer set changed while the locked version did not move is invisible to everything else here, and the finding says so in as many words. A record older than the window a project refreshes in is still an answer, and the finding carries how old it is.

A pull request can also edit the record itself, which is exactly what somebody with commit access would do. When the change under review rewrote or deleted a package's entry, the comparison uses the entry as it stands on the base revision, and the finding says the record was rewritten and what it now claims.

**Why it matters.** Before a new account publishes, it is usually added as a maintainer. In the event-stream case `right9ctrl` appears in the maintainer list at `3.3.5`, next to the original author, one release before the backdoor ([npm, 26 November 2018](https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident)). A removed maintainer matters too: it is what a takeover looks like once the attacker cleans up.

**Evidence.**

| Key | Meaning |
|---|---|
| `previous_version` | the previous release the set was compared with |
| `previous_maintainers` | its maintainer names, sorted |
| `maintainers` | the evaluated version's maintainer names, sorted |
| `added` | names present now and absent before, sorted |
| `removed` | names present before and absent now, sorted |

**Example.**

```
npm:event-stream@3.3.5  BLOCK
  warn
    TD003 maintainers-changed: Maintainers changed since 3.3.4: added right9ctrl
      3.3.4 listed dominictarr as maintainer; 3.3.5 lists dominictarr and right9ctrl: added
      right9ctrl
```

**Fix.** Same as TD002: confirm the change with the project. When the change is a maintainer leaving, check that the remaining ones are the people you expect.

**Allow.**

```yaml
allow:
  - check: maintainers-changed
    package: "npm:event-stream"
    reason: "right9ctrl joined as maintainer, confirmed with the author"
    expires: 2019-03-01
```

## TD004 trust-downgrade

**Detects.** A version whose publishing evidence is weaker than the previous release's, or than that of the version the base lockfile locked. A verified build attestation or trusted publishing record before, a bare registry signature or nothing now. The strength order is none, signature, attestation, trusted publisher, and a verified record ranks above an unverified one of the same kind. When the registry stores an attestation without verifying it, a deps.dev verification of the same version counts, so a registry that only stores the bundle does not produce a downgrade by itself. A bump usually crosses more than one release, so the version compared with is whichever of the two predecessors carried the most evidence, and the finding names it; a record the release before this one had already dropped is still a record the project is losing. A base version that could not be reached is a different thing from one the registry no longer has: the first leaves the second comparison unmade and the check reports itself as skipped naming it, the second is an answer and the check goes on with the release before this one alone. Skipped without a previous version. Applies to npm (`dist.attestations`, `dist.signatures`), PyPI (PEP 740 provenance) and crates.io (`trustpub_data`). This is the pnpm `trustPolicy: no-downgrade` idea applied to every ecosystem.

**Reported at `warn` when the comparison crosses release lines.** The previous release is the one published before this one, which for a maintenance release on an older line is a release of the newer line: `9.0.6` against `10.1.3`. That comparison says the older line carries less evidence than the newer one, which is a fact about the lines rather than about anything this release gave up, and at `block` it fails the build of every project pinned to an LTS line. It is still reported, because a patch published to an old line from a stolen token looks exactly like this, and the evidence carries `maintenance_release`. Both `trust-downgrade` block findings of a scan of npm/cli's lockfile on 2026-09-12 were this shape.

**Why it matters.** A stolen token cannot produce provenance. When the nx publishing token was stolen through a GitHub Actions injection on 26 August 2025, the attacker published eight malicious nx versions from outside the release workflow, and the Nx team's post mortem notes that "the malicious packages lacked NPM provenance signing" while provenance "doesn't block unsigned packages from being installed" ([Nx post mortem](https://nx.dev/blog/s1ngularity-postmortem), [GHSA-cxm3-wv7p-598c](https://github.com/nrwl/nx/security/advisories/GHSA-cxm3-wv7p-598c)). A package that has shipped provenance for years and suddenly ships none is exactly this pattern.

**Evidence.**

| Key | Meaning |
|---|---|
| `previous_version` | the previous release, whether or not it is the version the finding names |
| `previous_kind` | its provenance kind: `none`, `signature`, `attestation` or `trusted-publisher` |
| `previous_verified` | whether that evidence was verified |
| `previous_verified_by` | `registry` or `deps.dev`, when verified |
| `previous_identity` | the workflow or repository it names, when known |
| `compared_version` | the version the finding names: the stronger of the two predecessors |
| `base_version` | the version the base lockfile locked, when `diff` knows one and it is not the previous release (`diff` only) |
| `base_kind` | its provenance kind (`diff` only) |
| `base_verified` | whether that evidence was verified (`diff` only) |
| `base_verified_by` | `registry` or `deps.dev`, when verified (`diff` only) |
| `downgraded_since_base` | whether that version's evidence was stronger than this one's (`diff` only) |
| `kind` | the evaluated version's provenance kind |
| `verified` | whether its evidence was verified |
| `verified_by` | `registry` or `deps.dev`, when verified |
| `identity` | the workflow or repository it names, when known |

**Example.** A legitimate case that shows the shape: `rand_core@0.4.3` is a backport to an old release line, published with a token on 2026-09-02, while the line's newest release `0.10.1` came through trusted publishing:

```
cargo:rand_core@0.4.3  BLOCK
  block
    TD004 trust-downgrade: Provenance weaker than 0.10.1: a verified trusted publishing record before, no provenance evidence now
      0.10.1 was published with a verified trusted publishing record for
      github:rust-random/rand_core; 0.4.3 was published with no provenance evidence, so the evidence
      tying this release to its source is weaker than for the previous one
```

**Fix.** Ask why the evidence disappeared. A backport from a maintainer's machine, a migration between CI systems and a broken release workflow are the common benign answers, and each of them is visible in the repository. If none applies, treat the release as unverified until the maintainer confirms it.

**Allow.**

```yaml
allow:
  - check: trust-downgrade
    package: "cargo:rand_core@0.4.3"
    reason: "backport to the 0.4 line published by hand, matches the 0.4 branch"
    expires: 2026-12-01
```

## TD005 install-script-introduced

**Detects.** An npm version that declares an install-time script (`preinstall`, `install` or `postinstall`) which the previous release did not declare, or which the version the base lockfile locked did not. npm runs all three on every install of the package. `prepare` is not one of them and is not reported: npm runs a dependency's `prepare` only when the dependency comes from git or from a local folder, never for the registry tarball a lockfile entry names, so a release that adds a `husky` hook has added nothing an install will run. A base version that could not be reached is a different thing from one the registry no longer has: the first leaves the second comparison unmade and the check reports itself as skipped naming it, the second is an answer and the check goes on with the release before this one alone. Skipped without a previous version. npm only: crates.io and PyPI have no per-version script list to compare, and TD006 covers their install-time code.

**Why it matters.** Nearly every npm compromise of the last years delivered its payload through a script that the previous release did not have. The hijacked ua-parser-js releases `0.7.29`, `0.8.0` and `1.0.0` of 22 October 2021 added a `preinstall` hook that ran a cryptominer and a credential stealer ([issue #538](https://github.com/faisalman/ua-parser-js/issues/538)). The Shai-Hulud worm of September 2025 worked "by injecting malicious post-install scripts into popular JavaScript packages" ([GitHub, 22 September 2025](https://github.blog/security/supply-chain-security/our-plan-for-a-more-secure-npm-supply-chain/)). The `plain-crypto-js` package that the compromised axios pulled in on 31 March 2026 downloaded its remote access trojan from a `postinstall` hook ([Datadog Security Labs](https://securitylabs.datadoghq.com/articles/axios-npm-supply-chain-compromise/)). In every case the script was new.

**Evidence.**

| Key | Meaning |
|---|---|
| `previous_version` | the previous release, whether or not it is the version the finding names |
| `script_names` | the install-time scripts of the evaluated version, in lifecycle order (`preinstall`, `install`, `postinstall`) |
| `scripts` | the scripts by name, with the command each one runs |

**Example.** A harmless one that the registry still carries: `parcel-bundler@1.2.1` (December 2017) added a `postinstall` banner where `1.2.0` had no install script:

```
npm:parcel-bundler@1.2.1  BLOCK
  block
    TD005 install-script-introduced: Install script introduced: postinstall (1.2.0 had none)
      1.2.0 declared no install-time script; 1.2.1 declares postinstall (node -e
      "console.log('\u001b[35m\u001b[1mLove Parcel? You can now donate to our open
      collective:\u001b[22m\u001b[39m\n >
      \u001b[34mhttps://opencollective.com/parcel/donate\u001b[0m')"), which npm runs with the
      installing user's permissions on every install of the package
```

**Fix.** Read the script. `scripts` in the evidence holds the exact command; an `npm pack` of the version shows the files it runs. Install with `--ignore-scripts` (or the manager's `allowScripts` list) if the package works without it.

**Allow.**

```yaml
allow:
  - check: install-script-introduced
    package: "npm:parcel-bundler@1.2.1"
    reason: "postinstall only prints a donation banner, read the command"
    expires: 2018-06-01
```

## TD006 install-script-present

**Detects.** A version that runs code at install time at all, whether or not the previous version did. What that means depends on the ecosystem: npm scripts (`preinstall`, `install`, `postinstall`); a crates.io crate with a `build.rs`, which cargo compiles and runs before building the crate, or with `[lib] proc-macro = true`, whose code runs inside the compiler of every dependent (both found by downloading the `.crate` archive and checked against the registry checksum); a PyPI release published as a source distribution only, which pip must build by running the project's `setup.py` because no wheel exists. Skipped when the version details are unavailable. Applies to every ecosystem.

**Why it matters.** TD005 catches a script appearing; this check tells you that a package runs code on your machine before you ever import it, which is the part of the install worth reviewing even for a package that has always done it. The payloads of ua-parser-js (2021), Shai-Hulud (2025) and plain-crypto-js (2026) cited under TD005 all ran from install hooks, and blocking install scripts by default is now what npm 12, pnpm 11, Bun and Yarn do.

**Evidence.**

| Key | Meaning |
|---|---|
| `script_names` | the install-time scripts or markers of the version, in lifecycle order for npm (`preinstall`, `install`, `postinstall`), alphabetically otherwise |
| `scripts` | the same by name, with the command each one runs when the registry records one (empty for `build.rs`, `proc-macro`, `setup.py`) |

**Example.**

```
cargo:serde@1.0.229  WARN
  warn
    TD006 install-script-present: Runs code at install time: build.rs
      1.0.229 ships a build script (build.rs), which cargo compiles and runs before building the
      crate
```

**Fix.** Nothing to fix in the usual case; the finding is a warning that says where to look. Keep install scripts off by default in the package manager and allow them per package.

**Allow.** This is the check most projects write allow entries for. The default policy ships one as an example:

```yaml
allow:
  - check: install-script-present
    package: "npm:esbuild"
    reason: "downloads a native binary; reviewed by @vahap 2026-09-08"
    expires: 2027-03-01
```

A pattern such as `"cargo:*"` covers every crate when build scripts are not worth a warning in your project.

## TD007 new-dependency-introduced

**Detects.** Every runtime dependency the evaluated version declares that the previous release did not, or that the version the base lockfile locked did not. One finding per new dependency, so that each one is explained and escalated on its own. A dependency a plain install does not pull in is reported but never escalated, and the evidence marks it `optional`: a PyPI requirement behind an extra (`pip install pkg[socks]` and nothing else installs it) is the case this covers. Each new dependency is looked up through the registry and deps.dev, and the finding is raised to `block` when the dependency is young (its newest stable version, or the package's first release, is less than 7 days old), has low usage (weekly downloads below `low-usage.min_weekly_downloads`; no escalation on PyPI, which has no counts) or is unknown to deps.dev. The lookup reports the newest stable version rather than the one the requirement would resolve to: resolving a range needs the whole solver, so the explanation says what it actually looked at. A lookup error never escalates; the explanation says what could not be checked. A bump usually crosses more than one release, so the check compares with the version the base lockfile locked as well as with the release before this one, and the finding names the version that declared none of the dependency. A base version that could not be reached is a different thing from one the registry no longer has: the first leaves the second comparison unmade and the check reports itself as skipped naming it, the second is an answer and the check goes on with the release before this one alone. Skipped without a previous version. Applies to every ecosystem.

**Why it matters.** This is the pattern of the axios compromise of 31 March 2026: `axios@1.14.1` and `0.30.4` differed from the previous releases by one new dependency, `plain-crypto-js@4.2.1`, a package created for the attack that carried the remote access trojan ([axios post mortem](https://github.com/axios/axios/issues/10636)). It is also the event-stream pattern of 2018: `event-stream@3.3.6` added `flatmap-stream`, a package with no history and no users ([Snyk post mortem](https://snyk.io/blog/a-post-mortem-of-the-malicious-event-stream-backdoor/)). In both cases the new dependency was days old and had almost no downloads, which is what the escalation looks for.

**Evidence.** Present in every finding unless marked.

| Key | Meaning |
|---|---|
| `previous_version` | the previous release, whether or not it is the version the finding names |
| `base_version` | the version the base lockfile locked, when `diff` knows one and it is not the previous release (`diff` only) |
| `introduced_since_base` | whether that version declared none of the dependency (`diff` only) |
| `dependency` | the new dependency's name |
| `requirement` | the version requirement the evaluated version declares |
| `optional` | true when a plain install does not pull the dependency in, which also means no escalation |
| `new_dependencies` | every dependency the evaluated version added, sorted |
| `escalated` | whether the level was raised to block |
| `escalation_reasons` | `young`, `low-usage` and `unknown-to-deps.dev`, those that apply |
| `resolved_version` | the pinned version, or the newest stable one otherwise (when resolved) |
| `published_at` | its RFC 3339 publish time (when known) |
| `first_published_at` | RFC 3339 time of the package's first release (when known) |
| `weekly_downloads` | the dependency's weekly downloads (when the registry has them) |
| `min_weekly_downloads` | the low-usage threshold applied (when one is configured) |
| `deps_dev_found` | whether deps.dev knows the resolved version (when looked up) |
| `inspection_errors` | loader errors, one sentence each (when any) |

**Example.** A benign one; the explanation shows the facts the escalation is decided on:

```
npm:parcel-bundler@1.2.1  BLOCK
  warn
    TD007 new-dependency-introduced: New dependency json5 (^0.5.1), not declared by 1.2.0
      1.2.0 declared 31 runtime dependencies; 1.2.1 adds json5 (^0.5.1). The newest stable version
      is json5@2.2.3, published on 2022-12-31T17:11:32Z (1347d19h9m31s ago); the package's first
      release dates from 2012-05-27T20:32:39Z (5217d15h48m24s ago); it has 205460792 weekly
      downloads; deps.dev knows json5@2.2.3. Nothing raises the finding above the configured level
```

An escalated finding ends with "The finding is raised to block because the dependency is young and has low usage" and the title carries the reasons.

**Fix.** Look at the new dependency the way you would look at a new direct dependency: run `trustdiff check` on it. A young package with a handful of downloads pulled in by a popular one is the signature of the two incidents above; do not install until the maintainer has explained it.

**Allow.**

```yaml
allow:
  - check: new-dependency-introduced
    package: "npm:parcel-bundler@1.2.1"
    reason: "json5 is a well known parser, added for the .parcelrc format"
    expires: 2018-06-01
```

An entry is matched against the package the finding is about, which is the version
being evaluated and not the dependency it added, so the entry above covers every
dependency `parcel-bundler@1.2.1` declares that `1.2.0` did not. A pattern naming
`json5` covers nothing, because `json5` is not the package being checked. Pin the
version in the pattern, as above, so that the next release is judged again.

## TD008 typosquat-suspect

**Detects.** A package whose name looks like a misspelling of a popular package in the same ecosystem. The name is compared with the ecosystem's popular list (an embedded snapshot of about 14 900 npm names, 14 900 PyPI names and 5 000 crates, fetched on 2026-09-09 from the sources named in `internal/typosquat/data`, or a refreshed copy under the cache directory when it is less than 30 days old) using edit distance with a length-based threshold, adjacent transpositions, separator swaps, npm scope confusion, `py`, `python`, `js` and `node` affixes, digit and letter confusables and common-word insertions. A name that is itself popular is never a suspect. A match is reported at the level the policy sets only for a candidate that could still be a squat: one whose first release is less than a year old, or whose weekly downloads are below `low-usage.min_weekly_downloads`. A package that is neither is one a project has been living with, and it is reported at `warn` however the policy is set, because failing a gate on a name a project has installed for years is a cost with no finding behind it. One thing takes that back: how far behind the name it resembles the candidate is. Where the registry gives weekly downloads for both and the neighbor has a hundred times the candidate's, the demotion does not apply, because a package that far behind the name it imitates is where a typo lands whatever its age. A fact the run could not read never lowers the level, so a registry that did not answer leaves the finding where the policy put it, and a neighbor nobody could count vetoes nothing. One thing takes the veto back in turn: a name cannot have been registered to catch the typos of a name that did not exist yet, so a candidate whose first release is earlier than the neighbor's keeps its demotion whatever the gap, and its evidence carries `existed_before`. For a scoped popular name the threshold is read from the bare half alone: a scope is shared by every package inside it, so it is not the part a squatter imitates, and while the whole spelling decided, `@loaders.gl/` cleared the ten-rune line on its own and every package in that scope was two edits from every other one in it. The distance is still measured over the whole name, so a misspelled scope costs its edits like any other. As a cross-check, deps.dev's similarly named packages are consulted; a neighbor that is much more popular is added to the evidence and reported on its own when no rule matched. Where a rule did match, the finding stands on the popular list alone and a deps.dev outage changes nothing. Where no rule matched and the cross-check could not be made, the check reports itself as skipped rather than as a clean name: the list is embedded and cannot fail, so a name it does not resemble is half an answer, and the cross-check is the half that catches a look-alike the list has no entry for. An ecosystem deps.dev does not index is an answer rather than an outage, and the list then settles it. Skipped for an ecosystem without a popular list. Applies to every ecosystem.

**Why it matters.** In July 2017 a user published about forty packages under names one character away from popular ones; `crossenv`, the look-alike of `cross-env`, sent the environment variables of every machine that installed it to the attacker's server and went unnoticed for two weeks ([npm, 1 August 2017](https://blog.npmjs.org/post/163723642530/crossenv-malware-on-the-npm-registry)). The `plain-crypto-js` of the 2026 axios compromise borrowed the name of `crypto-js` for the same reason. Note the limits: the rules match `crossenv`, but a made-up prefix such as `plain-` is not in the common-word list, so `plain-crypto-js` was caught by TD009 and TD012 rather than by this check.

**Evidence.**

| Key | Meaning |
|---|---|
| `candidate` | the evaluated name in canonical spelling |
| `neighbor` | the popular name it resembles (when a rule matched) |
| `rule` | the rule that matched: `separator-swap`, `scope-confusion`, `language-affix`, `confusable-characters`, `common-word`, `transposition` or `edit-distance` (when a rule matched) |
| `distance` | the Damerau-Levenshtein distance to the neighbor (when a rule matched) |
| `list_fetched` | the date of the popular list consulted, `yyyy-mm-dd` |
| `deps_dev_neighbor` | a similarly named, much more popular package deps.dev returned (when the cross-check found one) |
| `standing` | what the level turned on: `young`, `low-usage`, `established`, `overshadowed`, `age-unknown` or `usage-unknown` |
| `weekly_downloads` | the candidate's weekly downloads (when the popularity gap decided the level) |
| `neighbor_weekly_downloads` | the neighbor's weekly downloads over the same week (when the popularity gap decided the level) |
| `existed_before` | a much more popular neighbor the candidate was on the registry before, whose gap therefore vetoed nothing |

**Example.** The 2017 package. npm removed the malicious versions, but the name is still registered and still collects scanner traffic, which is enough to clear both the year and the low-usage threshold. The distance to `cross-env` is what tells it apart. Captured live on 2026-09-11:

```
npm:crossenv@6.1.1  BLOCK
  block
    TD008 typosquat-suspect: "crossenv" resembles the popular npm package "cross-env"
      "crossenv" is not among the 17338 most popular npm packages but differs from "cross-env" only
      in separators (rule separator-swap, edit distance 1); deps.dev also lists the much more
      popular "cross-env" as a similarly named package. The package has been on the registry since
      2017-07-19T04:21:00Z and has 934 weekly downloads, but "cross-env" has 13403836, which is
      14351 times as many. A package that far behind the name it resembles is where a typo lands
      whatever its age, so the level stays at the configured one
```

Fourteen thousand times is what a squat looks like from the inside. The five names the largest lockfile in this repository still has flagged sit at the other end of the same scale: `css-font-parser` is the furthest behind its neighbor of the five, at fifteen times, and the rest are within a factor of seven. Two orders of magnitude separate the two groups, which is the room the hundredfold line sits in.

**Fix.** Check that you meant this package and not its neighbor. If you did, the finding is a false positive of the rules, which is what the allow entry is for.

**Allow.**

```yaml
allow:
  - check: typosquat-suspect
    package: "npm:crossenv"
    reason: "the fork is intended; it is not cross-env"
```

## TD009 malicious-advisory

**Detects.** A version that OSV lists under a malicious-package advisory (an id starting with `MAL-`, imported from the OpenSSF `malicious-packages` repository) or that deps.dev flags with a `MALICIOUS` finding. The two sources are consulted independently: when one of them was unavailable it runs on the other and the explanation says which source could not be consulted, and when neither found anything it passes only if both of them answered, otherwise it is skipped naming the source that was down. Applies to every ecosystem and blocks by default.

**Why it matters.** Once a compromise is public, the advisory is the cheapest signal there is, and it keeps protecting the people who install an old lockfile years later. Both packages of the event-stream incident carry advisories today, as does `plain-crypto-js` from the 2026 axios compromise ([MAL-2026-2306](https://osv.dev/vulnerability/MAL-2026-2306)). The limit is latency: an advisory exists only after someone found the package, which for axios took hours and for event-stream took weeks. The history-relative checks above are for the time in between; trustdiff does not try to beat commercial malware feeds at their own game.

**Evidence.**

| Key | Meaning |
|---|---|
| `advisories` | every malicious OSV advisory, sorted by id, as `{id, url, summary, aliases}` (`url`, `summary` and `aliases` are present when the advisory carries them) |
| `deps_dev_findings` | every deps.dev `MALICIOUS` finding as `{type, risk, detail}` (`risk` and `detail` are present when deps.dev returned them) |
| `sources` | the sources that answered, in this order: `osv`, `deps.dev` |
| `unavailable` | the source that could not be consulted, when one was: `osv` or `deps.dev` |

**Example.** The package behind the 2018 event-stream backdoor:

```
npm:flatmap-stream@0.1.1  BLOCK
  block
    TD009 malicious-advisory: malicious-package advisory MAL-2025-20690
      OSV lists 1 malicious-package advisory for npm:flatmap-stream@0.1.1: MAL-2025-20690 (Malicious
      code in flatmap-stream (npm)) at https://osv.dev/vulnerability/MAL-2025-20690; deps.dev flags
      npm:flatmap-stream@0.1.1 as malicious: MALICIOUS finding (RISK_CRITICAL)
```

**Fix.** Do not install it. If it is already installed, treat the machine and every credential on it as exposed; the advisory's references say what the payload did.

**Allow.** Possible, but there is no good reason for it. A wrong advisory should be reported upstream at the `malicious-packages` repository.

## TD010 vulnerability

**Detects.** Every OSV advisory that affects the version and whose severity is at or above `vulnerability.min_severity` (default `high`), one finding per advisory, most severe first. The severity is the advisory's own label when it has one (GHSA advisories carry LOW, MODERATE, HIGH or CRITICAL); otherwise the CVSS v3.0 or v3.1 base score is computed from the vector. Malicious-package advisories belong to TD009 and are left out. Skipped when OSV was unavailable; deps.dev `VULNERABLE` findings are not used as a substitute because they miss advisories OSV has. Applies to every ecosystem.

Limitation in 0.1.0: an advisory whose only severity is a CVSS v4 vector reports `unknown`, and an unknown severity counts as `medium`. It is therefore reported under a `low` or `medium` threshold and passes the default `high` one. CVSS v4 scoring is on the list in `docs/PLAN.md` section 13.

**Why it matters.** A known vulnerability in a version you are about to install is the oldest supply-chain problem and still the most common. The prototype pollution in lodash below 4.17.12 ([GHSA-jf85-cpcp-j695](https://osv.dev/vulnerability/GHSA-jf85-cpcp-j695), CVE-2019-10744, critical) sat in one of the most depended-on npm packages; a threshold on severity keeps the check useful in projects with many transitive dependencies.

**Evidence.** One finding per advisory.

| Key | Meaning |
|---|---|
| `advisory_id` | the OSV id |
| `aliases` | other identifiers of the same advisory (CVE ids), when any |
| `severity` | the severity as reported: `unknown`, `low`, `medium`, `high` or `critical` |
| `effective_severity` | the severity compared with the threshold (`unknown` counts as `medium`) |
| `score` | the CVSS base score, when the advisory carries one |
| `summary` | the advisory's one-line summary, when any |
| `url` | the advisory page, when known |
| `min_severity` | the threshold applied |

**Example.** The advisory GitHub filed for the 2021 ua-parser-js hijack:

```
npm:ua-parser-js@0.7.29  BLOCK
  block
    TD010 vulnerability: GHSA-pjwm-rvh2-c87w: high severity vulnerability (CVSS 8.8)
      OSV advisory GHSA-pjwm-rvh2-c87w (CVE-2021-4229) affects npm:ua-parser-js@0.7.29 with severity
      high (CVSS 8.8): Embedded malware in ua-parser-js, see
      https://osv.dev/vulnerability/GHSA-pjwm-rvh2-c87w; the policy reports vulnerabilities of
      severity high or above (vulnerability.min_severity)
```

**Fix.** Upgrade to a version outside the affected range; the advisory page lists it.

**Allow.** Lower or raise the threshold in the policy (`vulnerability: { level: block, min_severity: critical }`), or allow a reviewed advisory for one package:

```yaml
allow:
  - check: vulnerability
    package: "npm:lodash@4.17.11"
    reason: "the vulnerable function is not reachable from this project"
    expires: 2026-12-31
```

An allow entry covers every finding of the check for that package, so keep the pattern narrow.

## TD011 deprecated-or-yanked

**Detects.** A version the registry yanked or deprecated, a package deprecated or archived as a whole, or a version deps.dev marks deprecated. npm carries a per-version `deprecated` message, PyPI a per-release `yanked` flag with a reason, crates.io a per-version `yanked` flag with a `yank_message`. The registry and deps.dev are consulted independently like TD009, and like TD009 it is skipped rather than passed when nothing fired and one of the two could not be reached. Applies to every ecosystem and warns by default.

**Why it matters.** A yank is the registry's way of saying that a version should not be installed fresh: a broken build, a wrong dependency, a leaked secret or a compromise. A deprecation of the whole package says nobody maintains it, which is how event-stream got handed to a stranger in 2018 ([npm, 26 November 2018](https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident)). Either way the version you are looking at is one its own maintainers moved away from.

**Evidence.**

| Key | Meaning |
|---|---|
| `signals` | which signals fired, in this order: `yanked`, `version-deprecated`, `package-deprecated`, `deps-dev-deprecated` |
| `yanked` | `true` when the registry yanked the version |
| `version_deprecated` | the registry's deprecation message for the version, when set |
| `package_deprecated` | the registry's deprecation or archival message for the package, when set |
| `deps_dev_deprecated` | `true` when deps.dev marks the version deprecated |
| `deps_dev_reason` | the reason deps.dev gives, when it gives one |
| `unavailable` | the source that could not be consulted, when one was: `registry` or `deps.dev` |

**Example.**

```
npm:request@2.88.2  WARN
  warn
    TD011 deprecated-or-yanked: 2.88.2 is deprecated
      the registry deprecated version 2.88.2: "request has been deprecated, see
      https://github.com/request/request/issues/3142"; the registry deprecated the whole package
      request: "request has been deprecated, see https://github.com/request/request/issues/3142";
      deps.dev marks the version deprecated: "request has been deprecated, see
      https://github.com/request/request/issues/3142"
```

**Fix.** Move to the version or package the deprecation message points at. A yanked version that is already in your lockfile keeps installing; replace it before it disappears.

**Allow.**

```yaml
allow:
  - check: deprecated-or-yanked
    package: "npm:request"
    reason: "replacement scheduled for Q1, tracked in issue 42"
    expires: 2027-03-31
```

## TD012 low-usage

**Detects.** A package few people install: weekly downloads below `low-usage.min_weekly_downloads` (default 500). npm gives a weekly figure; crates.io gives 90-day recent downloads, reduced to a weekly figure; PyPI publishes no counts, so there the check uses a deps.dev `LOW_USAGE` finding when there is one and is skipped otherwise. A count that is missing because the request for it failed is not the same thing: the check is then skipped even when deps.dev answered, since nothing was compared with the threshold. Applies to every ecosystem and is `info` by default.

**Why it matters.** Low usage is not a problem by itself, but it is the common property of the packages that carried the payload in the incidents above: `flatmap-stream` had no users besides event-stream when it was added in 2018, and `plain-crypto-js` had none besides axios when it was added in 2026. It is also what makes a typosquat a typosquat. The count gives the other checks context, which is why the level is `info`, and it is one of the three reasons TD007 escalates a new dependency.

**Evidence.**

| Key | Meaning |
|---|---|
| `source` | where the signal came from: `registry` or `deps.dev` |
| `weekly_downloads` | the registry's weekly count (registry source only) |
| `min_weekly_downloads` | the policy threshold (registry source only) |
| `deps_dev_risk` | the `RISK_*` level of the `LOW_USAGE` finding, when deps.dev gave one (deps.dev source only) |
| `deps_dev_detail` | the finding's text, when deps.dev gave one (deps.dev source only) |

**Example.**

```
npm:plain-crypto-js@4.2.1  BLOCK
  info
    TD012 low-usage: 8 weekly downloads, below 500
      the registry reports 8 downloads in the last week for npm:plain-crypto-js, below the policy
      threshold of 500 (low-usage.min_weekly_downloads)
```

**Fix.** Nothing by itself. Read the package before depending on it; small packages are where a review is actually possible.

**Allow.** Set the threshold for your project (`low-usage: { level: info, min_weekly_downloads: 100 }`), or turn the check off with `low-usage: off`. Internal packages are better handled with an allow entry using a pattern such as `"npm:@myorg/*"`.

## TD013 exotic-source

**Detects.** A lockfile entry that does not come from the ecosystem's registry: a git repository, a tarball or archive URL, a directory on the machine, or an origin the file does not state. Default `block`, every ecosystem. It reads the lockfile entry rather than the registry, so it is skipped for a ref named on the command line, which has none, and for the same reason it still runs for a package the registry does not know, where every other check is skipped. That case is the one it exists for: a git dependency is a name no registry answers. A private registry or a mirror is not exotic: the parsers recognize it by the share of the file's downloads it carries and record the entry as a registry install.

Two of the four sources are reported at `info` whatever level the policy sets for the check. A `path` entry is a directory on the machine, which is what a monorepo writes for a package it keeps in its own tree: Superset's lockfile has twenty five, and failing a gate on unmodified upstream code is how a check gets turned off. Where a lockfile marks the repository's own code as such, it is not an entry at all: uv's editable and virtual project, its workspace members, and Cargo's root package and members are dropped by the parser rather than reported, which is ten more of ripgrep 14.1.1 that no longer reach a report. An `unknown` entry is usually an npm bundled dependency, whose bytes ship inside the archive of the package that carries them and are covered by that package's hash. Both stay in the report, because an entry that does not come from the registry is worth seeing in a diff and the `source` key says which it is. An allow entry takes them out of the report altogether.

**Why it matters.** A version number is a promise that a registry keeps: the release is immutable, its hash is recorded, and a takedown reaches everyone who installs it later. A git or URL dependency keeps none of that. A branch or tag moves, so the code installed today is not the code reviewed yesterday, and nothing in this tool or in the registry can tell you it changed. It is also how a dependency escapes every other check here: a package installed from a URL has no publisher history, no provenance and no advisory to match. Real projects do use git dependencies deliberately, which is what the allow list is for; what this check refuses to do is let one arrive unnoticed in a pull request.

An npm entry whose name npm's own grammar refuses is reported too, at the level the policy sets and never capped at `info`. The rules are the errors of `validate-npm-package-name`, the grammar npm holds the packages that already exist to, uppercase included. A name that breaks one cannot be on the registry, so whatever the entry installed came from somewhere else, and trustdiff asks no server about it: a name like that carries meaning into a request URL, where a `?` starts a query and a `..` is resolved away. Every check that reads the registry is skipped with `not a valid npm name`, which is an answer rather than an outage, so it does not count toward `on_data_unavailable`. `trustdiff check` refuses such a name on the command line with exit code 2. One rule of that grammar is left out on purpose: it refuses a leading hyphen, and the registry serves a package named `-` that predates the rule.

**Evidence.**

| Key | Meaning |
|---|---|
| `source` | where the entry was resolved from: `git`, `url`, `path` or `unknown` |
| `resolved` | the location as the lockfile records it, absent when the file states none |
| `lockfile` | the lockfile the entry came from, absent when the subject carries no location |
| `signal` | `invalid-name` when the finding is about the name rather than the source |
| `name_rule` | the rule of npm's name grammar the name breaks, in npm's own words (with `signal`) |

**Example.**

```
npm:some-tool@2.1.0  BLOCK  (package-lock.json:412)
  block
    TD013 exotic-source: Installed from git, not from the registry
      package-lock.json resolves some-tool@2.1.0 from
      git+ssh://git@github.com/example/some-tool.git#4f2a1c9, not from the npm registry, so the
      version number promises nothing about what is installed
```

**Fix.** Publish the dependency to the registry, or vendor it into the repository where it is reviewed like the rest of the code. A git dependency that has to stay should at least be pinned to a full commit, which is what TD014 checks.

**Allow.** A workspace member or a deliberate git dependency:

```yaml
allow:
  - check: exotic-source
    package: "npm:@myorg/*"
    reason: "workspace members, resolved from the repository itself"
```

## TD014 integrity-missing

**Detects.** A lockfile entry with nothing to verify the download against. Two signals, each its own finding, both `warn` by default, every ecosystem:

- `missing-hash`: the entry records no integrity hash. A git entry pinned to a full commit is not reported, because the commit is the hash.
- `file-hashes-nothing`: nothing in the whole file asks for a hash, so it is reported once for the file rather than once per line. pip is the one manager whose hash rule is written per file, so this is a `requirements` file and nothing else.
- `plain-http`: the entry is resolved over `http://`, so the download is neither confidential nor authenticated whatever the hash says.

Like TD013 it reads the lockfile entry and is skipped for a ref named on the command line, and like TD013 it still runs for a package the registry does not know, so an entry nothing guards is reported whether or not the package was ever published.

A `requirements.txt` that asks for no hash at all is one finding for the file, not one per pin. pip enters hash-checking mode for the whole file as soon as one requirement carries a `--hash` or a line says `--require-hashes`, and refuses every unhashed requirement in it from then on, so a file that hashes nothing is one fact about the file: it verifies none of what it installs. A project with two hundred plain pins was getting two hundred copies of that sentence.

The finding sits on the entry nearest the top of the file among the ones the run evaluated, which is the line to start at, and every other pin of the file stays a subject in its own right and still runs every other check. Because it is one finding on one package, an allow entry naming that package silences it for the whole file, and the explanation says so. In a file that is hash checked, a requirement whose `--hash` was taken off is still reported on its own line, which is the case worth catching.

`pip-compile --generate-hashes`, or `--hash` lines written by hand, is what answers it.

**Why it matters.** The hash is what makes a lockfile a lock. Without it, an install repeats the resolution rather than the result: a registry that serves different bytes for the same version, a compromised mirror, or a proxy in between changes what you get and nothing notices. Plain http makes that trivial for anyone on the path.

Two entries are exempt because no hash could be there to begin with. A local directory is built from the working tree: nothing is downloaded, so nothing could be verified, and a hash a lockfile cannot record is not one it is missing. That such a dependency comes from a directory rather than a registry is worth reporting, and [exotic-source](#td013-exotic-source) reports it, at `info`. An npm bundled dependency is the other: the lockfile writes it with no location and no hash because its bytes ship inside the archive of the package that carries it, and that package's own entry holds the hash for both. An entry that states no origin at all is not exempt and is worth a glance in a pull request; the `source` key is there so telling these apart does not mean opening the lockfile.

The repository's own code is not an entry at all. uv writes the project it locked into the lockfile with a source naming its own directory, Cargo writes the root package and every workspace member with no source, and none of them is a dependency the project acquired: the parser drops them and says so in the lockfile's dropped list. A directory dependency at any other path is a dependency and stays one.

**Evidence.**

| Key | Meaning |
|---|---|
| `signal` | `missing-hash`, `file-hashes-nothing` or `plain-http` |
| `source` | where the entry was resolved from: `registry`, `git`, `url`, `path` or `unknown` |
| `integrity` | the hash the entry records, absent when it records none |
| `resolved` | the location as the lockfile records it, absent when the file states none |
| `lockfile` | the lockfile the entry came from, absent when the subject carries no location |

**Example.**

```
npm:internal-widget@1.4.0  WARN  (package-lock.json:88)
  warn
    TD014 integrity-missing: No integrity hash to verify the download against
      package-lock.json records no integrity for internal-widget@1.4.0, so an install repeats the
      resolution rather than the result and nothing checks that the bytes are the ones this
      lockfile was written against
```

**Fix.** Re-run the package manager's install so it writes the hash, or move the dependency to a registry that provides one. For `plain-http`, change the registry URL to https.

**Allow.** A local path dependency, which has no hash by nature:

```yaml
allow:
  - check: integrity-missing
    package: "npm:@myorg/ui"
    reason: "workspace member resolved from a directory, no artifact to hash"
```

## TD015 version-anomaly

**Detects.** A version number that does not fit the package's history. Two signals, each its own finding, both `info` by default:

- `jump`: the step from the previous release is far beyond the package's own cadence. The major must exceed the previous release's by more than one, or the minor by more than ten while the major is unchanged (1.4.2 to 9.9.9), and the step must also exceed the largest step between consecutive earlier releases, so a package that has jumped before is not reported for doing it again. Calendar versioning, recognized by a leading component that reads as a year, is judged against the calendar instead: a major step no larger than the years between the two publish dates, or a minor step no larger than the months elapsed inside one year, is the scheme at work rather than a jump.
- `out-of-order`: the version sorts below a release of its own line that was published earlier, so the upload is not the newest of that line (1.2.5 after 1.4.2). The line is the major, or the major and minor together while the major is 0. A maintenance release on an older line, which is the normal shape of a maintained project, is not reported.

Prereleases, yanked versions, versions without a publish time and versions that do not parse (semver for npm and crates.io, PEP 440 for PyPI) are left out of the comparison. Skipped without a version list, when the evaluated version is missing from it, does not parse or has no publish time, and when there is no earlier release. Applies to every ecosystem.

**Why it matters.** This is a consistency check, not a detector, and none of the incidents cited in this document would have tripped it on its own: the sabotaged `colors@1.4.1` and `faker@6.6.6` of January 2022 ([Snyk](https://snyk.io/blog/open-source-npm-packages-colors-faker/)) kept to ordinary steps, and so did every hijacked release above. What both signals are for is the version number that does not match how the package has behaved until now, which is worth a line on the card when something else on the same card looks wrong. Both rules are deliberately narrow, because the obvious forms fire constantly on healthy projects: parallel release lines (the ua-parser-js fixes `0.7.30` and `0.8.1` were published after `1.0.0`, [issue #538](https://github.com/faisalman/ua-parser-js/issues/538)) and calendar versioning would otherwise produce a finding on every release. That is also why the level is `info`: the finding adds context, it is not meant to fail a build.

**Evidence.**

| Key | Meaning |
|---|---|
| `signal` | `jump` or `out-of-order` |
| `version` | the evaluated version |
| `published` | its publish time, RFC 3339 |
| `previous` | the previous release (jump only) |
| `previous_published` | its publish time, RFC 3339 (jump only) |
| `major_step` | the major increase from the previous release (jump only) |
| `minor_step` | the minor increase from the previous release (jump only) |
| `earlier_releases` | how many earlier releases the cadence was read from (jump only) |
| `max_major_step` | the largest major increase between consecutive earlier releases (jump only) |
| `max_minor_step` | the largest minor increase between consecutive earlier releases that share a major (jump only) |
| `calendar` | true when the version numbers were read as calendar versioning (jump only) |
| `earlier_version` | the highest earlier-published release of the same line the version sorts below (out-of-order only) |
| `earlier_published` | its publish time, RFC 3339 (out-of-order only) |
| `earlier_above` | how many earlier-published releases of the same line sort above the version (out-of-order only) |

**Example.** Constructed, since a package that trips either rule is rare by design. A 1.x line that has moved in steps of five publishes 1.20.5 after 1.30.0:

```
npm:example@1.20.5  OK
  info
    TD015 version-anomaly: minor version jumps from 1.1.0 to 1.20.5
      npm:example@1.20.5 (published 2026-09-09) raises the minor from 1 to 20 within major 1 from
      the previous release 1.1.0 (published 2026-09-04); across the 8 earlier releases, consecutive
      releases raised the major by at most 0 and the minor by at most 5
    TD015 version-anomaly: 1.20.5 published after 1.30.0, which sorts above it
      npm:example@1.20.5 was published on 2026-09-09 but sorts below 1.30.0, published on
      2026-08-30; 2 earlier releases sort above it, so this upload is not the newest of its line
```

**Fix.** Nothing to fix. Make sure the version you are installing is the one you meant; an out-of-order upload inside one line is often a maintenance release you did not know existed.

**Allow.** `version-anomaly: off` in the policy, or an allow entry for a package whose numbering the rules keep misreading:

```yaml
allow:
  - check: version-anomaly
    package: "npm:example"
    reason: "renumbered the 1.x line after the 2.0 release was withdrawn"
```

## TD016 lockfile-entry-changed

**Detects.** A lockfile entry that changed without its version changing: another integrity hash, another source, or another resolved location. Default `block`, every ecosystem. Four signals, one finding:

- `integrity-changed`: the entry records another hash for the version it already locked.
- `integrity-removed`: the hash that guarded the version is gone.
- `source-changed`: the same version now installs from somewhere else, a registry install becoming a git or a URL one.
- `resolved-changed`: the same version resolves from another location, for an entry that is not a registry install.

It reads the two lockfile entries and nothing else, so it needs both sides of a diff. A ref named on the command line has no entry, an added entry has no base entry, and `scan` reads one file with nothing to compare it to; each of those is reported as skipped with which case it was. A version that moved is not its business and produces no finding: that is what every other check is about.

Two moves are stated rather than judged and never rise above `info`, whatever the policy sets: an entry that moved onto the registry, which is what a project does when it stops vendoring a dependency, and a directory that moved to another directory, which is a workspace being rearranged.

A registry entry's resolved location is not compared at all. It names the mirror the artifact was fetched through, and moving a project to a mirror rewrites every one of them without changing a byte of what is installed.

Two integrity strings that share no algorithm are a re-encoding, not a change. npm moved its lockfiles from sha1 to sha512, and a file rewritten by a newer installer carries the same artifact under the stronger one; only a shared algorithm with different digests is two different artifacts under one version.

**Why it matters.** Keep `lodash` at 4.17.21 and swap its `integrity` for the hash of another tarball, and until this check existed every other check agreed the version was fine, because it was. The version is the one thing that did not move, and every other check is about a version. A registry cannot serve two artifacts for one release, so the second hash did not come from the registry.

A `--hash` taken off one line of a `requirements.txt` is `integrity-removed` here, at `block`. pip refuses to install anything from a file once one requirement in it carries a hash, so such a change breaks the install as well as unguarding the line, and it is the shape a person stripping a hash by hand leaves behind.

An allow entry for `exotic-source` does not silence this. That entry says a git dependency is deliberate; it says nothing about that dependency being repointed at another repository afterwards.

**Evidence.** `signal`, and the pair the signal is about: `base_integrity` and `integrity`, `base_source` and `source`, or `base_resolved` and `resolved`. `lockfile` names the file and line the head entry sits on.

**Fix or allow.** Find out why the hash moved. If the lockfile was regenerated against a private mirror that repackages what it serves, the mirror is the thing to look at, because a mirror that changes the bytes is not a mirror. If the change is deliberate, an allow entry with a reason and an expiry:

```yaml
allow:
  - check: lockfile-entry-changed
    package: "npm:internal-fork"
    reason: "vendored fork republished under the same version while the upstream fix lands"
    expires: 2027-01-01
```

## TD017 version-downgraded

**Detects.** A lockfile entry whose version went backwards: the head file locks a release that sorts below the one the base file locked. Default `info`, every ecosystem.

It reads the two lockfile entries and nothing else, so it needs both sides of a diff. A ref named on the command line has no entry, an added entry has no base entry, and `scan` reads one file with nothing to compare it to; each of those is reported as skipped with which case it was.

The order is the ecosystem's own: PEP 440 for PyPI, semantic versions everywhere else, which is what each registry requires of a published release ([npm](https://docs.npmjs.com/cli/v11/configuring-npm/package-json), [cargo](https://doc.rust-lang.org/cargo/reference/manifest.html), [JSR](https://jsr.io/docs/package-configuration), [PyPI](https://packaging.python.org/en/latest/specifications/version-specifiers/), all read 10 September 2026). A lockfile can still hold a version string none of those orders, because an entry that installs from somewhere other than the registry records the specifier where the version goes (`workspace:packages/bun-types`, `github:example/pkg#<sha>`). Such a pair is reported as skipped naming both spellings, never as a pass.

One shape produces a finding a reviewer will want to dismiss, and it is why the default is `info` rather than `warn`. A lockfile that holds one name at several major versions pairs its entries by name once the versions themselves do not match, so a change that drops a 5.x copy and keeps a 4.x one can read as a downgrade of the entry that stayed. The finding names both versions, so it is one line to check and one line to answer.

**Why it matters.** Rolling a dependency back is how a project unships a fix. Every release between the two is gone, including security fixes with no advisory filed yet, and that is precisely the window this tool exists for: `vulnerability` reports the older release only once OSV knows about it. A rollback is also what an attacker does with write access to a lockfile and no need to publish anything, since both releases are genuine and every other check reads the version in front of it and agrees it is fine.

**Evidence.**

| Key | Meaning |
|---|---|
| `base_version` | the version the base lockfile locked |
| `version` | the version the head lockfile locks |
| `resolved` | the location the head entry names, when it names one |
| `lockfile` | the file and line the head entry sits on |

**Fix or allow.** Say why in the pull request, or move forward instead. A rollback held for longer than a review is what an allow entry with a reason and an expiry is for:

```yaml
allow:
  - check: version-downgraded
    package: "npm:some-lib"
    reason: "4.x until the 5.x regression upstream is fixed, tracked in #412"
    expires: 2027-01-01
```
