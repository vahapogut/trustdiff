# trustdiff

trustdiff is a single-binary command line tool that finds trust regressions in a project's dependency tree before they land. A trust regression is not a change in a package's code but a change in the signals that made the package trustworthy: a version published by an account that never published one before, a release that lost the provenance every earlier release had, a version that adds an install script or a dependency the previous one did not have, a name one keystroke away from a popular package, a version with a known malicious or vulnerable advisory. Each of these preceded a real incident (event-stream in 2018, ua-parser-js in 2021, Shai-Hulud in 2025, axios in 2026), and each is visible in registry metadata before anyone has looked at the code. Cooldowns buy time and malware feeds catch what is already known; trustdiff tells you, across npm (npm, pnpm, yarn, bun), PyPI (pip, uv, poetry) and crates.io, in one binary with no account and no telemetry, that a dependency's trust signals regressed relative to its own history.

Version 0.2.0 ships `check` for single packages and `diff` for pull requests, with the GitHub Action, the pre-commit hook and SARIF output. The package manager hardening audit (`doctor`, 0.3.0) and Deno/JSR support (0.4.0) follow; see the [roadmap](#roadmap).

## Demo

Two commands against the live registries, captured on 2026-09-09:

```
$ trustdiff check npm:express@4.19.2 pypi:requests cargo:serde
npm:express@4.19.2  OK

pypi:requests@2.34.2  OK
  skipped TD003: baseline required (arrives in M4)

cargo:serde@1.0.229  WARN
  warn
    TD006 install-script-present: Runs code at install time: build.rs
      1.0.229 ships a build script (build.rs), which cargo compiles and runs before building the
      crate
  skipped TD003: baseline required (arrives in M4)

3 subjects, 0 block, 1 warn, 0 info, 2 skipped checks. Exit code 0 (no blocking findings).
```

`flatmap-stream@0.1.1` is the package that carried the 2018 event-stream backdoor. npm removed it from the registry, so the history checks have nothing to compare and say so; the advisory and download checks still run (the other seven skipped lines are trimmed here):

```
$ trustdiff check npm:flatmap-stream@0.1.1
npm:flatmap-stream@0.1.1  BLOCK
  block
    TD009 malicious-advisory: malicious-package advisory MAL-2025-20690
      OSV lists 1 malicious-package advisory for npm:flatmap-stream@0.1.1: MAL-2025-20690 (Malicious
      code in flatmap-stream (npm)) at https://osv.dev/vulnerability/MAL-2025-20690; deps.dev flags
      npm:flatmap-stream@0.1.1 as malicious: MALICIOUS finding (RISK_CRITICAL)
    TD010 vulnerability: GHSA-9x64-5r7x-2q53: critical severity vulnerability (CVSS 9.8)
      OSV advisory GHSA-9x64-5r7x-2q53 affects npm:flatmap-stream@0.1.1 with severity critical (CVSS
      9.8): Malicious Package in flatmap-stream, see
      https://osv.dev/vulnerability/GHSA-9x64-5r7x-2q53; the policy reports vulnerabilities of
      severity high or above (vulnerability.min_severity)
    TD010 vulnerability: GHSA-mh6f-8j2x-4483: critical severity vulnerability (CVSS 9.8)
      OSV advisory GHSA-mh6f-8j2x-4483 affects npm:flatmap-stream@0.1.1 with severity critical (CVSS
      9.8): Critical severity vulnerability that affects event-stream and flatmap-stream, see
      https://osv.dev/vulnerability/GHSA-mh6f-8j2x-4483; the policy reports vulnerabilities of
      severity high or above (vulnerability.min_severity)
  info
    TD012 low-usage: 97 weekly downloads, below 500
      the registry reports 97 downloads in the last week for npm:flatmap-stream, below the policy
      threshold of 500 (low-usage.min_weekly_downloads)
  skipped TD001: registry: version info of npm:flatmap-stream@0.1.1: npm: flatmap-stream@0.1.1: not found in the registry
  ...

1 subject, 3 block, 0 warn, 1 info, 8 skipped checks. Exit code 1 (blocking findings).
```

## Install

With a Go toolchain (1.26 or newer):

```sh
go install github.com/vahapogut/trustdiff/cmd/trustdiff@latest
```

Or download a release from the [releases page](https://github.com/vahapogut/trustdiff/releases). Every release ships one archive per platform (`trustdiff_<version>_<os>_<arch>.tar.gz`, `.zip` on Windows), `checksums.txt`, its cosign bundle `checksums.txt.sigstore.json`, an SPDX SBOM per archive and GitHub build provenance. Download the archive for your platform together with the two checksum files and verify before you unpack; substitute the archive you downloaded for `trustdiff_0.2.0_linux_amd64.tar.gz`.

1. Verify the signature on the checksum file (cosign v3 or later). The identity is the release workflow of this repository, running on a version tag.

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
   (Get-FileHash .\trustdiff_0.2.0_windows_amd64.zip -Algorithm SHA256).Hash
   Select-String windows_amd64 .\checksums.txt
   ```

3. Verify the build provenance with the GitHub CLI.

   ```sh
   gh attestation verify trustdiff_0.2.0_linux_amd64.tar.gz \
     --owner vahapogut \
     --signer-workflow vahapogut/trustdiff/.github/workflows/release.yml
   ```

If any step fails, do not run the binary; [SECURITY.md](SECURITY.md) says where to report it. Homebrew (`brew install vahapogut/tap/trustdiff`) and Scoop (`scoop install trustdiff` from the bucket) arrive with 0.4.0.

## Three ways to use it

### 1. About to add a dependency

`trustdiff check <ecosystem>:<name>[@<version>]` prints one card per package: age, publisher continuity, maintainers, provenance, install scripts, dependencies added since the previous version, look-alike names, advisories, downloads. Without a version the latest non-prerelease version is evaluated. This is the 2018 handover of event-stream as the registry still records it:

```
$ trustdiff check npm:event-stream@3.3.5
npm:event-stream@3.3.5  BLOCK
  block
    TD002 publisher-changed: Published by right9ctrl, which published none of the previous 5 versions
      the previous 5 versions (3.3.4, 3.3.3, 3.3.2, 3.3.1, 3.3.0) were published by dominictarr;
      3.3.5 was published by right9ctrl, an account that published none of them
  warn
    TD003 maintainers-changed: Maintainers changed since 3.3.4: added right9ctrl
      3.3.4 listed dominictarr as maintainer; 3.3.5 lists dominictarr and right9ctrl: added
      right9ctrl

1 subject, 1 block, 1 warn, 0 info, 0 skipped checks. Exit code 1 (blocking findings).
```

The exit code is for scripts: 0 means no blocking findings, 1 means at least one finding at or above `--fail-on` (default `block`), 2 a usage or configuration error, 3 that a required data source was unavailable and the policy says `on_data_unavailable: fail`. Findings are never hidden by an error; what could not be evaluated is listed as skipped.

`--format json` writes the same run as a document with a published schema ([schema/report.v1.json](schema/report.v1.json)); fields are added within a schema version, never renamed:

```
$ trustdiff --format json check cargo:serde@1.0.210
{
  "schema": "trustdiff.report/1",
  "tool": {
    "name": "trustdiff",
    "version": "dev",
    "commit": "none",
    "date": "unknown",
    "go_version": "go1.26.8"
  },
  "policy": {
    "path": "",
    "cooldown": "3d",
    "fail_on": "block"
  },
  "subjects": [
    {
      "ref": {
        "ecosystem": "cargo",
        "name": "serde",
        "version": "1.0.210"
      },
      "evaluated": [
        "TD001",
        "TD002",
        "TD004",
        "TD006",
        "TD007",
        "TD008",
        "TD009",
        "TD010",
        "TD011",
        "TD012",
        "TD015"
      ],
      "skipped": [
        {
          "check": "TD003",
          "reason": "baseline required (arrives in M4)"
        }
      ],
      "findings": [
        {
          "id": "TD006",
          "name": "install-script-present",
          "level": "warn",
          "ref": {
            "ecosystem": "cargo",
            "name": "serde",
            "version": "1.0.210"
          },
          "title": "Runs code at install time: build.rs",
          "explanation": "1.0.210 ships a build script (build.rs), which cargo compiles and runs before building the crate",
          "evidence": {
            "script_names": [
              "build.rs"
            ],
            "scripts": {
              "build.rs": "build script runs at compile time"
            }
          }
        }
      ],
      "verdict": "warn"
    }
  ],
  "summary": {
    "subjects": 1,
    "findings": {
      "block": 0,
      "info": 0,
      "warn": 1
    },
    "skipped": 1,
    "exit_code": 0,
    "exit_meaning": "no blocking findings"
  }
}
```

### 2. A pull request gate

`trustdiff diff` evaluates only what a lockfile change adds or modifies, against a git base that defaults to the merge base with `origin/main`. It reads `package-lock.json`, `pnpm-lock.yaml`, `uv.lock` and `Cargo.lock`, and every finding carries the lockfile line the entry sits on:

```sh
trustdiff diff --format markdown
```

```
## trustdiff: 1 subject, 0 block, 2 warn, 0 info, 9 skipped checks

| Package | Level | Check | Finding | Location |
| --- | --- | --- | --- | --- |
| npm:demo-crypto-helper@1.0.2 | warn | TD001 young-version | Published 2d2h47m15s ago, inside the 3d cooldown | package-lock.json:32 |
| npm:demo-crypto-helper@1.0.2 | warn | TD006 install-script-present | Runs code at install time: postinstall | package-lock.json:32 |

Exit code 0 (no blocking findings).
```

In a workflow, write SARIF instead and let code scanning put those findings on the diff:

```yaml
- uses: vahapogut/trustdiff@v0.2.0
  with:
    fail-on: block
    format: sarif
```

The action downloads the pinned release, verifies it against checksums signed with cosign before running it, and uploads the SARIF. Or run the binary yourself:

```sh
trustdiff diff --base "$BASE_SHA" --format sarif > trustdiff.sarif
```

`trustdiff scan` evaluates every entry of every lockfile it finds, which is the first-adoption pass rather than the gate. `trustdiff hook install` writes a pre-commit hook that runs the same diff locally, and `.pre-commit-hooks.yaml` offers it to pre-commit users. Exceptions live in `.trustdiff.yaml` with a reason and an expiry date and are reviewed like code.

A note on what the gate compares against: the previous version of a package is the release before the one you are getting, and separately the version your project actually had. Upgrading across several releases makes those differ, and `diff` uses both, so a postinstall script that arrived two releases ago is still reported as new to your project.

### 3. Auditing a monorepo (0.3.0)

The `doctor` command arrives in 0.3.0. It will walk a repository, detect every package manager by lockfile, manifest and `packageManager` field, and print a scorecard of the native hardening settings: cooldown and install-script blocking on, off, or set with the wrong unit (npm counts days, pnpm and Yarn minutes, Bun seconds, uv, Deno and pip take ISO 8601 durations), with `doctor --fix` writing version-correct configuration with a diff preview and backups and `doctor --ci` exiting non-zero on drift:

```sh
trustdiff doctor
trustdiff doctor --fix
trustdiff doctor --ci
```

Today `trustdiff doctor` exits with code 2 and prints `trustdiff: doctor: not implemented in <version>`.

## Checks

Every check has a stable id, a name used in the policy file, a default level and the ecosystems it applies to. [docs/checks.md](docs/checks.md) has a section per check: what it detects, the incident it would have caught, the evidence keys, an example, how to fix and how to allow.

| Id | Name | Signal | Default | Ecosystems |
|---|---|---|---|---|
| [TD001](docs/checks.md#td001-young-version) | `young-version` | published less than `cooldown` ago | warn | all |
| [TD002](docs/checks.md#td002-publisher-changed) | `publisher-changed` | publishing account not among the previous 5 versions' publishers | block | npm, cargo; pypi in 0.4.0 |
| [TD003](docs/checks.md#td003-maintainers-changed) | `maintainers-changed` | maintainer set differs from the previous version | warn | npm; pypi and cargo in 0.4.0 |
| [TD004](docs/checks.md#td004-trust-downgrade) | `trust-downgrade` | provenance weaker than the previous version's | block | npm, pypi, cargo |
| [TD005](docs/checks.md#td005-install-script-introduced) | `install-script-introduced` | install script where the previous version had none | block | npm |
| [TD006](docs/checks.md#td006-install-script-present) | `install-script-present` | runs code at install time (npm scripts, `build.rs`, proc-macro, sdist-only release) | warn | all |
| [TD007](docs/checks.md#td007-new-dependency-introduced) | `new-dependency-introduced` | runtime dependency the previous version did not declare; block when it is young, low usage or unknown to deps.dev | warn | all |
| [TD008](docs/checks.md#td008-typosquat-suspect) | `typosquat-suspect` | name close to a popular package | block | all |
| [TD009](docs/checks.md#td009-malicious-advisory) | `malicious-advisory` | OSV `MAL-` advisory or deps.dev `MALICIOUS` finding | block | all |
| [TD010](docs/checks.md#td010-vulnerability) | `vulnerability` | OSV advisory at or above `min_severity` | block, min high | all |
| [TD011](docs/checks.md#td011-deprecated-or-yanked) | `deprecated-or-yanked` | version deprecated or yanked, package deprecated | warn | all |
| [TD012](docs/checks.md#td012-low-usage) | `low-usage` | weekly downloads below `min_weekly_downloads` | info | all |
| [TD013](docs/checks.md#td013-exotic-source) | `exotic-source` | lockfile entry from git, a tarball or a local path | block | all |
| [TD014](docs/checks.md#td014-integrity-missing) | `integrity-missing` | lockfile entry without a hash, or over plain http | warn | all |
| [TD015](docs/checks.md#td015-version-anomaly) | `version-anomaly` | version number jumps past the package's cadence or is published out of order | info | all |

An expired `allow` entry produces a warning of its own, [TD000](docs/checks.md#td000-expired-allow). Any check whose data is missing reports skipped with the reason, never a pass.

## Policy

`trustdiff policy init` writes a fully commented `.trustdiff.yaml` into the current directory and `trustdiff policy validate` checks one against the published schema ([schema/policy.v1.json](schema/policy.v1.json), also usable for editor completion). The file is found upward from the working directory, then under `$XDG_CONFIG_HOME/trustdiff/policy.yaml`; `--policy` names one explicitly; without any, the built-in defaults apply. Unknown keys are errors, so a typo cannot silently disable a rule. An excerpt:

```yaml
version: 1
cooldown: 3d                      # 12h, 3d, 1w, 3d12h, or ISO 8601 such as P3D
cooldown_exclude:
  - "npm:@myorg/*"
previous_versions_window: 5
checks:
  publisher-changed: block
  install-script-present: warn
  vulnerability: { level: block, min_severity: high }
  low-usage: { level: info, min_weekly_downloads: 500 }
allow:                            # reviewed exceptions, with a reason; expiry recommended
  - check: install-script-present
    package: "npm:esbuild"
    reason: "downloads a native binary; reviewed by @vahap 2026-09-08"
    expires: 2027-03-01
on_data_unavailable: warn         # or fail, which exits with code 3
ecosystems:
  cargo:
    cooldown: 7d
```

The complete file with every key and its default is [internal/policy/default.yaml](internal/policy/default.yaml). Precedence for a value that exists in several places: the command line flag (`--cooldown`, `--fail-on`), then the ecosystem override, then the policy value, then the built-in default.

Two environment variables matter: `TRUSTDIFF_CACHE_DIR` moves the disk cache (default: the `trustdiff` directory under the user cache directory; `trustdiff cache status` prints it) and `TRUSTDIFF_NOW`, an RFC 3339 time, fixes the run clock for reproducible runs. `NO_COLOR` and a non-terminal stdout disable color, as does `--no-color`. `--offline` reads only the cache and reports every check that needs the network as skipped.

## How it compares

Nobody should choose a supply-chain tool from a table written by one of the projects in it, so every cell below was checked on 2026-09-09 against the project's own repository, license file or documentation, and every project is linked. "Not documented" means the project's documentation does not say, not that the feature is absent. If a cell is wrong, open an issue.

| Project | Open source | Single binary | Ecosystems | History-relative checks | Lockfile diff | SARIF | Offline | Telemetry |
|---|---|---|---|---|---|---|---|---|
| trustdiff | Apache-2.0 | yes (Go, static) | npm, PyPI, crates.io; Deno and JSR in 0.4.0 | yes: publisher, maintainers, provenance, install script and dependencies, each against the package's own history | 0.2.0 | 0.2.0 | cache only; OSV mirror in 0.4.0 | none |
| [Socket Firewall Free](https://docs.socket.dev/docs/socket-firewall-free) | no: binary under the PolyForm Shield license | yes, as a wrapper (`sfw npm install`) | npm, yarn, pnpm, pip, uv, cargo | no: Socket's feed | no | no | no, needs Socket's API | always on, not configurable |
| [Aikido Safe Chain](https://github.com/AikidoSec/safe-chain) | AGPL-3.0 or commercial | no: Node.js proxy behind shell aliases | npm, yarn, pnpm, bun, pip, uv, poetry, pipx, pdm | no: Aikido's feed and a 48 h minimum age | no | no | no | none stated ("no build data shared") |
| [SafeDep pmg](https://github.com/safedep/pmg) | Apache-2.0 | yes, as a wrapper (Go) | npm, pnpm, yarn, bun, pip, pipx, poetry, uv | no: SafeDep's feed, a cooldown and an opt-in sandbox | no | no | no | anonymous usage data, opt-out |
| [Datadog scfw](https://github.com/DataDog/supply-chain-firewall) | Apache-2.0 | no: Python wrapper (`scfw run`) | npm, pip, poetry | no: OSV and Datadog's dataset, warns on recent publishes | no | no | no | optional log forwarding to Datadog, off by default |
| [tirith](https://github.com/sheeki03/tirith) | AGPL-3.0 or commercial | yes (Rust) | npm family, cargo, pip, gem, go, composer, dotnet, mvn, gradle | no: a signed reputation database | no | yes | yes, by design | none stated |
| [npq](https://github.com/lirantal/npq) | Apache-2.0 | no: Node.js | npm (yarn, pnpm as the installer) | partly: provenance regression, new maintainer, package age; npm only, mostly warnings | no | no | no | none ("does not collect any usage data") |
| [GuardDog](https://github.com/DataDog/guarddog) | Apache-2.0 | no: Python | PyPI, npm, Go, crates.io, RubyGems, GitHub Actions, VS Code extensions | no: static analysis and metadata heuristics | scans requirement and lock files, no git base | yes | no | not documented |
| [InstallGuard](https://github.com/jt-systems/installguard) | Apache-2.0 | yes (Rust, alpha) | npm, pnpm, yarn, PyPI | yes: publisher change, dist-tag churn, file-set diff | evaluates lockfiles, no git base documented | not documented | re-verification against a recorded snapshot | none stated ("no telemetry or hidden phone-home path") |
| [DepsGuard](https://github.com/arnica/depsguard) | MIT | yes (Rust) | configuration of npm, pnpm, yarn, bun, aube, uv, pip, poetry, Renovate, Dependabot | no: writes hardening settings, never evaluates packages | no | no | yes | not documented |
| [romnn/cooldown](https://github.com/romnn/cooldown) | MIT or Apache-2.0 | yes (Rust) | Go, Cargo, uv, pip, poetry, conda, pixi, npm, pnpm, yarn, bun, deno, bundler, hex, maven, gradle, SwiftPM | no: release age only | checks the resolved lockfile, no git base | no | not documented | not documented |
| Native cooldowns | part of each package manager | not applicable | each its own | no | no | no | yes | the manager's own |

Native cooldowns: npm [`min-release-age`](https://docs.npmjs.com/cli/v11/using-npm/config), pnpm [`minimumReleaseAge`](https://pnpm.io/settings), Yarn [`npmMinimalAgeGate`](https://yarnpkg.com/configuration/yarnrc), Bun [`minimumReleaseAge`](https://bun.com/docs/pm/cli/install), Deno [`minimumDependencyAge`](https://docs.deno.com/runtime/packages/supply_chain/), uv [`exclude-newer`](https://docs.astral.sh/uv/reference/settings/), pip [`--uploaded-prior-to`](https://pip.pypa.io/en/stable/cli/pip_install/), and Cargo's `min-publish-age`, nightly only as of September 2026 ([tracking issue](https://github.com/rust-lang/cargo/issues/17009)). Use them; trustdiff's `doctor` will check that they are set correctly, and the checks above cover what a cooldown does not.

## What trustdiff does not do

- It does not wrap, alias or replace your package manager, and it is not a registry proxy. Run it before an install or in CI; the install itself is unchanged.
- It does not compete with malware feeds on latency. Its advisory checks use OSV and deps.dev; a vendor feed will list a new malicious package earlier. The history-relative checks are for the hours before any feed knows.
- It does not sandbox install scripts and does not analyze package source code. GuardDog does the latter; trustdiff may call it in a later release.
- It is not a service: no dashboard, no account, no vendor feed, nothing sent anywhere.
- It does not do license compliance or SBOM generation.

## Roadmap

- 0.2.0: `diff --base <git-ref>` and `scan` over `package-lock.json`, `pnpm-lock.yaml`, `uv.lock` and `Cargo.lock`, findings on lockfile lines, TD013 and TD014, SARIF and markdown output, a composite GitHub Action, a pre-commit hook and `hook install`.
- 0.3.0: `doctor` with a scorecard of every package manager's native hardening settings, version-aware keys and units, `--fix` with diff preview and backups, `--ci`, and a lint for unpinned GitHub Actions.
- 0.4.0: `yarn.lock`, `bun.lock`, `deno.lock`, `poetry.lock` and hash-pinned `requirements.txt`, the Deno and JSR registries, `trustdiff baseline` for PyPI and crates.io maintainer diffs, offline advisories from the OSV mirror, a Bun security scanner adapter, Homebrew and Scoop.

The detailed plan with estimates is [docs/PLAN.md](docs/PLAN.md).

## Principles

- One static binary, no runtime, no vendor account.
- No telemetry, no auto-update, no analytics, no phone-home of any kind. The only network calls are the registry and advisory requests needed for the packages you ask about, and `--offline` turns those off too.
- Almost no dependencies of its own, because a tool about dependency risk should not add much of it: six third-party modules, enforced in CI.
- Anything that could not be evaluated is reported as skipped, never as a pass.
- Releases are reproducible, signed with cosign and attested with GitHub build provenance; [SECURITY.md](SECURITY.md) explains how to verify one and how to report a problem.

## Contributing

Bug reports, fixtures from real incidents, new checks and documentation fixes are welcome; [CONTRIBUTING.md](CONTRIBUTING.md) has the development setup and the procedure for adding a check. Security problems go through [SECURITY.md](SECURITY.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
