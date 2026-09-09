# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Until 1.0.0, a minor release may change command line behavior, the policy file format or the report schemas; such changes are listed under Changed.

## [Unreleased]

## [0.2.0] - 2026-09-09

The pull request gate. `diff` evaluates what a lockfile change adds or modifies and puts every finding on the lockfile line it belongs to, as SARIF for code scanning, as a markdown table for a comment, or as a card on a terminal.

### Added

- `diff [--base <git-ref> | --base-file <path>]` evaluates only the entries a lockfile change added or modified. The base defaults to the merge base with `origin/main`. Removed entries are listed and never fetched, and a change that touches no lockfile exits 0 saying so.
- `scan [<path>]` evaluates every entry of every lockfile under a path, saying first how much work that is.
- Lockfile parsers for `package-lock.json` (lockfileVersion 2 and 3), `pnpm-lock.yaml` (6 and 9), `uv.lock` and `Cargo.lock` (v3 and v4). Each entry carries where it was resolved from, its integrity hash, whether the project depends on it directly, and the line it sits on. An entry a parser cannot read is dropped with a reason rather than failing the file. [docs/adr/0002-lockfile-parsers.md](docs/adr/0002-lockfile-parsers.md) records why these are written here.
- TD013 `exotic-source` (block): a lockfile entry resolved from git or from a tarball URL. A private registry is recognized by the share of the file it serves, so it is not exotic. A local directory, which is what a monorepo writes for its own packages, and an entry whose origin the file does not state, which is usually an npm bundled dependency, are reported at info whatever level the policy sets: both belong in a diff, neither fails a gate on its own.
- TD014 `integrity-missing` (warn): a lockfile entry with no integrity hash, or resolved over plain http. A git entry pinned to a full commit carries its own integrity and is not reported.
- `--format sarif` writes SARIF 2.1.0 with one rule per check, a help link into `docs/checks.md`, the lockfile line as the result location and a stable fingerprint per finding, validated against the vendored schema in tests. `--format markdown` writes a pull request comment as one table.
- A composite GitHub Action with the inputs `version`, `base`, `policy`, `fail-on` and `format`. It downloads the pinned release, verifies it against checksums signed with cosign before running it, and uploads the SARIF. Inputs reach the shell through the environment, never through interpolation.
- `.pre-commit-hooks.yaml` with the `trustdiff-diff` hook, and `trustdiff hook install|uninstall` for a git pre-commit or pre-push hook. Install refuses to overwrite a hook it did not write; uninstall removes only its own.
- `diff` compares against the version the base lockfile locked as well as the release before the new one, which differ when a project upgrades across several releases (brief section 4.1). `install-script-introduced` uses both, so a script that arrived two releases ago is still reported as new to this project.
- `make demo` runs the gate over `testdata/demo-repo` offline with the clock pinned, which is the acceptance case: a change that adds a young package with a postinstall script.
- A lockfile no parser can read, and a directory a walk was refused, are named in a note beside the findings and follow `on_data_unavailable` for the exit code. A run that covered less than it was asked to never reads as a pass.
- Every value the markdown comment prints is escaped, because a lockfile in a pull request decides the package names and versions it carries. The SARIF fingerprint covers the check, the package, the lockfile path and the evidence that separates two findings of one check, so a re-run updates the annotation it already left.

### Changed

- `diff` and `scan` replace the placeholders that exited with code 2. `--format sarif` and `--format markdown`, which every command refused, now work.

## [0.1.0] - 2026-09-09

The first usable release: `check` evaluates package versions on npm, PyPI and crates.io and prints one verdict card per package. The other commands still exit with code 2 and name the release they arrive in.

### Added

- `check <ref>...` for `npm:`, `pypi:` and `cargo:` refs. A ref without a version resolves to the latest non-prerelease version and the report says so. Output as `human` (one card per package with the findings grouped by level, the skipped checks with their reasons, and a summary line) or `json` (the document described by `schema/report.v1.json`). Exit code 0 without blocking findings, 1 with them; `--fail-on` picks the level that counts.
- Registry clients under `internal/registry`: npm (full packument, per-version publisher, maintainers, scripts, dependencies and deprecation, `dist.signatures` and `dist.attestations`, weekly downloads), PyPI (project and release JSON, PEP 740 provenance, yanked releases, sdist-only detection) and crates.io (crate and versions with `published_by` and `trustpub_data`, owners, per-version dependencies, and the `.crate` archive verified against the registry checksum and inspected for `build.rs` and `proc-macro`, at one request per second with an identifying User-Agent). Every response is cached on disk; immutable per-version data is cached without expiry.
- Advisory clients under `internal/advisory`: OSV (`querybatch` in chunks of 1000 and per-advisory details; severity from the GHSA label or a CVSS v3.0 or v3.1 base score computed in-house; an advisory with only a CVSS v4 vector reports unknown, which counts as medium) and deps.dev (`versionbatch`, `findingsbatch`, similarly named packages), used as accelerator and cross-check, never as the only source.
- The check framework in `internal/checks`: one file per check, a loader that prefetches the batch sources once per run and memoizes every response, a subject carrying the version, its predecessor (the highest non-prerelease, non-yanked release published before it), the history window, advisories and deps.dev facts, bounded concurrency through `--jobs`, a per-check timeout, panic recovery, and the policy applied per finding: levels, `off`, allow entries, `cooldown_exclude` and the warning for an expired allow entry. A check whose data is missing reports skipped with the reason, never a pass.
- The checks, with their default levels: TD001 `young-version` (warn), TD002 `publisher-changed` (block; npm and crates.io), TD003 `maintainers-changed` (warn; npm, PyPI and crates.io report skipped until the 0.4.0 baseline), TD004 `trust-downgrade` (block), TD005 `install-script-introduced` (block; npm), TD006 `install-script-present` (warn), TD007 `new-dependency-introduced` (warn, raised to block when the new dependency is young, has low usage or is unknown to deps.dev), TD008 `typosquat-suspect` (block), TD009 `malicious-advisory` (block), TD010 `vulnerability` (block at severity `high` or above), TD011 `deprecated-or-yanked` (warn), TD012 `low-usage` (info, below 500 weekly downloads) and TD015 `version-anomaly` (info). TD013 `exotic-source` (block) and TD014 `integrity-missing` (warn) were accepted by the policy and started running in 0.2.0 with `diff`. `docs/checks.md` documents every check with its evidence keys.
- Typosquat detection for TD008: Damerau-Levenshtein distance with a length-based threshold, adjacent transpositions, separator swaps, npm scope confusion, `py`, `python`, `js` and `node` affixes, digit and letter confusables and common-word insertions, over embedded lists of the popular packages of each ecosystem (about 14 900 npm, 14 900 PyPI and 5 000 crates.io names, fetched on 2026-09-09 by `scripts/gen-toplists`; sources and licenses are recorded in `internal/typosquat/data`), with deps.dev's similarly named packages as a cross-check. A refreshed copy of a list under the cache directory is preferred while it is younger than 30 days.
- Version parsing in `internal/model/version`: semver for npm and crates.io, an in-house PEP 440 parser for PyPI, prerelease detection and ordering, and the history helpers that define the previous version and the publisher window.
- `httpcache` `Post` for idempotent JSON query endpoints (OSV `querybatch`, the deps.dev batches), cached, rate limited and retried like `Get`.
- Exit code 3 when the policy says `on_data_unavailable: fail` and a registry or advisory source was unavailable for one of the packages. The findings are still printed and the skipped checks say which source failed.
- `--offline` with a cold cache reports every check that needs the network as skipped and exits with the code the policy asks for.
- `--cooldown` on the command line overrides the policy file and its per-ecosystem overrides.
- `TRUSTDIFF_NOW`, an RFC 3339 time, fixes the run clock for reproducible runs and the demo. `TRUSTDIFF_CACHE_DIR`, which `cache status` and `cache clear` already honored, selects the cache `check` reads and writes.
- `go run ./scripts/record-fixture` and `make fixture` for recording registry responses into `testdata/`, with the recording date written next to them.
- Live integration tests in `internal/integration` behind the `integration` build tag (`make test-integration`), run weekly by CI against the real registries and asserting on response shape only.
- Documentation for the launch: `docs/checks.md`, the README with the comparison table, and a demo recording workflow (`.github/workflows/demo.yml`, `docs/demo.tape`).

### Changed

- `check` replaces the 0.0.1 placeholder that exited with code 2 for every invocation. A script that treated exit code 2 as "not implemented" now sees 0 or 1, and 3 with `on_data_unavailable: fail`.

## [0.0.1] - 2026-09-09

Project skeleton, published as a prerelease so that the release pipeline (checksums, SBOM, signatures, provenance) is exercised before the first usable version. Nothing evaluates packages yet; `check` arrives in 0.1.0.

### Added

- Command line skeleton with every command registered: `check`, `diff`, `scan`, `doctor`, `baseline`, `hook install|uninstall`, `cache status|clear|refresh-lists|refresh`, `policy init|validate` and `version`. Commands that a later milestone implements exit with code 2 and say which version they are missing from.
- Global flags `--format`, `--policy`, `--offline`, `--no-cache`, `--cooldown`, `--fail-on`, `--jobs`, `--no-color` and `-v`, with `NO_COLOR` and non-terminal detection; exit codes 0 (no blocking findings), 1 (blocking findings), 2 (usage or configuration error) and 3 (required data source unavailable and the policy says fail).
- `version` prints the release tag, commit, build date, Go version and platform, as text or as JSON with `--format json`.
- Policy file `.trustdiff.yaml`: `policy init` writes a fully commented default and `policy validate` checks a file against the published JSON Schema (`schema/policy.v1.json`). Unknown keys are errors, `allow` entries need a reason, and an expired `allow` entry produces a warning of its own.
- Disk cache for registry data under the user cache directory, with ETag and Last-Modified revalidation, per-host rate limiting, retries and a 10 second timeout; `cache status` and `cache clear`.
- `human` and `json` report formats. The JSON shape is published as `schema/report.v1.json` and is stable within a schema version.
- Continuous integration: lint, tests on Linux, macOS and Windows with Go 1.26 and 1.27, `govulncheck`, `gosec`, a binary size gate and a direct dependency budget gate.
- Signed releases: reproducible builds for Linux, macOS and Windows on amd64 and arm64, `checksums.txt`, an SBOM, cosign keyless signatures and GitHub build provenance. `SECURITY.md` explains how to verify a download.

[Unreleased]: https://github.com/vahapogut/trustdiff/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/vahapogut/trustdiff/releases/tag/v0.2.0
[0.1.0]: https://github.com/vahapogut/trustdiff/compare/v0.0.1...v0.1.0
[0.0.1]: https://github.com/vahapogut/trustdiff/releases/tag/v0.0.1
