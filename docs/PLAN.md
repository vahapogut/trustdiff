# trustdiff development plan

Status: approved 2026-09-09. Written before the first commit and revised the same day after a review against the brief.
Source: the project brief. "§N" always refers to a brief section; "section N" refers to this document.

Module path used throughout: `github.com/vahapogut/trustdiff` (the repository exists and is empty as of 2026-09-09).

Estimates are focused working hours for one person and include tests, docs and review. At 8 focused hours per day, M0 needs about 5 days and M1 about 10 working days (9 if task 1.14 moves to M2), which is over the §16 targets. The growth is deliberate: the release pipeline (signing, provenance, checksums) is exercised for real at v0.0.1 instead of at the public launch, and three pieces of work the brief requires but never names as tasks (schema validation, version parsing, integration tests) are made explicit. If time runs short, these slip first and the acceptance criteria never do: recall tuning in task 1.12, comparison table polish in task 1.15, and bare-manifest refs (task 1.14, which can move to M2).

## 1. Ground rules that shape every task

- Stdlib first. The six direct dependencies allowed by §15 are allocated now and no further module, including another `golang.org/x/*` package, enters without an ADR: `github.com/spf13/cobra` (CLI), `gopkg.in/yaml.v3` or its maintained continuation (see open question 8), `github.com/BurntSushi/toml`, `golang.org/x/term` (TTY and width detection), `golang.org/x/time` (per-host rate limiting), `golang.org/x/mod` (semver). Concurrency limits use a buffered-channel semaphore, not `x/sync`. Anything else stops the work and gets a written justification (§0.4).
- `CGO_ENABLED=0` always, no sqlite, caches are plain files.
- Tests never touch the network. Real registry responses are recorded once into `testdata/` and served with `net/http/httptest`. Live tests sit behind `//go:build integration` and run in their own CI job (§0.5).
- Fast-moving facts (registry fields, package manager config keys, units) are re-verified against the official docs right before the adapter or rule is implemented, and the verification date goes into a code comment next to the fact (§0.2). Never invent a registry field.
- No telemetry, no auto-update, no analytics. The README says so (§0.6).
- A milestone is done only when: tests pass, `golangci-lint` is clean, README documents the behavior, `CHANGELOG.md` has an entry, and the milestone's tag from the overview table exists. Conventional commits, small and focused: one commit per check, per parser, per doctor rule, and the splits named in the task tables (§0.3).
- Every ADR is written and committed before the code it governs (§0.9). ADR 0001 (schema validation) precedes the policy package, ADR 0002 (parser strategy) precedes the lockfile package, ADR 0003 (config edits) precedes the doctor readers and fixers.
- Globs in `cooldown_exclude` and `allow.package` use `path.Match` semantics (not `filepath.Match`, whose separator differs on Windows); `**` is unsupported and documented as such. Schema `pattern` values must be RE2-compatible because Go's `regexp` is RE2.

## 2. Milestone overview

| Milestone | Tag | Target (§16) | Estimate | Outcome |
|---|---|---|---|---|
| M0 Skeleton | v0.0.1 | 2 to 3 days | 38 h | Buildable and linted binary with `version`, `policy init|validate`, `cache status|clear`; v0.0.1 prerelease published with checksums, SBOM, signatures and provenance |
| M1 `check` | v0.1.0 | 1 week | 78 h (70 h if task 1.14 moves to M2) | npm, PyPI, crates.io verdict cards; TD001 to TD012 and TD015; public release with README, demo GIF and docs/checks.md |
| M2 `diff` + CI | v0.2.0 | 1 week | 40 h (48 h if task 1.14 moves in, after 2.6) | Lockfile diff gate with SARIF, GitHub Action, pre-commit hook, git hook |
| M3 `doctor` | v0.3.0 | 1 week | 34 h | Hardening scorecard, `--fix`, `--ci`, Actions SHA-pin lint |
| M4 Breadth | v0.4.0 | 1 to 2 weeks | 42 h | Remaining lockfiles, Deno/JSR, baseline, offline OSV, Bun scanner, brew and scoop |

Dependency order is strict: M0, then M1, then M2, then M3, then M4. Inside a milestone, tasks are listed in the order they are committed.

## 3. M0 Skeleton (v0.0.1)

Goal: every building block that is not a check exists, is tested, and has been released once through the real pipeline, so M1 is feature work only.

| # | Task | Deliverables | Est. |
|---|---|---|---|
| 0.0 | Toolchain | The machine has Go 1.24.4 and none of the required tools (checked 2026-09-09). Install `make`; install golangci-lint, goreleaser, cosign and syft as pinned binaries; `go install` pinned govulncheck, gosec and staticcheck; commit `.golangci.yml` (v2 schema, `version: "2"`) and `tools.mk` (pinned versions and install recipes). Versions from section 12 | 2 h |
| 0.1 | Repository bootstrap | `go mod init github.com/vahapogut/trustdiff` with the directive set to `go 1.26` deliberately (stable minus one, section 12; `GOTOOLCHAIN=auto` fetches it on the 1.24.4 machine), `LICENSE`, `.gitignore` (includes `.planning/`), `.editorconfig`, Makefile (`build`, `test`, `lint`, `snapshot`, `tools` via `include tools.mk`), README stub with the no-telemetry statement, `docs/adr/0000-template.md` | 1 h |
| 0.2 | Entry point and version | `cmd/trustdiff/main.go`; `internal/version` with `-ldflags` vars (version, commit, date) plus runtime Go version; `trustdiff version` | 1 h |
| 0.3 | CLI skeleton | `internal/cli`: root command with the §3 global flags (`--format`, `--policy`, `--offline`, `--no-cache`, `--cooldown`, `--fail-on`, `--jobs`, `--no-color`, `-v`); the final subcommand list registered (`check`, `diff`, `scan`, `doctor`, `baseline`, `hook install|uninstall`, `cache status|clear|refresh-lists|refresh`, `policy init|validate`, `version`), unimplemented ones exit 2 with "not implemented in <version>"; exit code constants 0/1/2/3; precedence rule documented: CLI flag, then ecosystem override, then policy file, then default; `--fail-on` decides which levels produce exit 1 while `never` still allows 2 and 3; structured logger to stderr behind `-v`; `NO_COLOR` and non-TTY detection via `x/term` | 3 h |
| 0.4 | Core model | `internal/model`: `Ecosystem`, `PackageRef` with parser for `eco:name[@version]` and PEP 503 normalization for PyPI, `VersionInfo`, `Publisher`, `Provenance`, `Finding`, `Level`, `Evidence`, `Subject`; table tests | 2 h |
| 0.5 | ADR 0001 schema validation | Decide how `policy validate`, the report golden tests and the SARIF tests validate against JSON Schema without a validator module. Decision to record: an in-house validator in `internal/jsonschema` supporting `type`, `enum`, `const`, `required`, `properties`, `additionalProperties`, `items`, `minItems`, `uniqueItems`, `oneOf`, `anyOf`, `allOf`, local `$ref` into `definitions` and `$defs`, `pattern` (RE2), and lenient `format`; this covers the §5 policy shape (check values are a string or an object, which needs `oneOf`) and the SARIF 2.1.0 schema. No Go module is added without the §0.4 stop-and-ask | 1 h |
| 0.6 | JSON Schema validator | `internal/jsonschema` per ADR 0001, tested against the vendored SARIF 2.1.0 schema (`internal/report/testdata/`, with source URL, download date and license header) and a small valid/invalid corpus | 4 h |
| 0.7 | Policy | `internal/policy` in three commits: (1) duration parser (`12h`, `3d`, `1w`, `P3D`) and `path.Match` globs; (2) typed config for §5, defaults, strict loading (unknown keys are errors via `yaml.v3` `KnownFields`), allow-list expiry that yields its own warn finding, per-ecosystem overrides, upward discovery then `$XDG_CONFIG_HOME/trustdiff/policy.yaml`; (3) `policy init` writing the fully commented default, `policy validate` using 0.6, `schema/policy.v1.json` embedded and published. Negative tests: unknown key, bad enum, bad duration, expired allow entry, allow entry without reason, rejected by both the typed decoder and the schema | 5 h |
| 0.8 | HTTP cache layer | `internal/httpcache` in two commits: (1) client with `x/time/rate` per-host limiter, retries with jitter, 10 s timeout, `User-Agent: trustdiff/<version> (+https://github.com/vahapogut/trustdiff)`; (2) disk cache under `os.UserCacheDir()/trustdiff` keyed by URL with ETag and Last-Modified revalidation and per-entry TTL, `--offline` (cache only, typed "offline" error), `--no-cache`; `cache status` and `cache clear` as thin wrappers over the cache directory; `httptest` fixture server tests | 4 h |
| 0.9 | Reports v1 | `internal/report`: `human` (cards grouped by level, width and color aware, closing summary line with counts and exit code meaning) and `json` implementing the full §10 shape from day one (`schema`, `tool`, `policy`, `subjects[].{ref, evaluated[], skipped[]{check, reason}, findings[]{id, name, level, title, explanation, evidence, location?{path, line}}}`, `summary`) so M2 adds data, not fields; `schema/report.v1.json`; golden tests include one subject with `location` and one with `skipped`; JSON output validated against the schema with 0.6 | 3 h |
| 0.10 | CI | `.github/workflows/ci.yml` with top-level `permissions: contents: read`: lint, test matrix (Go 1.26 and 1.27 on linux, macos, windows), `govulncheck`, `gosec`, a binary size gate (each binary under 15 MB) and a dependency budget gate (`go list -m -f '{{if and (not .Main) (not .Indirect)}}{{.Path}}{{end}}' all | grep -c .` prints at most 6); a separate `integration` job (`go test -tags integration ./...`) on schedule and `workflow_dispatch`, not required for merge, real tests arrive in task 1.8; every action pinned to a 40-char SHA (see open question 9 for the provenance exception); `.github/dependabot.yml` with `cooldown: default-days: 7` for gomod and github-actions | 3 h |
| 0.11 | Release pipeline | `.goreleaser.yaml`: linux, darwin, windows for amd64 and arm64; `-trimpath`, `CGO_ENABLED=0`, `-ldflags=-s -w`, `-buildvcs=false`, `SOURCE_DATE_EPOCH`, `mod_timestamp: '{{ .CommitTimestamp }}'`; `release: prerelease: auto`; archives, `checksums.txt`, SBOM via syft installed through a SHA-pinned installer, cosign v3 keyless signing in bundle format, build provenance per open question 9. `make snapshot` runs `goreleaser release --snapshot --clean --skip=sign,publish` locally. `release.yml` runs on `v*` tags with `contents: write` and `id-token: write` on the release job only | 5 h |
| 0.12 | Community and security docs | `SECURITY.md` (disclosure policy, and the SHA-pin exception if question 9 keeps the SLSA generator), `CONTRIBUTING.md` (dev setup and `make tools`; the how-to sections for fixtures, checks, parsers and doctor rules are added by tasks 1.1, 1.9, 2.2 and 3.3), `CODE_OF_CONDUCT.md`, issue and PR templates, `CHANGELOG.md` (Keep a Changelog) | 2 h |
| 0.13 | Tag and verify | Push `v0.0.1`; `release.yml` publishes it, then `gh release edit v0.0.1 --prerelease` marks it (`auto` keys off a version suffix); download a binary and verify `checksums.txt`, `cosign verify-blob` and the provenance | 2 h |

Acceptance: `go build ./...`, `go test ./...` and `golangci-lint run` are clean on the matrix; `trustdiff version`, `policy init`, `policy validate`, `cache status`, `cache clear` work; `trustdiff check` exits 2 with "not implemented in v0.0.1"; the v0.0.1 prerelease exists with checksums, SBOM, signatures and provenance verified from a downloaded binary.

## 4. M1 `check` for npm, PyPI, crates.io (v0.1.0)

Goal: the verdict card from §2 scenario 1 for three ecosystems, backed by recorded fixtures, released publicly with the README the brief describes.

| # | Task | Deliverables | Est. |
|---|---|---|---|
| 1.1 | Source interface and fixture tooling | `internal/registry/registry.go` (`Source` interface: `Versions`, `Owners`, returning `model.VersionInfo`); `go run ./scripts/record-fixture <url> <path>` (Go, so it runs on Windows) writing the recording date into a `testdata/README`; Makefile `fixture` target; CONTRIBUTING section "recording fixtures" | 2 h |
| 1.2 | Version parsing and history helpers | `internal/model/version`: semver via `x/mod/semver` (normalize the `v` prefix, strip build metadata) for npm and cargo; in-house PEP 440 parser using the PEP's canonical regex (RE2-safe) for PyPI; prerelease predicate; ordering; table tests. Generic helpers over `[]model.VersionInfo` per §4.1: previous version (highest non-prerelease, non-yanked, published before the evaluated one, by publish time) and the publisher window; table tests for prerelease and yanked exclusion and publish-time ordering. Needed by 1.9, 1.11 and 1.13 | 5 h |
| 1.3 | npm client | Full and abbreviated packument, scoped name encoding, `time`, per-version `_npmUser`, `maintainers`, `scripts`, `dependencies`, `deprecated`, `dist.attestations` and `dist.signatures` presence, downloads point and bulk endpoints. TTLs: packument 1 h, per-version publish times forever. Fixtures: healthy package, documented publisher-change case, install-script-introduced case, a `MAL-` listed version (npm replaces such packages with a security-holding placeholder, so the malicious signal in the acceptance test comes from the 1.6 OSV fixture and the packument fixture may be the placeholder) | 5 h |
| 1.4 | PyPI client | Project JSON, per-version JSON, simple index v1 JSON for upload times, PEP 740 provenance endpoint (404 means none), `ownership` object if present at verification time, `yanked`, sdist-only detection. TTLs: project JSON 1 h, per-version JSON and PEP 740 results forever. Fixtures include an sdist-only release | 4 h |
| 1.5 | crates.io client | Crate, versions with `published_by` and `trustpub_data` (presence and `verify` field, re-verified against a real crate, feeds TD004), owners, per-version dependencies; `.crate` download verified against `versions[].checksum` before inspection, streamed gzip and tar that stops once `<name>-<version>/Cargo.toml` and `build.rs` have been seen, capped at the crates.io size limit, result cached per version forever; 1 request per second limiter; identifying UA. Fixtures: a yanked crate, one small real crate with `build.rs`, one proc-macro crate, with attribution | 5 h |
| 1.6 | OSV client | `querybatch` in chunks of 1000, `vulns/<id>` details, `MAL-` detection, TTL 6 h. Severity: `database_specific.severity` when present (GHSA emits LOW, MODERATE, HIGH, CRITICAL); otherwise the CVSS v3.0 and v3.1 base score computed in-house and tested against the FIRST specification examples; v4-only advisories report `unknown` (counts as medium per §4) in v0.1 with the limitation recorded in `docs/checks.md#td010` and the MacroVector port listed in section 13. Shape verified against a live `GET /v1/vulns/GHSA-...` before implementing; fixtures | 4 h |
| 1.7 | deps.dev client | `versionbatch`, `findingsbatch`, `similarlyNamedPackages`, system mapping for npm, PyPI, crates.io; fixtures; used as accelerator and cross-check only | 3 h |
| 1.8 | Integration tests | `//go:build integration` tests for `npm:express`, `pypi:requests`, `cargo:serde`, one scoped npm package, OSV and deps.dev, asserting on response shape only; `make test-integration`; wired to the 0.10 integration job | 2 h |
| 1.9 | Check framework and runner | `internal/checks` in two commits: (1) `Check` interface, registry of checks, a `Loader` interface with `Prefetch(ctx, []PackageRef)` called once per run and reused later by `diff` and `scan`, `Subject` assembly (version, previous version, history window, advisories, deps.dev data), checks receive the loader so TD007 can query the introduced dependency's age, usage and deps.dev presence, `Subject.Now` injected by the runner with a hidden `TRUSTDIFF_NOW` override for tests and the demo, buffered-channel semaphore sized by `--jobs`, per-check timeout, `skipped` with reason on data unavailability; (2) policy application: levels, `off`, allow-list, cooldown excludes, ecosystem overrides, the 0.3 precedence rule with table tests for every level of the chain. CONTRIBUTING section "adding a check" | 7 h |
| 1.10 | Checks TD001 to TD007 | One file and one commit per check: `young-version`, `publisher-changed`, `maintainers-changed` (npm via per-version `maintainers`; pypi and cargo report `skipped: baseline required` until M4), `trust-downgrade`, `install-script-introduced`, `install-script-present`, `new-dependency-introduced` with escalation when the new dependency is young, low usage or unknown to deps.dev; table tests with fake sources; evidence objects stable for JSON | 6 h |
| 1.11 | Checks TD009 to TD012, TD015 | One file and one commit per check: `malicious-advisory`, `vulnerability` with `min_severity`, `deprecated-or-yanked`, `low-usage`, `version-anomaly` (cadence jump and out-of-order publish, using 1.2); table tests | 4 h |
| 1.12 | Typosquat TD008 | Three commits: (1) rules (Damerau-Levenshtein with length-based threshold, transpositions, separator swaps, scope confusion, `py`/`python`/`js`/`node` affixes, digit and letter confusables, common-word insertions) and property tests (no top-N name flags itself, symmetry); (2) `go run ./scripts/gen-toplists` fetching hugovk/top-pypi-packages, LeoDog896/npm-rank or wooorm/npm-high-impact, and crates.io `/api/v1/crates?sort=downloads&per_page=100` paginated to about 5000 at 1 request per second (URLs re-verified and recorded in a testdata README), writing `internal/typosquat/data/*.txt` with a NOTICE line per dataset; lookup order is the refreshed cache copy (TTL 30 d) then the embedded snapshot; `cache refresh-lists` tested with httptest and documented as about 50 crates.io requests; deps.dev neighbor cross-check; (3) recall test on a fixed sample of about 200 confirmed typosquats from the ecosyste-ms dataset, vendored with CC0 attribution, asserting at least 80 % recall | 8 h |
| 1.13 | `check` command | Ref parsing, latest non-prerelease resolution (1.2) with a note in the output, human and json output, exit codes, `--offline` behavior with skipped checks and `on_data_unavailable` | 3 h |
| 1.14 | Bare manifest refs | Done in M4, not M1: open question 10 moved it out, because a sibling lockfile answers the same question exactly and a range only has to be resolved where there is none. `check package.json`, `check pyproject.toml` and `check Cargo.toml` evaluate the file's direct dependencies at the version each declared range resolves to today. The matchers are in `internal/manifest` rather than the `internal/model/rangespec` proposed here, because they are read by nothing else: node-semver range sets, Cargo requirements, PEP 440 specifier sets and Poetry's mixture of the last two, resolved against the registry version list, with a declaration nothing can be resolved from listed beside the report with its reason | 8 h |
| 1.15 | Documentation, budgets and release | Three commits: (1) `docs/checks.md`, one section per TD id (what, why with the real incident, evidence, fix or allow); (2) README per §14: pitch, demo GIF of `check npm:express@4.19.2 pypi:requests cargo:serde` recorded with vhs (through a SHA-pinned vhs action or WSL, since vhs is not installed locally), install (`go install ...@latest`, release download with `checksums.txt` and `cosign verify-blob`), the three §2 scenarios with real output, short checks table, policy example, comparison table with all eleven competitors and the eight §14 columns, "what trustdiff does not do", roadmap; open the good-first-issue seeds that do not collide with planned work (homoglyph rule, README translations); (3) performance check (`check npm:express` under 2 s warm and 5 s cold against the fixture server), size and dependency gates green, CHANGELOG, `v0.1.0` tag and published release with signatures and provenance | 12 h |

Acceptance (§16 M1): `trustdiff check npm:express@4.19.2 pypi:requests cargo:serde` prints three cards; the recorded `MAL-` fixture yields exit 1; `--offline` with a cold cache yields skipped checks and the exit code the policy asks for; the v0.1.0 binary is under 15 MB with at most 6 direct dependencies.

## 5. M2 `diff` and CI integration (v0.2.0)

Goal: a PR gate that evaluates only what a lockfile change adds or modifies, with findings on the right lockfile lines in SARIF, runnable as a GitHub Action, a pre-commit hook and a git hook.

| # | Task | Deliverables | Est. |
|---|---|---|---|
| 2.1 | ADR 0002 parser strategy | In-house minimal parsers versus reusing `google/osv-scalibr` extractors; record the module count of osv-scalibr (`go list -m all`) as evidence against the §0.4 and §15 budgets; decision committed before any parser | 1 h |
| 2.2 | Lockfile model and line index | `internal/lockfile`: `Parser` interface (`Detect`, `Parse`), `Lockfile` and `Entry` (ref, resolved, integrity, direct, line), detection by file name, registry of parsers, and a shared line-index helper (`json.Decoder` `Token` plus `InputOffset` for JSON, a line scanner for TOML, `yaml.v3` node positions for YAML). CONTRIBUTING section "adding a lockfile parser" | 3 h |
| 2.3 | `package-lock.json` v2 and v3 | `packages` map, resolved and integrity, direct flag from the root entry, line numbers via the shared index; fixtures from real projects with attribution, one of them with at least 2000 entries so the 2.10 target is measurable | 4 h |
| 2.4 | `pnpm-lock.yaml` v6 and v9 | Importers for the direct flag, resolution and integrity, line numbers via node positions | 4 h |
| 2.5 | `uv.lock` | TOML, `source` table for registry versus git and url, `sdist` and `wheels` hashes, line numbers via the shared index | 3 h |
| 2.6 | `Cargo.lock` v3 and v4 | `source` (registry, git, path), `checksum`; root packages are the `[[package]]` entries without a `source`, their `dependencies` lists give the direct dependencies; line numbers via the shared index | 3 h |
| 2.7 | Git diff plumbing | `internal/gitdiff`: resolve the base with `git rev-parse --verify --end-of-options '<ref>^{commit}'` and reject failures, `git show --end-of-options <sha>:<path>`, fixed argv, no shell, G204 justification comment; merge-base with `origin/main`; `--base-file`; entry-level diff (added, changed, removed); the "previous version in the base lockfile" fed into the subject so both previous versions are reported when they differ (§4.1); tests run against a temporary repository created with `git init` | 3 h |
| 2.8 | Checks TD013, TD014 | `exotic-source`, `integrity-missing` (missing hash or plain http), with lockfile locations; one commit each | 2 h |
| 2.9 | SARIF and markdown | SARIF 2.1.0 with one rule per check, `helpUri` into `docs/checks.md`, level mapping, `physicalLocation` on the lockfile line, validated in tests against the schema vendored in 0.6; markdown PR table; golden tests for both formats on the 0.9 fixture subjects, LF-normalized | 4 h |
| 2.10 | `diff` and `scan` commands | `diff [--base <git-ref> | --base-file <path>]` (default merge-base with `origin/main`) evaluates only added and changed entries; `scan [<path>]` evaluates every entry of every detected lockfile; both honor `--format`, `--fail-on` and the 0.3 exit codes; every finding carries `location{path, line}`; registry, OSV and deps.dev calls go through the 1.9 `Prefetch` in batches; performance target (2000-entry lockfile with 50 changes under 15 s) measured with the fixture server | 4 h |
| 2.11 | Action, pre-commit, git hook | `action.yml` composite with inputs `version`, `base`, `policy`, `fail-on`, `format`: the default `version` is a fixed tag whose sha256 table is embedded in `action.yml`; other versions verify `checksums.txt` with `cosign verify-blob` (SHA-pinned cosign-installer, certificate identity of this repository's release workflow); inputs pass through `env:` and are quoted; SARIF upload via SHA-pinned `codeql-action/upload-sarif`. `.pre-commit-hooks.yaml` with hook id `trustdiff-diff`. `trustdiff hook install|uninstall` for pre-commit and pre-push | 4 h |
| 2.12 | Demo repo, self-test, release | `testdata/demo-repo` with base and head lockfiles committed; the demo package's fixture packument has a single version with a `postinstall` script; `make demo` builds a temporary git repository from them with the injected clock and prints the human report (never invoked by `go test`). Tag `v0.2.0-rc.1` as a prerelease; a self-test workflow points `action.yml` at the demo repo and the SARIF upload is verified on a PR; tag `v0.2.0`; commit "chore(action): pin v0.2.0 and checksums"; re-record the GIF with the `diff` scenario; docs; CHANGELOG | 5 h |

Acceptance (§16 M2): on `testdata/demo-repo` the branch that adds a young package with a `postinstall` produces SARIF with exactly two findings, TD001 and TD006, on that entry's lockfile lines (TD005 has no previous version to compare against and is listed as skipped); the Action runs green on this repository's own PRs.

## 6. M3 `doctor` (v0.3.0)

Goal: a scorecard of every package manager's native hardening settings in a repository, with version-correct keys and units, fixable in place.

| # | Task | Deliverables | Est. |
|---|---|---|---|
| 3.1 | Detection and fixture monorepo | Lockfile and manifest detection for every manager in §7, `packageManager` field, `--user` scope discovery. Versions are derived first from `packageManager`, `.yarnrc.yml` `yarnPath`, `.yarn/releases/*` and lockfile version markers; only then `<pm> --version` runs, from `os.TempDir()` with `COREPACK_ENABLE_AUTO_PIN=0` and `COREPACK_ENABLE_DOWNLOAD_PROMPT=0`, a 3 s timeout, fixed argv, no shell and a G204 justification, so repository-controlled binaries never execute and nothing is downloaded. Tests use a fake `PATH` directory with stub scripts. Fixture monorepo skeleton (npm 12, pnpm 11, yarn 4.15, bun 1.3, uv, pip, deno) reused by 3.4 to 3.7 | 5 h |
| 3.2 | ADR 0003 config edits | Edit strategy for YAML, ini, TOML, JSON and JSONC: `yaml.v3` and `encoding/json` are used only to locate keys (node line and column, decoder offset); the writer inserts or replaces specific lines and never re-serializes, verified by round-tripping a 2-space `pnpm-workspace.yaml` with blank lines. Also decides the doctor JSON shape: a subject of kind `config` with rule-level findings inside report.v1 (evidence carries manager, file, key, current, expected, unit), or a separate `schema/doctor.v1.json` if that does not fit | 1 h |
| 3.3 | Rules table and doctor policy | `{manager, minVersion, file, key, desired, unit, severity, fix}` rows for §7 with version-aware key selection (for example pnpm v10 `onlyBuiltDependencies` versus v11 `allowBuilds`), unit normalization across days, minutes, seconds and ISO-8601 durations, per-row "verified on" dates after re-checking the docs. The SHA-pin rule carries a built-in exception list (SLSA reusable workflows, local `./` actions) reported as "tag-pinned by design" plus a policy allow-list. The pip row is user or virtualenv scope (`--user`) with a repository-level recommendation (`PIP_CONFIG_FILE` or `--uploaded-prior-to` in CI), verified against pip's configuration docs. `internal/policy` and `schema/policy.v1.json` gain an optional `doctor:` section (`ci_min_severity`, per-rule `off`) additively, documented in the `policy init` comments. CONTRIBUTING section "adding a doctor rule" | 5 h |
| 3.4 | Config readers | In-house ini reader for `.npmrc` and `pip.conf` (`key=value`, `key[]=value`, `;` and `#` comments, `${ENV}` left unexpanded, `[section]` headers for `pip.conf`); `pnpm-workspace.yaml`, `.yarnrc.yml`, `dependabot.yml` and workflow files via `yaml.v3` nodes with positions; `bunfig.toml`, `pyproject.toml`, `uv.toml`, `poetry.toml` via TOML plus the line scanner; `deno.json`, `deno.jsonc`, `package.json` (`allowScripts`, `trustedDependencies`, `packageManager`) and `renovate.json` via an in-house JSONC pre-processor that strips comments and trailing commas while preserving byte offsets (shared with 4.1 for `bun.lock`). Readers surface only audited keys, redact values of keys containing token, auth, password or credential and any URL userinfo, and never log file contents | 6 h |
| 3.5 | Fixers | `internal/textdiff`, a line-based unified diff ported from Go's `internal/diff` with BSD attribution (no shell-out to git); atomic write, timestamped backup preserving the file mode, diff preview, idempotent re-run; package.json edits are line-based like the rest | 5 h |
| 3.6 | Scorecard and modes | Human, json and markdown scorecards (set, missing, wrong unit or too permissive, not applicable); `--fix`; `--ci` exits 1 on any missing or wrong item at or above `doctor.ci_min_severity`; the Cargo row reports "no stable cooldown yet (RFC 3923)" and recommends `cargo-deny`, `cargo-vet`, `cargo-audit`; doctor json per ADR 0003 and validated in golden tests | 5 h |
| 3.7 | Golden tests | `doctor --fix` on the fixture monorepo writes exactly the expected files, a second run changes nothing, `bunfig minimumReleaseAge = 10080` is flagged as a wrong unit with the corrected value in seconds, and this repository's own workflows pass `doctor --ci` | 5 h |
| 3.8 | Docs and release | README doctor section, CHANGELOG, bump the `action.yml` pin and checksums (standing post-release step), `v0.3.0` | 2 h |

Acceptance (§16 M3): `doctor --fix` on the fixture monorepo containing npm 12, pnpm 11, yarn 4.15, bun 1.3, uv, pip and deno configs writes exactly the expected files (golden); re-running is a no-op; wrong-unit configs are flagged with the corrected value.

## 7. M4 Breadth (v0.4.0)

Goal: the remaining lockfiles and ecosystems, the baseline that PyPI and crates.io maintainer checks need, a real offline mode, and the package channels.

| # | Task | Deliverables | Est. |
|---|---|---|---|
| 4.1 | Remaining lockfiles | `yarn.lock` (Berry), `bun.lock` (JSONC via the 3.4 helper), `deno.lock`, `poetry.lock`, hash-pinned `requirements.txt`; fixtures and line numbers; one commit per parser | 12 h |
| 4.2 | Deno and JSR adapter | Verify the JSR API against jsr.io docs and a live fetch, dated comments; recorded fixtures for `meta.json`, `<version>_meta.json` and the api.jsr.io package and version endpoints; a per-check applicability table for `jsr:` and `deno:` refs where checks without a source report `skipped: no source for jsr` (deps.dev has no Deno or JSR system; the OSV ecosystem list is verified before deciding TD009 and TD010); npm-via-deno entries map to the npm adapter | 7 h |
| 4.3 | Baseline | `internal/baseline`: `.trustdiff/baseline.json` in a format usable by every ecosystem; `trustdiff baseline` writes it; `diff` and `scan` write it only when `--update-baseline` is given; `diff` reads the baseline from the base git ref via `internal/gitdiff` and reports baseline changes made in the PR as evidence; PyPI TD002 and TD003 and cargo TD003 via baseline; maintainer changes without a version change | 6 h |
| 4.4 | Offline advisories | `cache refresh` downloads the OSV zips for the configured ecosystems and builds a compact plain-file index (name to affected ranges and advisory ids) once per download; `--offline` reads only the index; `cache status` shows index age; every check that cannot run reports `skipped: offline`; tests use a 3-advisory zip fixture served by httptest | 5 h |
| 4.5 | Bun scanner adapter | `integrations/bun-scanner/` with its own `package.json`, zero runtime dependencies, files whitelist and engines; Bun's Security Scanner API verified against the docs first; CI runs its tests in a separate job with Bun installed through a SHA-pinned action, offline; published only via npm trusted publishing (OIDC) with provenance from a SHA-pinned workflow; `@trustdiff` scope availability re-checked right before | 6 h |
| 4.6 | Package distribution | Create the `homebrew-tap` and `scoop-bucket` repositories, store a fine-grained token as a secret, dry-run on a prerelease, re-check the formula and manifest names right before; goreleaser configured with its current (non-deprecated) keys; README brew and scoop lines; bump the `action.yml` pin and checksums; CHANGELOG; `v0.4.0` | 5 h |
| 4.7 | Good first issues | Seed the remaining items: crates.io `db-dump` path for large audits, pnpm hook integration; confirm the M1 seeds (homoglyph rule, README translations) are still open | 1 h |

Acceptance: a `jsr:` ref prints a card with the applicable checks and the rest skipped with reasons; `diff` reports line numbers for each M4 lockfile; `--offline` with refreshed zips runs TD009 and TD010 from the index; `brew install` and `scoop install` from the published tap and bucket work.

## 8. Cross-cutting conventions

- Package layout follows §8 exactly. `internal/checks` depends on `internal/model` and small interfaces only; registry clients return typed structs; all network calls go through `internal/httpcache`.
- Each check, each lockfile parser and each doctor rule is a one-file addition by design, so contributors can add one without touching the rest.
- Every fixture in `testdata/` carries a README line with the source URL, recording date and license where one applies.
- Golden files are written with LF line endings and compared after normalizing CRLF so the Windows development machine and Linux CI agree.
- Performance budgets from §15 are checked with benchmarks that run against the fixture server, not the network.
- Every release from v0.2.0 on ends with the standing step "bump the `action.yml` pin and checksums".
- User-controlled values that reach a subprocess (git refs, package manager names) go through fixed argv with `--end-of-options` where the tool supports it, never through a shell.

## 9. Risks and mitigations

| Risk | Mitigation |
|---|---|
| crates.io limit of 1 request per second makes `scan` of a large `Cargo.lock` slow | Batch what deps.dev can answer first, cache immutable per-version data forever, document the expected duration, plan the `db-dump` path (task 4.7 seed) |
| Registry fields drift (PyPI `ownership`, npm `attestations`, pnpm keys) | Re-verify right before implementing, dated comments, fixtures recorded with the date, the integration job from 0.10 and 1.8 catches shape changes |
| JSON Schema validation without a library | ADR 0001 and task 0.6: in-house validator covering the schema subset used by the policy, report and SARIF schemas, tested against a valid/invalid corpus |
| Comment-preserving edits across YAML, ini, TOML, JSON and JSONC | ADR 0003: parsers locate, a line-based writer edits, diff preview and backup, never a full rewrite |
| CVSS v4 scoring | v0.1 reports `unknown` (counts as medium) for v4-only advisories and says so in docs; MacroVector port tracked in section 13 |
| Bare-manifest range resolution is a hidden multi-day task | Task 1.14 is explicit and can move to M2 (open question 10) |
| `slsa-github-generator` is no longer actively maintained and must be referenced by tag, which conflicts with SHA pinning | Open question 9; either alternative keeps SHA pinning everywhere or documents a single named exception |
| `gopkg.in/yaml.v3` is frozen and its repository archived | Open question 8 |
| Local toolchain gaps and Go 1.24.4 on the development machine | Task 0.0 with pinned versions, CI is the source of truth |
| Windows path and line ending differences | CI matrix includes windows, golden tests normalize line endings, paths built with `filepath` |
| Name collision | Verified 2026-09-09 (section 11); re-check `@trustdiff/bun-scanner`, the Homebrew formula and the Scoop manifest right before tasks 4.5 and 4.6; fallback name `installgate` |

## 10. Open questions (§17 plus three raised while writing this plan) and their answers

All ten were answered on 2026-09-09; the proposal column is the decision.

| # | Question | Decision |
|---|---|---|
| 1 | GitHub owner and module path | Settled: `github.com/vahapogut/trustdiff`, repository created 2026-09-08; registry name availability re-verified on 2026-09-09 (section 11) |
| 2 | License | Apache-2.0 (explicit patent grant, matches most tools in this space) |
| 3 | Default cooldown | 3 days, `cargo` override to 7 days as in the §5 example |
| 4 | `publisher-changed` default level and window | `block`, window 5; large-maintainer-set noise is handled by the allow-list and by TD003 staying at `warn` |
| 5 | Minimum Go version | 1.26 (stable minus one as of 2026-09-09, see section 12); CI matrix tests 1.26 and 1.27 |
| 6 | Ship `doctor` for npm and pnpm inside M1 | Keep the milestone order; `doctor` lands complete in M3 so the rules table is verified once |
| 7 | Exclusions from v0.1 | None proposed beyond what is already deferred (CVSS v4 scoring, Sigstore verification, GuardDog) |
| 8 | YAML module | `gopkg.in/yaml.v3` is frozen at v3.0.1 (2022) and go-yaml/yaml is archived; the maintained continuation is `go.yaml.in/yaml/v3` (v3.0.5, 2026-07, same API). Proposal: use `go.yaml.in/yaml/v3` and note the substitution in the README dependency list |
| 9 | Build provenance | `slsa-framework/slsa-github-generator` declares itself no longer actively maintained (last release v2.1.0, 2025-02) and requires tag references. Proposal: GitHub native provenance with `actions/attest-build-provenance` (v4.2.2), verified with `gh attestation verify`, which keeps SHA pinning everywhere |
| 10 | Bare manifest refs (task 1.14) | Proposal: move to M2 after the lockfile parsers, so a sibling lockfile supplies versions and in-house range resolution is the fallback; v0.1.0 accepts `eco:name[@version]` refs only; the deferral is noted in the M1 Goal line, the README and the v0.1.0 CHANGELOG entry |

Decisions taken in this plan without asking, accepted with the rest: `cache refresh-lists` (top-N lists, §3) and `cache refresh` (OSV zips, §11) are two subcommands; the policy file gains an additive `doctor:` section in M3; `poetry.lock` and `deno.lock` stay in task 4.1 as §16 M4 lists them and the good-first-issue seeds are the items no task claims.

## 11. Name availability, verified 2026-09-09

Every probe below is an observed HTTP status, not a guess.

| Namespace | trustdiff | installgate (fallback) |
|---|---|---|
| npm package, `@trustdiff` scope, user, punctuation variants | free | free |
| PyPI JSON and simple index, PEP 503 variants | free | free |
| crates.io, `-` and `_` variants | free | free |
| GitHub user or org | free | free |
| GitHub repositories with the exact name | ours, plus one unrelated 1-star repository in a different field | none |
| Homebrew core formula and cask | free | free |
| Go module namespace, JSR scope, deno.land/x | free | free (one unrelated `cmd/installgate` sub-package exists) |
| Docker Hub | free | one active third-party image |
| Linux, Windows and macOS package indexes (via Repology) | free | free |
| Domains | `.com` registered and parked since 2023, `.dev` and `.io` free | `.com`, `.dev`, `.io` free |

Decision: keep `trustdiff`. The only collision is the parked `.com` domain, which does not affect any distribution channel.

## 12. Toolchain versions observed on 2026-09-09

Pinned versions are chosen in task 0.0 from these observations and recorded in the Makefile and workflows.

| Tool | Version | Note |
|---|---|---|
| Go stable lines | 1.27.1, 1.26.8 | "stable minus one" is 1.26; the local machine runs 1.24.4 and fetches 1.26 through the `go` directive |
| golangci-lint | v2.13.2 | v2 config schema (`version: "2"`) |
| goreleaser | v2.18.1 | several v1-era keys are deprecated |
| cosign | v3.1.3 | at least v3.1.3 (security fix), bundle format is the default |
| syft | current release | installed through a SHA-pinned installer in CI |
| gosec | v2.29.0 | |
| govulncheck | v1.8.0 | install from the module proxy, GitHub releases are stale |
| staticcheck | 2026.2.1 | |
| actions/checkout, setup-go, upload-artifact | v7 line | node24 runtime |
| github/codeql-action | v4 | |
| actions/attest-build-provenance | v4.2.2 | if open question 9 chooses it |
| cobra, BurntSushi/toml | v1.10.2, v1.6.0 | |
| go.yaml.in/yaml/v3 | v3.0.5 | if open question 8 chooses it; `gopkg.in/yaml.v3` stays at v3.0.1 |

## 13. Later, not in v0.x

Full Sigstore verification of attestations; CVSS v4 MacroVector scoring; calling GuardDog for source-level analysis; SBOM ingestion; a `watch` mode that re-checks a baseline periodically and opens issues; crates.io `db-dump` ingestion for large audits.

Work started with task 0.0 on 2026-09-09.

## 14. What shipped after v0.4.0

Written 2026-09-12, after the precision pass of that day. Sections 1 to 13 above
are the plan as it was approved on 2026-09-09 and are not edited; this section and
the next are what happened next and what is proposed after it.

| Release | Date | What it was |
|---|---|---|
| v0.4.1 | 2026-09-10 | The P0 section of an independent review of 0.4.0: five checks that passed silently when a source was down, `version-downgraded` (TD017), and the release work 0.4.0 itself needed |
| v0.5.0 | 2026-09-12 | The P1, P2 and P3 sections of the same review. The engine fixes (the repository's own code no longer read as a dependency, a scope no longer paying for the distance between the packages inside it, a bump compared with the version the project had rather than only the release before it), the doctor rules re-verified against the current package manager documentation, and the parts that run inside somebody else's pipeline: the Bun scanner, the pre-commit hook, the action and the release workflows |
| v0.5.1 | 2026-09-12 | The GitHub Action, which had never worked in any release that shipped it: a runner refused to load `action.yml` at all, and on Windows the archive was compared against a hash the shell had escaped. Both were found by the action self-test that shipped in 0.5.0, the first time it was dispatched |

What the two 0.5.x releases cost to make is worth recording with them. v0.5.0
needed the release job re-run after its Homebrew and Scoop pushes failed on a
token without the Contents permission, and the re-run then failed on `422
already_exists` for every asset it had already uploaded, which is why
`release.replace_existing_artifacts` is set now. v0.5.1 exists because the action
had never been exercised end to end from a published reference, which is why the
self-test grew a seventh leg that does exactly that.

## 15. The precision pass of 2026-09-12

Ten public repositories at pinned commits, every lockfile format the tool reads,
every block and warn finding classified by hand. The measurements, the
classifications and the reports are in [docs/precision.md](precision.md) and
`docs/precision/`. What it changed:

- `yarn.lock` in the format Yarn 1 wrote is read. The parser handled only the Yarn
  2 format, so a repository that never migrated got "not read" and every entry in
  it went unevaluated. React's lockfile, 2,394 entries, is one of those.
- The npm download counts API is asked once per 128 packages instead of once per
  package, and at one request per second. Evaluating one 1,201 entry lockfile drew
  2,406 answers of `429 Too Many Requests` before that.
- Four checks changed level in cases the pass showed were not worth a block: a
  package adopting trusted publishing, a release cut by an account the previous
  release already listed as a maintainer, a name that existed before the one it
  resembles, and a comparison that crosses release lines.
- One check stopped reading a data source's indexing lag as a finding, and one
  constant moved on the strength of seven measured findings rather than a guess.

Two things the pass found and did not fix, which is why they are in the proposal
below: a `scan` spends most of its wall clock asking for download counts one
scoped name at a time, because npm's bulk form refuses scoped names; and 528 warn
findings in one repository were npm entries with neither a location nor a hash,
which is true of that lockfile and says more about how npm wrote it than about the
project.

## 16. Proposed M5 (v0.6.0)

Ranked by what it is worth to somebody using the tool, which is not the order they
are easiest to build. Not approved; this is the proposal.

| # | Item | Why it is where it is | Est. |
|---|---|---|---|
| 5.1 | `watch` over a baseline: re-evaluate the packages a project already has, on a schedule, and report what changed since the baseline was recorded | Everything else here answers a question at the moment a lockfile changes. Most of the incidents this tool is built around happened to a version a project already had: a package is fine when it is installed and stops being fine three weeks later, when nothing in the repository changes and nothing runs. `baseline` already records the observed state and TD002 and TD003 already compare against it, so this is a command and a report rather than an engine | 12 h |
| 5.2 | Sigstore bundle verification of npm attestations | The tool stores what a registry hands it and takes deps.dev's word for whether an attestation verifies. That is a third party in the trust path of the check that matters most when a token is stolen, and the precision pass produced the case for it: a release four days old blocked because deps.dev had not read its attestation yet. Verifying the bundle locally removes the dependency and the lag both. Section 13 defers it; the pass is the argument for undeferring it | 16 h |
| 5.3 | Lazy download counts | A `scan` of a 1,201 entry npm lockfile spends most of its wall clock on `api.npmjs.org`, one scoped name at a time, because the bulk form refuses scoped names and the address is rate limited. Counts feed two checks. Asking only where an answer can change a finding, and saying so when it was not asked, is the difference between a scan that takes four minutes and one that takes twenty | 8 h |
| 5.4 | GuardDog handoff | Everything here is registry metadata. `--guarddog` would hand the packages that already look wrong to a tool that reads the code, and report what it said, which is the natural next question after a finding rather than a wider net | 10 h |
| 5.5 | crates.io ownership at the time of a release | `publisher-changed` demotes a release cut by an account npm listed as a maintainer of the previous version. crates.io publishes owners as current state only, so the same demotion cannot be made there and fifteen findings of the pass stayed at block. `db-dump` carries owner history; section 13 defers ingesting it | 10 h |
| 5.6 | A policy preset for a project that vendors from git | The pass produced seven block findings for git dependencies pinned at a commit sha, in repositories that clearly meant it. The answer is an allow entry, and writing one per dependency by hand is the kind of work people skip. `trustdiff policy allow <finding>` writing the entry, with a reason and an expiry, is small and removes the reason to turn a check off | 6 h |
