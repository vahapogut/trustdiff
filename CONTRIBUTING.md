# Contributing to trustdiff

Thank you for considering a contribution. Bug reports, fixtures from real incidents, new checks, lockfile parsers, doctor rules and documentation fixes are all welcome. For anything larger than a bug fix, open an issue first so the design is agreed before the code is written; the roadmap in [docs/PLAN.md](docs/PLAN.md) shows what is already planned.

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). Security problems go through [SECURITY.md](SECURITY.md), not the issue tracker.

## Development setup

1. Go. `go.mod` declares `go 1.26.0` and `toolchain go1.26.8`. With the default `GOTOOLCHAIN=auto`, any Go 1.21 or newer you already have downloads that toolchain the first time it builds the module, so nothing needs to be installed by hand. `go version` inside the repository should print go1.26.8.
2. make. It is preinstalled on macOS and most Linux distributions. On Windows install it with `choco install make` or `scoop install make` and run the targets from Git Bash, which ships with Git for Windows.
3. Tools. `make tools` installs the pinned versions of golangci-lint, goreleaser, cosign, govulncheck, gosec and staticcheck into `$(go env GOPATH)/bin`. The versions live in `tools.mk`; bump them there, never ad hoc. Add that directory to your `PATH`:

   ```sh
   export PATH="$(go env GOPATH)/bin:$PATH"            # bash, zsh
   ```

   ```powershell
   $env:PATH = "$(go env GOPATH)\bin;$env:PATH"        # PowerShell
   ```

4. Build and test once to make sure everything is wired: `make build && make test && make lint`.

## Make targets

| Target | What it does |
|---|---|
| `build` | Builds `bin/trustdiff` with `-trimpath`, `CGO_ENABLED=0` and the version, commit and date set at link time from git |
| `test` | `go test ./...`. Never touches the network |
| `test-integration` | `go test -tags integration ./...`. Hits live registries; run it deliberately, see Tests below |
| `lint` | `golangci-lint run ./...` with the committed `.golangci.yml` |
| `vet` | `go vet ./...` |
| `vuln` | `govulncheck ./...` |
| `sec` | `gosec -quiet ./...` |
| `snapshot` | `goreleaser release --snapshot --clean --skip=sign,publish,sbom`: a local dry run of the release pipeline that needs neither syft, cosign nor a GitHub token. The archives land in `dist/` |
| `clean` | Removes `bin/` and `dist/` |
| `tools` | Installs the pinned developer tools from `tools.mk` |
| `demo` | Runs the gate over `testdata/demo-repo` offline with the clock pinned |

`fixture` records one live registry response into a testdata directory (see Recording fixtures below) and `test-integration` runs the live tests in `internal/integration`, which need the network and skip when `TRUSTDIFF_INTEGRATION_OFFLINE` is set. `demo` runs the pull request gate over the demo repository with `--offline` and the clock pinned, so it prints the same thing on every machine; [docs/demo-repo.md](docs/demo-repo.md) says what that is.

CI runs `lint`, `test`, `vet`, `vuln` and `sec`, plus a binary size gate and a direct dependency budget gate. Run the same targets locally before opening a pull request.

## Commits

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/): `type(scope): summary`, imperative mood, lower case, no trailing period, with a body that explains why when the summary is not enough.

Types used in this repository:

| Type | Use it for |
|---|---|
| `feat` | New behavior visible to users: a command, a check, a parser, a doctor rule, a flag |
| `fix` | A bug fix |
| `docs` | Documentation only, including ADRs and `docs/checks.md` |
| `test` | Tests and fixtures only |
| `refactor` | Code change with no behavior change |
| `ci` | Workflows, dependabot, lint configuration |
| `build` | Build, release and tooling: Makefile, `tools.mk`, goreleaser |
| `chore` | Everything else, for example bumping the pinned release in `action.yml` |

The scope is the package or area the change lives in: `cli`, `model`, `policy`, `httpcache`, `report`, `checks`, `lockfile`, `doctor`, `action`, `release`. A breaking change to the command line, the policy file or a report schema carries `!` after the scope and a `BREAKING CHANGE:` footer.

One change per commit. A new check, a new parser and a new doctor rule are each one commit. A refactor never rides along with a behavior change, and unrelated changes are never squashed together. Small commits make the history reviewable and make bisecting work; the pull request title follows the same format because it becomes the merge commit.

## Tests

`go test ./...` never touches the network, on any machine, in any configuration. Real registry and advisory responses are recorded once into `testdata/` and served with `net/http/httptest`. A test that needs the network belongs behind `//go:build integration`, runs with `make test-integration`, and asserts on the shape of a response rather than on values that drift. The integration job in CI runs on a schedule and on demand and is not required for merge.

Conventions:

- Table-driven tests wherever there is more than one case. Write the tests before the implementation.
- Golden files for every report format, written with LF line endings and compared after normalizing CRLF, so Windows and Linux agree.
- Every fixture directory carries a README line with the source URL, the recording date and the license where one applies.
- Checks get fake sources injected through interfaces; never a concrete client.

### Recording fixtures

Tests never touch the network. A registry or advisory response is recorded once
with the helper and served by `net/http/httptest` from then on:

```bash
go run ./scripts/record-fixture https://registry.npmjs.org/express internal/registry/npm/testdata/express.json
```

`make fixture URL=<url> OUT=<path>` runs the same command. The helper writes the body
byte for byte and adds a line to the `README.md` next to it with the method, URL,
status, size and date, so every fixture carries its provenance. Use `-accept` for
an alternate media type (the abbreviated npm packument) and `-post <file>` for batch
endpoints such as OSV `querybatch`. Re-record a fixture when the code needs a field
the old copy lacks; commit the fixture and the README line together with the change
that needs them.

## Architecture decision records

Decisions that shape more than one package are written down in `docs/adr/` as `NNNN-title.md`, from the template in `docs/adr/0000-template.md`: context, decision with the alternatives that lost, consequences. An ADR is written and committed before the code it governs, so the review is about the decision first and the code second. Change a decision by writing a new ADR that supersedes the old one and updating the old status line; do not rewrite history.

Write one when you add a module, change a published schema, choose a strategy that several packages depend on (parsers, config edits, validation), or are unsure and want a decision on record.

## Dependency policy

This tool exists because dependencies are dangerous, so it has almost none. Standard library first. Exactly six third-party modules are allowed, and CI fails when the direct dependency count exceeds six:

| Module | Used for |
|---|---|
| `github.com/spf13/cobra` | Command line |
| `go.yaml.in/yaml/v3` | YAML policy and config files (the maintained continuation of `gopkg.in/yaml.v3`, same API) |
| `github.com/BurntSushi/toml` | TOML lockfiles and config files |
| `golang.org/x/term` | Terminal and width detection |
| `golang.org/x/time` | Per-host rate limiting |
| `golang.org/x/mod` | Semantic version parsing |

Nothing else, including other `golang.org/x/*` packages: concurrency limits use a buffered channel, not `x/sync`. `CGO_ENABLED=0` always, no sqlite, caches are plain files, and third-party Go code is never vendored or copied in.

If you believe a change needs another module, stop and ask in an issue before writing code. Give a one-paragraph justification and the module's profile: who maintains it, how big it is, how it is released and signed. An accepted module gets an ADR. A pull request that adds a module without that discussion will be asked to remove it.

## Style

- `gofmt` and `goimports` with the local prefix from `.golangci.yml`; `make lint` must be clean.
- Every package starts with a doc comment explaining its role in the layout described in `docs/PLAN.md`.
- Errors are wrapped with context: `fmt.Errorf("npm packument %s: %w", name, err)`.
- `ctx` is the first parameter of anything that does I/O.
- Stdout is reserved for reports. Diagnostics go through the `*slog.Logger` to stderr, behind `-v`.
- No global mutable state except the link-time variables in `internal/version`.
- Boring, readable code over clever code.
- A fact that changes over time (a registry field, a config key, a tool flag, an action SHA) is re-verified against the official source right before it is used, and the verification date goes into a comment next to it. Never invent a registry field; fetch the endpoint and look.
- Documentation and comments are plain and specific, written for the person maintaining this next year: no filler, ASCII punctuation, no marketing.
- ASCII punctuation means no en-dash and no em-dash anywhere the project writes prose: source comments, documentation, commit messages, and the title and explanation of every finding, which `internal/checks` has a guard test for. Three kinds of file hold those characters legitimately and must not be "fixed". The guard tests themselves carry them in the character class they match against, because a guard has to name what it forbids. `internal/registry/pypi/testdata/requests-2.32.0.json` is a recorded upstream response whose payload is somebody else's README; a fixture is evidence of what an API returned, so editing it would make it evidence of nothing. And a document somebody else wrote about this project, such as `docs/review-2026-09-10.md`, is kept exactly as it was received, for the same reason: it is the record of what they said, not something this project is free to rewrite.

## Adding a check

A check is one file under `internal/checks/`, its test file, one section in `docs/checks.md`, one line in the changelog and one commit. The doc comment on `Runner` in `internal/checks/runner.go` is the contract; this is the same procedure with `internal/checks/td001.go` (`young-version`) as the example.

1. Pick the id and the name. Ids are `TD` plus three digits, assigned in order and never reused; the name is lower-case words joined by hyphens and is the key in the `checks` map of the policy file. Both patterns are enforced by `schema/report.v1.json`.
2. Register the default. Add a row to `checkDefaults` in `internal/policy/policy.go`, the source of `policy.CheckNames` and `policy.DefaultCheck`; add the name to both check name lists in `schema/policy.v1.json` and copy that file over `internal/policy/policy.v1.json` (the tests fail while the two differ); add the commented line to `internal/policy/default.yaml`, which `policy init` writes and which the tests compare with the defaults. The test in `internal/policy/policy_test.go` that counts the checks needs the new count.
3. Write `internal/checks/tdNNN.go`. It starts with a doc comment that says what the check detects, which ecosystems it applies to, when it is skipped, and lists the evidence keys one per line with their meaning; that list is copied into `docs/checks.md`, so keep the two identical. A registry field the check relies on is re-verified against a live response and the date goes into the comment. The file defines a type implementing `Check` and registers it from `init`:

   ```go
   type td001 struct{}

   func init() { Register(td001{}) }

   func (td001) ID() string                    { return "TD001" }
   func (td001) Name() string                  { return "young-version" }
   func (td001) Ecosystems() []model.Ecosystem { return nil } // nil means every ecosystem
   ```

   `Run` receives the assembled `Subject` and must:

   - read what it needs from the `Subject` and never fetch on its own; a check that needs another package goes through `s.Loader`, which memoizes per run;
   - return `Skip(id, reason)` when a source it needs is unavailable, taking the reason from `s.Skipped(SourceRegistry)` and its siblings, never an empty `Result`: an unavailable source is reported as skipped, not as a pass;
   - build findings with `NewFinding` so the id, name, effective level, ref and location are set, with an `Evidence` map whose keys the doc comment documents; values must encode as JSON, and keys are added within a report schema version, never renamed or removed;
   - honor `ctx`: the runner cancels it at the per-check timeout and reports the check as skipped, and a check that ignores `ctx` keeps running in the background until it returns on its own;
   - not panic; the runner recovers a panic and reports the check as skipped with the message, but whatever the check found is lost;
   - put the evidence into the title and the explanation in plain ASCII ("the previous 5 versions (3.3.4, 3.3.3, 3.3.2, 3.3.1, 3.3.0) were published by dominictarr; 3.3.5 was published by right9ctrl"); the test helper rejects em and en dashes.

   The runner does the rest: it skips checks that do not apply to the ecosystem or whose effective level is `off`, drops findings covered by an allow entry, skips `young-version` for packages under `cooldown_exclude`, and emits the expired-allow finding for stale entries. A check does not re-implement any of that.
4. Write `internal/checks/tdNNN_test.go` as a table over hand-built subjects with the helpers in `subject_a_test.go`: `subjectA` builds a subject with a version and its history, `withPreviousA` adds the previous release, `unavailableA` marks a source as failed, `runA` runs the check by id and asserts the shape of the result against an `outcomeA` (a number of findings, or a skip whose reason contains a fragment), `wantTextA` checks fragments of the text. Cover the finding with its evidence and text, the boundary where it does not fire, and a skip for every source the check needs. No fixtures: a check never talks to a registry.
5. Document it in `docs/checks.md` with a section headed `## TDNNN name` (the anchor `#tdNNN-name` becomes the rule's `helpUri` in SARIF): what it detects, why it matters with a real incident and a link to a source, the evidence table, an example as the human writer prints it, how to fix, how to allow. Add the row to the checks table in `README.md`.
6. Add a line under `Unreleased` in `CHANGELOG.md`: ``TDNNN `name` (default level): one sentence on what it reports``.
7. Commit the whole change as `feat(checks): TDNNN name`.

## Adding a lockfile parser

A parser is one package under `internal/lockfile/<name>/` implementing the `Parser` interface in `internal/lockfile/lockfile.go`, with real lockfiles as fixtures and a `testdata/README.md` recording where each one came from and under which license.

1. Write `internal/lockfile/<name>/<name>.go` with `Name`, `Detect` and `Parse`, and register the parser from `init`. The package doc comment says which format versions it reads, how it decides `Direct`, and how it places an entry on a line. [ADR 0002](docs/adr/0002-lockfile-parsers.md) says why these are written here rather than taken from a library.
2. Read only what `lockfile.Entry` holds. An entry the parser cannot make sense of is dropped with `Drop` and a reason, never a failure of the whole file: a lockfile that half parses is still worth evaluating.
3. Give every entry a line. `LineIndex` turns a byte offset into a line for the formats whose decoder reports one, and `TableFinder` places a TOML table by a header confirmed against the name it declares.
4. Decide where an entry comes from with `RegistryHosts` rather than by the shape of a URL. A private registry is recognized by the share of the file's downloads it carries, which is what a repointed entry cannot fake.
5. Test against a real lockfile of a real project, plus a small file of your own for the edge cases. Assert the entry count, the direct dependencies, the sources and at least one line number.
6. Add the format to the list in `README.md` and a line under `Unreleased` in `CHANGELOG.md`, and commit as `feat(lockfile): <name>`.

## Adding a doctor rule

A rule is one entry in a `rules_<manager>.go` file under `internal/doctor/`, one section in `docs/doctor.md`, one line in the changelog and one commit.

1. **Read the documentation first, and write down the date.** Every rule carries `Docs` and `Verified`, and a test fails when either is missing. These settings are new and they move: two have changed their key name, one changed its default, and one accepts a duration string only from a later minor release. A row copied from memory or from a blog post is a row that will eventually tell somebody to write a key their package manager rejects.
2. Pick the id and the name. Ids are `DR` plus three digits, grouped ten per manager and never reused; the name is lower-case words joined by hyphens and is the key a policy file turns the rule off with.
3. Add the entry and register it from `init`. Fill in `Since`, and `Until` when a newer key replaced this one, so that a project is judged by the key its own version reads.
4. Choose a `Desired`. `MinimumAge` for a wait, with the `Unit` this manager counts in; `BoolSetting` for a switch; `EnumSetting` for a value out of a set; `Advice` for a question that has no right answer a tool can check. Give `MinimumAge` and `BoolSetting` the manager's own default and the version it arrived in, so a project that is already protected is not told to write anything.
5. Set `Fixable` only when writing the value is safe and unambiguous. Which packages may run a build script, which scanner to trust, whether to turn hardened mode on: those are decisions, and a rule that writes one is a rule people turn off.
6. Add the unit if the manager counts in one nothing else uses. A `Unit` is a name, a parser and a formatter, and its parser refuses the other managers' spellings on purpose: accepting `3d` where a number of minutes belongs would call a value correct that the manager itself rejects.
7. Test it in `internal/doctor`: the value that is right, the value that is present and too small, the unit confusion if the manager has a neighbour that counts differently, and the version boundary. A fix test asserts the file comes out byte for byte the same except the line that changed, and that a second run writes nothing.
8. Document it in `docs/doctor.md`: the table row, and a note under it when the setting has a catch worth knowing, such as the file it is read from not being the one everybody expects.
9. Add a line under `Unreleased` in `CHANGELOG.md` and commit as `feat(doctor): DRNNN name`.

## License

By contributing you agree that your contribution is licensed under the Apache License 2.0, like the rest of the project (see [LICENSE](LICENSE)). There is no contributor license agreement.
