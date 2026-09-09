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

Two more targets arrive with later milestones: `fixture` (recording registry responses, with the first registry client) and `demo` (the README demonstration, with the demo repository).

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

The recording script (`go run ./scripts/record-fixture <url> <path>`) and the full instructions for this section arrive with the first registry client. Until then, record a response with `curl` and add the README line described above by hand.

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

## Adding a check

A check is one file under `internal/checks/`, one commit, and one section in `docs/checks.md`; the walkthrough for this section arrives with the check framework in v0.1.0.

## Adding a lockfile parser

A parser is one package under `internal/lockfile/<name>/` implementing the `Parser` interface, with real lockfiles as fixtures and their attribution; the walkthrough arrives with the lockfile model in v0.2.0.

## Adding a doctor rule

A rule is one row in the rules table under `internal/doctor/`, carrying the date on which its key, unit and minimum version were verified against the package manager's documentation; the walkthrough arrives with `doctor` in v0.3.0.

## License

By contributing you agree that your contribution is licensed under the Apache License 2.0, like the rest of the project (see [LICENSE](LICENSE)). There is no contributor license agreement.
