# @trustdiff/bun-scanner

A Bun security scanner that runs [trustdiff](https://github.com/vahapogut/trustdiff) over the packages `bun install` is about to fetch, and stops the install when one of them shows a trust regression.

Bun 1.3 added a [Security Scanner API](https://bun.com/docs/pm/security-scanner-api): the scanner named in `bunfig.toml` is handed every package Bun proposes to install, including transitive dependencies, before anything is written to disk. This package is such a scanner. For each package it runs `trustdiff check --format json` and turns the findings into advisories Bun understands: a blocking finding cancels the install, a warning asks on a terminal and cancels in CI. A package it could not check is reported too, because an install where nothing could be checked should not look like an install where nothing was wrong.

## What it needs

- Bun 1.3.0 or newer. Earlier releases have no scanner API.
- The `trustdiff` binary on your PATH. **This package does not contain it and does not download it.** trustdiff is a single Go binary that you install yourself, from a [release](https://github.com/vahapogut/trustdiff/releases) (with signature and checksum verification) or with `go install github.com/vahapogut/trustdiff/cmd/trustdiff@latest`. If the binary is not there, the scanner says so and lets the install continue, unless you tell it not to; see `TRUSTDIFF_BUN_REQUIRE_BINARY` below.

## What it sends where

Nothing goes anywhere on this package's account. It has no dependencies, no telemetry and no network code at all: the only thing it does is run a program on your machine and read what that program printed on stdout. The network calls you may see during an install are trustdiff's own, to the public npm registry and to the OSV and deps.dev advisory sources, for the packages you are installing and for nothing else. `trustdiff --offline` turns those off too, and a policy file decides the rest. There is no account, no token and no dashboard anywhere in this path.

## Install

```sh
bun add -d @trustdiff/bun-scanner
```

The scanner has to be a dependency of the project that uses it. Bun resolves it out of the project's own dependency tree and refuses to run one that is only installed globally.

Then point Bun at it:

```toml
# bunfig.toml
[install.security]
scanner = "@trustdiff/bun-scanner"
```

That is the whole setup. There is no build step: the package ships one TypeScript file and Bun runs it as it is.

## What you see

Bun does the printing, so the exact layout is Bun's. What this package decides is the level, the package name, the sentence and the link:

```
  FATAL: express
    TD002 publisher-changed on express@4.19.2. published by an account that has not
    published this package before. the previous 5 versions were published by
    dougwilson; 4.19.2 was published by ci-bot.
    https://github.com/vahapogut/trustdiff/blob/main/docs/checks.md#td002-publisher-changed

  1 advisory (1 fatal)
```

and the install stops before anything is written to disk.

## How a finding becomes an advisory

trustdiff gives every finding a level, which the policy file can change per check and per ecosystem. Bun has two levels. The mapping is:

| trustdiff finding | Bun advisory | What Bun does |
|---|---|---|
| `block` | `fatal` | Cancels the install at once with a non-zero exit code |
| `warn` | `warn` | Prompts on an interactive terminal, cancels everywhere else, CI included |
| `info` | not reported | Nothing |
| nothing could be checked | `warn` by default | Same as any warning, and `TRUSTDIFF_BUN_UNCHECKED` changes it |

Informational findings are dropped rather than reported as warnings, because a warning cancels installs in CI and an informational note is not something trustdiff itself considers actionable. To act on one, raise it to `warn` or `block` in your policy file and it will be reported.

The advisory names the check by id and by policy name, repeats trustdiff's own explanation, and links to the section of [docs/checks.md](https://github.com/vahapogut/trustdiff/blob/main/docs/checks.md) that describes the check.

## When the scan cannot be done

Bun has no advisory level that means "nobody knows about this one", so every gap has to be turned into one of the two levels it does have. These are the gaps and what each becomes.

- **The binary is missing.** The scanner writes one line to stderr saying that nothing was scanned, and returns no advisories, so a machine that has not installed trustdiff yet is not blocked from installing anything. Set `TRUSTDIFF_BUN_REQUIRE_BINARY=1` in a repository that has decided every install must be scanned, and a missing binary stops the install instead.
- **The binary fails, times out, or prints something that is not a trustdiff report.** The scanner throws, and Bun cancels the install. This is deliberate. A scan that did not happen must never look like a clean bill of health, so the failure is loud and the message carries the exit code and the binary's own error output. A large tree takes several trustdiff runs, and when a later run fails the scanner prints what the earlier ones found before it throws, so those findings are not lost with the exception.
- **Bun resolved no exact version for a package.** trustdiff would have to answer about whichever version is published as latest, which is not the one Bun is about to write to disk, so the package is not checked at all. It is reported as an unchecked package rather than passed over.
- **Every check on a package was skipped.** The report then carries no finding for it, which reads exactly like a package that passed everything. It is reported as an unchecked package instead. A package where only some checks were skipped keeps its findings and gets a count on stderr, because a check that does not cover an ecosystem is skipped on every package of that ecosystem and stopping an install over that would help nobody.
- **trustdiff exits 1.** That is the normal outcome for a package worth blocking, not an error, and the report is read as usual.
- **trustdiff exits 3.** A required data source was unavailable and your policy said that fails the run. The report is still read for its findings, and every package the run could not finish checking becomes a `fatal` advisory. That is not this scanner's judgment to soften: `TRUSTDIFF_BUN_UNCHECKED` does not apply, because your own policy file already decided. Set `on_data_unavailable: warn` there if you want the run to carry on instead.

## Configuration

Everything is configured through the environment, so a project can set it in CI without changing any file the scanner ships.

| Variable | Default | What it does |
|---|---|---|
| `TRUSTDIFF_BIN` | `trustdiff` | The binary to run. A bare name is looked up on PATH; a value containing a path separator is used as given, for a binary vendored into the repository or installed by a CI step somewhere private. |
| `TRUSTDIFF_BUN_REQUIRE_BINARY` | `0` | When true, a missing binary stops the install instead of skipping the scan. Accepts `1`, `true`, `yes`, `on` and their negatives. |
| `TRUSTDIFF_BUN_TIMEOUT_MS` | `120000` | How long one trustdiff run may take before it is killed and the install stops. Raise it for very large dependency trees on a cold cache. |
| `TRUSTDIFF_BUN_UNCHECKED` | `warn` | What a package trustdiff could not check counts as. `fatal` stops the install, `warn` asks on a terminal and cancels in CI, `ignore` reports nothing. Exit code 3 is fatal whatever this says. |

A value that is neither true nor false, a timeout that is not a positive whole number, or an unchecked policy that is none of the three words, is an error rather than a silent fallback: a typo in a variable that decides whether installs are scanned should be visible.

`ignore` is there for the project that installs from a mirror where some data source is genuinely never reachable and has accepted what that means. It is not a way to quieten a noisy install: everything it hides is a package nobody checked.

trustdiff's own settings are unchanged and are read from the same places as always: `--policy` has no equivalent here, so the policy comes from the `.trustdiff.yaml` found upward from the directory the install runs in, then the user-level policy, then the built-in defaults. That is where you set cooldowns, per-check levels, allow-lists and `--offline` behaviour.

## Development

```sh
cd integrations/bun-scanner
bun test
```

The tests run against a stub binary written into a temporary directory, never against the real trustdiff, so they need no network, no Go toolchain and no released binary. They cover a clean scan, a blocking finding, a warning, a missing binary in both its modes, a binary that fails, a run that is killed for taking too long, a malformed document, an empty package list, each of the three ways a package can end up unchecked, a run that could not reach a data source, and a failure part way through a tree large enough to take two runs. A stub can be given one behaviour per run, which is how that last one is written. `.github/workflows/bun-scanner.yml` runs the same command on Linux and on Windows with the proxy variables pointed at a closed port, so an accidental network call fails the build.

The package has no dependencies of any kind, `@types/bun` included, which is why `src/index.ts` carries its own copy of the Bun scanner interfaces rather than importing them. The copies are annotated with the date they were checked against Bun's `packages/bun-types/security.d.ts`; re-check them when Bun changes the API version.

## Publishing, for the repository owner

No npm credential exists in this repository and none is meant to. The publishing itself is done by [`.github/workflows/npm-publish.yml`](../../.github/workflows/npm-publish.yml), through npm's trusted publishing: GitHub mints an OIDC token for that one workflow file, npm exchanges it for a short lived credential, and there is no secret to leak. It runs on a version tag rather than on the GitHub release, because a release created by the automatic `GITHUB_TOKEN` does not start another workflow run. It reads the version out of `package.json`, skips when the registry already has it, asserts the tarball holds four files, and runs `bun test` before it publishes anything.

Three things still need the owner's own hands, once. `npm login` and then `sh scripts/publish-scanner.sh` from the repository root does the two that can be scripted and checks the third. As of 2026-09-10 the `@trustdiff` scope is unregistered on npm and `@trustdiff/bun-scanner` does not exist, so all three are open. [docs/releasing.md](../../docs/releasing.md) section 8 has them in full; in short:

1. **Create the npm organization.** The scope cannot be a personal one: npm gives every account only the scope matching its own name, so the account publishing this owns that scope and nothing else, and `@trustdiff` needs an organization literally named `trustdiff`. Organizations are created on npmjs.com only. Choose the free plan, which allows unlimited public packages, and turn on two-factor authentication first, because the next two steps both require it.
2. **Publish the first version by hand.** Trusted publishing cannot create a package that does not exist yet, so version 0.4.0 goes out from a machine where a person can answer a two-factor prompt. Run `npm pack --dry-run` first and confirm the tarball holds only `src/index.ts`, `README.md`, `LICENSE` and `package.json`.
3. **Add the trusted publisher.** `npm trust github --repo vahapogut/trustdiff --file npm-publish.yml`, which needs npm 11.15.0 or newer and two-factor authentication, or the same thing through the package settings page. Then restrict token-based publishing on the package. The workflow's file name is part of that contract: renaming it breaks publishing until the trusted publisher is reconfigured.

After that, bump `version` here in the same commit as the trustdiff release it belongs to, add a line to the root `CHANGELOG.md`, and the tag publishes it.

## License

Apache-2.0, the same as trustdiff. See [LICENSE](LICENSE).
