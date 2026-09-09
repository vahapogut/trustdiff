# @trustdiff/bun-scanner

A Bun security scanner that runs [trustdiff](https://github.com/vahapogut/trustdiff) over the packages `bun install` is about to fetch, and stops the install when one of them shows a trust regression.

Bun 1.3 added a [Security Scanner API](https://bun.com/docs/pm/security-scanner-api): the scanner named in `bunfig.toml` is handed every package Bun proposes to install, including transitive dependencies, before anything is written to disk. This package is such a scanner. For each package it runs `trustdiff check --format json` and turns the findings into advisories Bun understands: a blocking finding cancels the install, a warning asks on a terminal and cancels in CI.

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

Informational findings are dropped rather than reported as warnings, because a warning cancels installs in CI and an informational note is not something trustdiff itself considers actionable. To act on one, raise it to `warn` or `block` in your policy file and it will be reported.

The advisory names the check by id and by policy name, repeats trustdiff's own explanation, and links to the section of [docs/checks.md](https://github.com/vahapogut/trustdiff/blob/main/docs/checks.md) that describes the check.

## When the scan cannot be done

- **The binary is missing.** The scanner writes one line to stderr saying that nothing was scanned, and returns no advisories, so a machine that has not installed trustdiff yet is not blocked from installing anything. Set `TRUSTDIFF_BUN_REQUIRE_BINARY=1` in a repository that has decided every install must be scanned, and a missing binary stops the install instead.
- **The binary fails, times out, or prints something that is not a trustdiff report.** The scanner throws, and Bun cancels the install. This is deliberate. A scan that did not happen must never look like a clean bill of health, so the failure is loud and the message carries the exit code and the binary's own error output.
- **trustdiff exits 1.** That is the normal outcome for a package worth blocking, not an error, and the report is read as usual. Exit code 3 (a required data source was unavailable and the policy says to fail) also comes with a report and is read the same way.

## Configuration

Everything is configured through the environment, so a project can set it in CI without changing any file the scanner ships.

| Variable | Default | What it does |
|---|---|---|
| `TRUSTDIFF_BIN` | `trustdiff` | The binary to run. A bare name is looked up on PATH; a value containing a path separator is used as given, for a binary vendored into the repository or installed by a CI step somewhere private. |
| `TRUSTDIFF_BUN_REQUIRE_BINARY` | `0` | When true, a missing binary stops the install instead of skipping the scan. Accepts `1`, `true`, `yes`, `on` and their negatives. |
| `TRUSTDIFF_BUN_TIMEOUT_MS` | `120000` | How long one trustdiff run may take before it is killed and the install stops. Raise it for very large dependency trees on a cold cache. |

A value that is neither true nor false, or a timeout that is not a positive whole number, is an error rather than a silent fallback: a typo in a variable that decides whether installs are scanned should be visible.

trustdiff's own settings are unchanged and are read from the same places as always: `--policy` has no equivalent here, so the policy comes from the `.trustdiff.yaml` found upward from the directory the install runs in, then the user-level policy, then the built-in defaults. That is where you set cooldowns, per-check levels, allow-lists and `--offline` behaviour.

## Development

```sh
cd integrations/bun-scanner
bun test
```

The tests run against a stub binary written into a temporary directory, never against the real trustdiff, so they need no network, no Go toolchain and no released binary. They cover a clean scan, a blocking finding, a warning, a missing binary in both its modes, a binary that fails, a malformed document and an empty package list. `.github/workflows/bun-scanner.yml` runs the same command on Linux and on Windows with the proxy variables pointed at a closed port, so an accidental network call fails the build.

The package has no dependencies of any kind, `@types/bun` included, which is why `src/index.ts` carries its own copy of the Bun scanner interfaces rather than importing them. The copies are annotated with the date they were checked against Bun's `packages/bun-types/security.d.ts`; re-check them when Bun changes the API version.

## Publishing, for the repository owner

Nothing in this repository publishes this package, and no workflow here holds an npm credential. Publishing is a one-time setup plus a release workflow, both done by the owner under their own npm account. As of 2026-09-10 the `@trustdiff` scope is unregistered on npm and `@trustdiff/bun-scanner` does not exist, so all of the following is still open.

1. **Create the scope.** Sign in to npmjs.com and create the `trustdiff` organization, or claim the scope on the personal account. Turn on two-factor authentication first.
2. **Publish the first version by hand.** npm's trusted publishing is configured per package on a page that only exists once the package does, so the first version cannot come from OIDC. From `integrations/bun-scanner`, run `npm publish --access public` from a machine you control, with 2FA. Check `npm pack --dry-run` first and confirm the tarball holds only `src/index.ts`, `README.md`, `LICENSE` and `package.json`.
3. **Add the trusted publisher.** On the package settings page on npmjs.com, or with `npm trust github --repo vahapogut/trustdiff --file <the publish workflow filename>` (npm 11.15.0 or newer), name this repository and the filename of the workflow that will publish. Then restrict token-based publishing on the package, so a leaked token cannot publish a release.
4. **Write the publish workflow.** It is not in this repository yet and is deliberately not part of the test workflow. It needs `permissions: id-token: write` for OIDC, npm 11.5.1 or newer with Node 22.14.0 or newer, every `uses:` pinned to a full commit SHA as everywhere else here, and a trigger on the release tag. With trusted publishing configured, npm generates and publishes the provenance attestation itself and no npm token is needed at all.
5. **Keep the version in step.** `package.json` carries its own version. Bump it with the trustdiff release it belongs to and add a line to the root `CHANGELOG.md`.

## License

Apache-2.0, the same as trustdiff. See [LICENSE](LICENSE).
