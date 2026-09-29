# trustdiff pnpm install hook

Copy one file into a pnpm project to check its resolved npm packages before pnpm links them into `node_modules` or runs their install scripts. A blocking finding stops the install. The hook has zero runtime dependencies; install the [trustdiff binary](https://github.com/vahapogut/trustdiff#install) separately.

Supported: **pnpm 10.x, lockfile version 9, Node.js 20 or newer**. The executable lifecycle test pins pnpm **10.33.2**. pnpm 8's v6 lockfile and pnpm 11/12 are outside this integration's supported range. The hook refuses an unknown lockfile format instead of treating it as an empty dependency tree.

## Install

1. Install trustdiff and confirm `trustdiff version` works, or set `TRUSTDIFF_BIN` to its full executable path.
2. Copy [.pnpmfile.cjs](.pnpmfile.cjs) beside your project's `pnpm-lock.yaml`. For a workspace, use the workspace root. Commit it so every developer and CI job uses the same gate.
3. Run `pnpm install`. When adding or updating this hook in an existing project, refresh pnpm's hook checksum once with `pnpm install --lockfile-only --no-frozen-lockfile --ignore-scripts`, review the lockfile diff, then commit it. CI can continue to use `pnpm install --frozen-lockfile`.

For a checkout of this repository next to your project:

```sh
cp ../trustdiff/integrations/pnpm-hook/.pnpmfile.cjs .pnpmfile.cjs
pnpm install
```

PowerShell:

```powershell
Copy-Item ../trustdiff/integrations/pnpm-hook/.pnpmfile.cjs .pnpmfile.cjs
$env:TRUSTDIFF_BIN = 'C:\tools\trustdiff.exe'
pnpm install
```

If a project already has a `.pnpmfile.cjs`, preserve its hooks and compose this gate **after** its existing hooks. The file exports `createHooks(projectRoot)` for that purpose. A hook that changes the lockfile after this gate would make the scan stale. Keep the project root as the working directory so trustdiff finds the correct `.trustdiff.yaml`.

There is no npm install command for this integration and no background service. The copied file is the whole adapter.

## What blocks an install

The hook runs `trustdiff check --format json -- npm:name@version ...` with fixed arguments and no shell. It batches large trees into at most 100 references and about 8,000 argument characters per process, including on Windows.

| Result | Install behavior |
|---|---|
| Clean report | Continue; return the original lockfile unchanged |
| `info` finding | Continue |
| `warn` finding | Print the finding; continue if trustdiff's policy allows it |
| `block` finding | Print the finding and stop |
| Exit 1 | Stop; this includes warnings when the policy's `fail_on` is `warn` |
| Exit 3 | Stop; the policy requires a data source that was unavailable |
| Missing binary | Stop with installation instructions and `TRUSTDIFF_BIN` guidance |
| Crash, timeout, excess output or malformed report | Stop |
| Missing/duplicate/unexpected report subject | Stop |
| No checks completed for a package | Stop; an unchecked package is not a clean package |

Partial skips are counted on stderr; checks that do not apply to npm should not make every npm install fail. Run `trustdiff check` on the named refs for the complete skip reasons. trustdiff reads its normal project/user policy; this hook does not override it or weaken required-source failures.

## Resolutions and local packages

The scan covers every registry package in the supplied lockfile, including transitive, optional and development dependencies and every workspace importer. A filtered or production install can therefore report a package that is locked but not selected for that particular command. Aliases use the actual resolved registry name, scoped names retain their scope, and peer/patch variants of the same name and version are checked once. This checks the registry release's metadata, not the contents of a local patch or a mirror's tarball.

Workspace `link:` entries and pnpm directory resolutions have no public registry release to query. They are explicitly counted as local exclusions; their registry dependencies remain in the scan. Review that local code separately. Git, remote URL, local tarball, unknown resolution types and unresolved versions stop the gate with an explanation. The hook never substitutes their self-declared name/version for a public npm package.

Private packages need data sources that trustdiff can evaluate. If every check is skipped, the install stops. A project using unsupported dependency sources should keep its separate review process rather than treating this hook as proof those sources were checked.

## Repeat and frozen installs

pnpm's `afterAllResolved` hook runs after full dependency resolution, but its fast path can skip that phase. The accompanying `preResolution` hook scans the existing wanted lockfile, so repeat and `--frozen-lockfile` installs are gated too. Neither hook disables frozen mode. If full resolution follows, the newly resolved lockfile is scanned again; trustdiff's normal cache avoids repeating registry downloads.

This conservative choice also checks the old lockfile during an update/removal. If an old blocked dependency prevents replacing it, perform an explicitly reviewed lockfile-only update with `pnpm install --lockfile-only --ignore-pnpmfile --ignore-scripts --no-frozen-lockfile`, inspect the resulting dependency changes, then run the normal install with the hook enabled. The lockfile-only command is a deliberate bypass for editing resolutions; it is not a checked install.

The gate is not a sandbox. pnpm may fetch manifests/tarballs during resolution before calling `afterAllResolved`. pnpm itself, project configuration and hooks run before this gate; an install hook cannot make untrusted project configuration safe. `--ignore-pnpmfile` bypasses this gate, as does using another package manager. Enforce the committed hook and the normal install command in CI when this is a project requirement.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `TRUSTDIFF_BIN` | `trustdiff` | Executable name on PATH or path to the binary; not a shell command |
| `TRUSTDIFF_PNPM_TIMEOUT_MS` | `120000` | Positive whole milliseconds per batch, maximum 2147483647 |

A report is limited to 8 MiB and diagnostics to 64 KiB per batch. A timeout or size violation kills the process and refuses the install. No setting converts missing coverage or an execution failure into a successful scan.

## Tests and API evidence

```sh
node --test integrations/pnpm-hook/test/hook.test.cjs
PNPM_CLI=/path/to/pnpm/bin/pnpm.cjs node --test integrations/pnpm-hook/test/*.test.cjs
```

PowerShell uses `$env:PNPM_CLI = 'C:\path\to\pnpm\bin\pnpm.cjs'`. `PNPM_CLI` is test-only and must point to pnpm 10.33.2. Without it, the lifecycle test is explicitly skipped; unit tests still run. CI installs that pinned test tool outside this integration and runs both suites on Linux and Windows.

Unit tests execute the production hook against a stub executable and cover exact arguments, alias/scope/peer handling, unsupported resolutions, coverage failures, malformed reports, missing binaries, timeout, bounded output and batching. The lifecycle test runs real pnpm against a loopback-only synthetic npm registry, installs a package through an alias with a scoped transitive dependency, and asserts that clean installs complete while blocking fresh, repeat and frozen installs never reach the project lifecycle script. No package fixture or test request uses the public registry.

The API and object shape were verified on **2026-09-29** against these primary sources:

- [pnpm 10 hook documentation](https://pnpm.io/10.x/pnpmfile).
- [pnpm 10.33.2 install implementation](https://github.com/pnpm/pnpm/blob/v10.33.2/pkg-manager/core/src/install/index.ts), including preResolution before the frozen-install decision and afterAllResolved before package linking.
- [pnpm 10.33.2 internal lockfile types](https://github.com/pnpm/pnpm/blob/v10.33.2/lockfile/types/src/index.ts), including registry, directory and git resolutions.

All fixtures are synthetic and authored for this repository on 2026-09-29 under Apache-2.0. The integration uses the repository's [Apache-2.0 license](LICENSE).
