# Optional GuardDog source analysis

`--guarddog` asks a separately installed [DataDog GuardDog](https://github.com/DataDog/guarddog) executable to analyze registry releases that already have a trustdiff `warn` or `block` verdict. The default trustdiff run does not start GuardDog, download package source, or add a Python dependency.

The supported executable is **GuardDog 3.2.0** on Linux or macOS with its kernel sandbox available. Install that version separately using the [upstream installation instructions](https://github.com/DataDog/guarddog/tree/v3.2.0#installation), then check `guarddog --version`. trustdiff does not install or upgrade it. Native Windows is refused; run both tools inside a supported Linux environment such as WSL. A missing sandbox is a scan failure, with no retry that disables isolation.

```sh
trustdiff check npm:example@1.2.3 --guarddog
trustdiff scan package-lock.json --guarddog --format json
trustdiff diff --base-file package-lock.json.before package-lock.json --guarddog
trustdiff watch . --guarddog
```

Use `--guarddog-bin /absolute/path/to/guarddog` for an executable outside `PATH`. `--guarddog-timeout 90s` changes the per-release deadline; the default is two minutes, and the CLI accepts one second through ten minutes. The version probe counts against the first release's deadline and has its own ten-second maximum.

`watch` reads an existing reviewed baseline; see [watch](watch.md) for creating that baseline and choosing an interval.

## Selection and results

The handoff supports npm, PyPI and Cargo releases with an exact version. Cargo maps to GuardDog's `crates` command. Local directories, Git dependencies, archive URLs, bundled packages and unsupported ecosystems do not become same-named registry scans. Missing coverage is reported explicitly. Releases with no existing warning or block finding are not selected.

For npm lock entries, the public tarball URL must name the same package and exact version, including its scope. A tarball repointed to another package on the same registry host is unavailable. Private mirrors are not replaced by public packages. For PyPI, GuardDog selects the first supported source/archive distribution listed for the release; the result is release-level analysis, not proof that every platform wheel or the particular locked artifact was scanned. GuardDog does not compare a scanned distribution against the lockfile checksum.

GuardDog's npm `risky_new_dependency` metadata rule is excluded. That rule resolves additional dependency ranges and starts further scans, which would expand this handoff beyond the exact releases trustdiff selected. Each npm result states the exclusion. Other applicable GuardDog rules retain their upstream behavior.

The report includes an attributed `guarddog` supplement; it does not change a trustdiff finding's level or erase a finding. JSON keeps the package reference, source URL, tool version, upstream issue count, nonempty rule matches, compact risks, rule errors and status. Source locations are relative to the scanned package, and temporary directory prefixes are normalized so repeated watch runs do not invent changes.

| Status | Meaning |
|---|---|
| `completed` | The reviewed executable returned the requested package and exact version with a complete report and no reported rule errors. |
| `partial` | The requested release was identified and available evidence is retained, but some GuardDog rules failed. |
| `unavailable` | The scan could not be completed or verified, for example a missing executable, unsupported platform/version, download failure, malformed report, timeout or output overflow. |

Zero issues means this GuardDog run reported no matches. It does not prove a package is safe. A download error with zero issues is unavailable, and a report for another release is rejected. An incomplete requested handoff cannot make an otherwise successful run succeed; existing warning/block exit behavior retains priority. The usual trustdiff metadata evidence remains present even when the external analysis fails.

## Execution limits

- At most twenty release scan attempts per client/run, including failed attempts. Additional selections are reported unavailable.
- At most 4 MiB of standard output and 64 KiB of diagnostics per process. Overflow stops the process; truncated JSON is never interpreted as a clean scan.
- A fresh private working directory and temporary root for each process. Package names cannot select a same-named path in the user's project.
- Fixed argument vectors with an explicit `--sandbox` and `--` terminator. No shell, target package installation or package lifecycle command is invoked.
- The scanner and its process group are terminated on cancellation, timeout or output overflow; owned temporary files are removed afterward.

`--offline --guarddog` is rejected before starting the scanner. GuardDog's registry download and metadata phases need network access before it applies its analysis sandbox. The extraction and source-analysis phases use GuardDog's sandbox with network blocked. The adapter bounds process time, output and selected releases; it does not impose additional download-size, memory or disk quotas on the external tool. Use your isolated analysis environment for source scanning.

## Contract and verification

The CLI, JSON reporter, sandbox and archive extraction paths were reviewed on 2026-09-29 at GuardDog v3.2.0, commit [`3da172679cb58b1c9a780f9f5d640f855be016dc`](https://github.com/DataDog/guarddog/tree/3da172679cb58b1c9a780f9f5d640f855be016dc). A newer version requires another contract review before trustdiff accepts it. GuardDog is an external runtime prerequisite and is not bundled into trustdiff.

Ordinary tests use synthetic upstream-shaped reports and inert executable helpers. Linux subprocess tests exercise exact arguments, sandbox flags, version rejection, private directories, failure reports, output bounds, timeouts and child-process cancellation; Windows tests verify parsing and refusal before process creation. These tests do not download or install suspect packages. macOS uses the same POSIX adapter and runs its subprocess tests in CI. A symlinked temporary-parent regression verifies that working and scratch directories use the same canonical path, including macOS's `/var` and `/private/var` aliases.

The separate live integration test requires an explicit environment flag and an installed GuardDog 3.2.0. It downloads the small established release `npm:is-number@7.0.0`, exercises the real sandbox, and requires a complete report for that exact identity with no rule errors. It does not assume that a benign package will always produce zero heuristic matches. On a supported Linux/macOS host:

```sh
TRUSTDIFF_GUARDDOG_INTEGRATION=1 \
TRUSTDIFF_GUARDDOG_BIN=/absolute/path/to/guarddog \
go test -tags integration ./internal/guarddog -run TestIntegrationRealGuardDogSandbox -count=1 -v
```

Without the environment flag the live test skips, even when `-tags integration` is set. `TRUSTDIFF_INTEGRATION_OFFLINE` also disables it. Once enabled on Linux/macOS, a missing executable, unavailable sandbox or incomplete scan is a test failure. Upstream GuardDog 3.2.0 requires Python 3.10 or newer; an isolated virtual environment with `python -m pip install 'guarddog==3.2.0'` supplies the external executable without changing trustdiff's dependencies.

The real GuardDog 3.2.0 sandbox integration passed on Linux in GitHub Actions on 2026-09-29 (job `109569550198`). That run verified the installed executable against `npm:is-number@7.0.0`; it does not extend support to unreviewed GuardDog versions or native Windows.

See [ADR 0008](adr/0008-guarddog-handoff.md) for the design decision. Primary sources are the pinned [CLI](https://github.com/DataDog/guarddog/blob/3da172679cb58b1c9a780f9f5d640f855be016dc/guarddog/cli.py), [JSON reporter](https://github.com/DataDog/guarddog/blob/3da172679cb58b1c9a780f9f5d640f855be016dc/guarddog/reporters/json.py), [sandbox](https://github.com/DataDog/guarddog/blob/3da172679cb58b1c9a780f9f5d640f855be016dc/guarddog/sandbox.py), [archive handling](https://github.com/DataDog/guarddog/blob/3da172679cb58b1c9a780f9f5d640f855be016dc/guarddog/utils/archives.py) and [additional-dependency rule](https://github.com/DataDog/guarddog/blob/3da172679cb58b1c9a780f9f5d640f855be016dc/guarddog/analyzer/metadata/npm/risky_new_dependency.py).
