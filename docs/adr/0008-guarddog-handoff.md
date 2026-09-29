# ADR 0008: Opt-in GuardDog handoff for suspicious registry releases

Date: 2026-09-29
Status: accepted

## Context

The M5 proposal asks trustdiff to pass releases with existing trust findings to a source analyzer. The normal run must retain its small Go dependency set, metadata-only behavior and offline guarantees. GuardDog is a separately installed Python tool; silently installing it, scanning local project paths, accepting a different package version, or treating its download errors as a clean scan would break those guarantees.

The upstream CLI and JSON contract were verified against GuardDog v3.2.0, commit `3da172679cb58b1c9a780f9f5d640f855be016dc`, on 2026-09-29. Its default branch has changed since older integrations were written. This release requires a kernel sandbox for extraction and source analysis; its own documentation supports Linux/macOS scanning and Docker for Windows. Its JSON can contain `issues: 0` together with `errors`, so process success alone proves nothing about coverage.

## Decision

Add an explicit `--guarddog` handoff after trustdiff evaluates packages. Only registry releases with an existing warn or block finding qualify. Use a separately configured executable, require exactly the reviewed version 3.2.0, and invoke its scan command with a fixed argument vector, an exact validated version, JSON output, `--sandbox`, and the argument terminator `--`. Never invoke a shell, install the tool, install the target package, or run a package lifecycle command.

Run the executable in an owned empty temporary directory so GuardDog cannot interpret a registry name as a same-named directory in the user's project. Support npm, PyPI and Cargo (`crates` in GuardDog). Refuse offline mode and native Windows before process creation. On supported POSIX hosts, put the process in its own group and terminate that group on cancellation, timeout or output overflow. Limit a client to twenty scans, bound each scan to two minutes by default, and retain at most 4 MiB of JSON and 64 KiB of diagnostics per process.

Keep results as an attributed report supplement. They do not erase, weaken or promote trustdiff findings. Parse the package and exact version identity, counts, rule results and risk records; do not infer success from an exit code. Distinguish a completed scan, a partial scan with upstream errors, and an unavailable scan. Empty findings mean only that the selected GuardDog version reported none. Preserve useful partial evidence when a rule fails.

## Consequences

The default trustdiff run acquires no new dependency, network request or process. Users who opt in must install the reviewed GuardDog release and have a supported sandbox. Linux/macOS subprocess handling is tested with a deterministic helper rather than downloaded suspect packages; native Windows receives a clear unsupported message and can use trustdiff inside a supported Linux environment instead.

GuardDog's download and metadata phases require network access and run before its analysis sandbox is applied. The adapter does not claim to cap the external tool's download bytes, memory or disk usage; the limits here cover wall time, process output and package count. Operators should run source scanning in their normal isolated analysis environment. New GuardDog releases require a contract review and tests before widening the version check.

Primary sources: [CLI](https://github.com/DataDog/guarddog/blob/3da172679cb58b1c9a780f9f5d640f855be016dc/guarddog/cli.py), [JSON reporter](https://github.com/DataDog/guarddog/blob/3da172679cb58b1c9a780f9f5d640f855be016dc/guarddog/reporters/json.py), [package scanner](https://github.com/DataDog/guarddog/blob/3da172679cb58b1c9a780f9f5d640f855be016dc/guarddog/scanners/scanner.py), and [sandbox description](https://github.com/DataDog/guarddog/blob/3da172679cb58b1c9a780f9f5d640f855be016dc/README.md#sandboxed-scanning).
