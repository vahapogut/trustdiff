# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Until 1.0.0, a minor release may change command line behavior, the policy file format or the report schemas; such changes are listed under Changed.

## [Unreleased]

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

[Unreleased]: https://github.com/vahapogut/trustdiff/compare/v0.0.1...HEAD
[0.0.1]: https://github.com/vahapogut/trustdiff/releases/tag/v0.0.1
