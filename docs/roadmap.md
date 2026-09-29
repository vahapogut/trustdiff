# Roadmap status

Reviewed on 2026-09-29. A released milestone, an implemented change on `main`,
and a proposal are different states. The README's versioned list describes
released milestones. The historical [PLAN](PLAN.md) is preserved for context.

## Released

| Version | Delivered behavior | Code and regression coverage |
|---|---|---|
| [0.2.0](https://github.com/vahapogut/trustdiff/releases/tag/v0.2.0) | Lockfile `scan`/`diff`, TD013/TD014, SARIF/Markdown, GitHub Action and commit hooks | `internal/lockfile`, `internal/gitdiff`, `internal/cli`, `internal/report`, `action.yml`, `.github/workflows/action-selftest.yml` |
| [0.3.0](https://github.com/vahapogut/trustdiff/releases/tag/v0.3.0) | Version-aware `doctor`, configuration previews/backups, CI mode and workflow pin checks | `internal/doctor`, `internal/configfile`, `internal/cli/doctor_test.go` |
| [0.4.0](https://github.com/vahapogut/trustdiff/releases/tag/v0.4.0) | Remaining lockfile formats, JSR, baselines, offline OSV, Bun scanner and package-manager distribution | `internal/lockfile`, `internal/registry/jsr`, `internal/baseline`, `internal/advisory/osvindex`, `integrations/bun-scanner`, `.goreleaser.yaml` |
| [0.4.1](https://github.com/vahapogut/trustdiff/releases/tag/v0.4.1) | Review corrections including TD016 and unhashed requirements | `internal/checks/td016.go`, `internal/lockfile/pipreq` |
| [0.5.0](https://github.com/vahapogut/trustdiff/releases/tag/v0.5.0) | Doctor precision, TD017, local-source handling and integration failure handling | `internal/doctor`, `internal/checks/td017.go`, `internal/checks/runner.go`, Bun and Action regression suites |
| [0.5.1](https://github.com/vahapogut/trustdiff/releases/tag/v0.5.1), [0.5.2](https://github.com/vahapogut/trustdiff/releases/tag/v0.5.2) | Publishing/workflow and finding-precision corrections | [CHANGELOG](../CHANGELOG.md), CLI/check/registry tests |

The Homebrew cask and Scoop bucket both name CLI 0.5.2. The npm package
`@trustdiff/bun-scanner` has its own version, 0.5.0. Their version numbers do not
need to match. The untagged npm staging correction is described under Unreleased
in the changelog.

## Current development

The four starter issues seeded by the original plan were follow-up development,
not evidence that every later idea had been implemented:

- [#1](https://github.com/vahapogut/trustdiff/issues/1): Unicode look-alike names
  in TD008, including a name-only diagnostic for Unicode npm input. npm's package
  name validation remains strict; this diagnostic does not imply such a name is
  publishable on npm.
- [#2](https://github.com/vahapogut/trustdiff/issues/2): an explicit, bounded
  crates.io dump index for bulk scans. [Usage](crates-dump.md) lists which data is
  present, what remains unavailable and how single-package checks differ.
- [#3](https://github.com/vahapogut/trustdiff/issues/3): a pnpm install hook,
  including the frozen-lockfile path that bypasses `afterAllResolved`.
  [Its README](../integrations/pnpm-hook/README.md) defines supported versions and
  limitations; local-registry integration tests exercise real pnpm installs.
- [#4](https://github.com/vahapogut/trustdiff/issues/4): a partial Turkish README,
  linked to an exact English source commit. CI reports a stale source revision
  when the English README changes without updating the translation.

These changes remain **Unreleased** until included in a published version.

## Proposals still in the detailed plan

[PLAN section 16](PLAN.md#16-proposed-m5-v060) proposes `watch`, local Sigstore
verification, lazy download-count fetching, a GuardDog handoff, historical Cargo
owner comparison and a `policy allow` helper. That section calls itself a
proposal; the released milestones above do not imply those commands exist.

One premise needs correcting: the public crates.io dump does not provide a
complete ownership-event history. Current owner rows and their creation times
cannot establish who owned a crate at every past release. The dump implementation
therefore reports unavailable historical facts instead of reconstructing them
from current owners. Baselines can record observations from the time they are
created, but cannot recover observations never made. See [the dump ADR](adr/0005-crates-database-dump.md).

## Verification

Ordinary Go tests use fixtures and local HTTP servers. CI runs supported Go
versions on Linux, macOS and Windows, plus a Linux race-detector run, lint,
security checks, and the six-module/15 MB budgets. Bun and pnpm adapters have
their own suites. A passing fixture test is not evidence of a successful live
registry request; live integration runs and published artifacts remain separate
checks.
