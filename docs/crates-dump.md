# Bulk Cargo scans from the crates.io database dump

This feature is **Unreleased**. Build the current source to use it. The dump
replaces per-crate crates.io metadata requests during `scan`; it does not replace
OSV or deps.dev, inspect crate contents, or supply every check's required facts.

## Refresh and scan

```sh
trustdiff cache refresh --crates-dump
trustdiff cache status
trustdiff scan Cargo.lock
```

Refresh is an explicit large download, never an automatic side effect of a scan.
`--crates-dump` refreshes Cargo registry metadata instead of the usual OSV data;
it cannot be combined with `--ecosystem` or `--offline`. Each refresh downloads
the archive in full, even when the upstream snapshot has not changed.

`scan` automatically selects an installed index younger than **48 hours**, measured
from the upstream snapshot timestamp, not the time it was downloaded. At 48 hours
it is stale. `cache status` shows its age, crate/version counts and disk use;
`trustdiff cache status --format json` also exposes the snapshot metadata,
`age_seconds`, `stale` and `stale_after` under `crates_dump`.

If the index is absent, stale or its metadata is unreadable, scans use the ordinary
Cargo API/cache path. An installed but unusable index produces a diagnostic. Once
an index is selected, a missing crate/version or damaged shard does not trigger a
per-crate API fallback: the report names the missing data. A recently published
version may not yet exist in the snapshot. Refresh, or use `scan --no-cache` for
the API path. Single-package `check` and pull request `diff` keep their API/cache
behavior; for example, `trustdiff check cargo:serde` does not select this index.

## Offline use and cache location

```sh
trustdiff cache refresh --ecosystem cargo
trustdiff scan Cargo.lock --offline
```

Run the first command online to prepare OSV advisories separately. Offline scans
can use a fresh dump index and cached advisory data; absent data is skipped with
its reason, not certified clean. A stale dump still falls back to the ordinary
cache, without network requests. `--no-cache` bypasses the dump and HTTP cache;
it cannot be combined with `--offline`.

All commands use `TRUSTDIFF_CACHE_DIR`, or the platform's default trustdiff cache.
For one shared custom location:

```sh
export TRUSTDIFF_CACHE_DIR="$PWD/.trustdiff-cache"
trustdiff cache refresh --crates-dump
trustdiff scan Cargo.lock
```

In PowerShell, set `$env:TRUSTDIFF_CACHE_DIR = 'C:\caches\trustdiff'`. The
`--cache-dir` flag belongs only to `cache` commands: refreshing with
`trustdiff cache refresh --crates-dump --cache-dir PATH` does not redirect later
scans. Set the environment variable to that same path for those scans.

## Facts available to checks

| Included when the snapshot provides them | Unknown or outside this index |
|---|---|
| Crate names and creation/update timestamps | Contents and install/build scripts of crate archives |
| Version publication times, yank flags and SHA-256 checksums | Dependency rows and download counts |
| Publishing user identities, when recorded | Missing publishing users are unknown, not anonymous |
| Current user/team owner sets, when resolvable | Complete historical ownership events |
| Snapshot timestamp and crates.io source commit | Trusted-publisher evidence; the public dump excludes `trustpub_data` |

Checks that need missing facts report them as unavailable/skipped. Other sources
can still answer their own checks. Current owners and row creation dates cannot
establish who owned a crate at every past release; this feature does not invent
an ownership history. A baseline can retain observations from when it was made.

## Size, storage and recovery

The official archive advertised **1,924,432,540 bytes** on 2026-09-29. Its size
changes. Downloads have a 30-minute HTTP timeout. Hard limits reject more than
4 GiB compressed, 64 GiB expanded, or 4 GiB of generated index data; version
partition files are also capped at 4 GiB. These are limits, not measured space
requirements. Allow disk space for the archive, selected CSV tables, partition
files, the new index and every retained older generation at the same time.
Processing after download can take additional time. Ctrl+C or SIGTERM cancels the
command with exit code 3, removes its staging files and refresh lock, and leaves
the last published index intact. Stdout may contain partial output when a command
is interrupted; exit code 3 does not certify a completed report. A forced
termination or power loss still needs recovery.

The index uses up to 256 plain JSON shards under `crates-dump/g-<archive-sha256>`.
Each shard's size and SHA-256 are recorded and verified when read. A complete
generation is published by replacing `current.json`; an unsuccessful refresh
keeps the previous selection. Older generations stay on disk so active readers
can finish. `cache status` counts their storage too; refresh does not prune them.

`trustdiff cache clear` clears the HTTP/advisory caches as well as recognized dump
files and generations. The dump directory is left empty. A refresh lock, symlink,
unknown file or leftover build directory makes dump cleanup refuse deletion.
After a crash or forced termination, first verify that no refresh/clear process
is still running. Only then inspect the reserved `crates-dump` directory and remove a confirmed abandoned
`refresh.lock` or `build-*` directory before retrying. Do not remove a lock merely
because another refresh reports it, or delete files whose ownership is unclear.

## Sources and validation

Verified 2026-09-29 against the [crates.io data-access guidance](https://crates.io/data-access),
[official archive](https://static.crates.io/db-dump.tar.gz),
[dump configuration](https://github.com/rust-lang/crates.io/blob/0498d51e0f06f379c8e570db1628763ad4be7927/crates/crates_io_database_dump/src/dump-db.toml)
and [SQL export](https://github.com/rust-lang/crates.io/blob/0498d51e0f06f379c8e570db1628763ad4be7927/crates/crates_io_database_dump/src/snapshots/crates_io_database_dump__tests__sql_scripts%40export.sql.snap).
Tests use local archives and independently recorded API responses. This change
has not been benchmarked against the complete production dump. See the
[design decision](adr/0005-crates-database-dump.md) and
[fixture provenance](../internal/registry/crates/dumpindex/testdata/README.md).
