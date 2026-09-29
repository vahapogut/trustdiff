# 0005: Read bulk Cargo metadata from the crates.io database dump

Status: accepted

## Context

A Cargo workspace scan should not send one API request per crate when crates.io
publishes its public database for bulk consumers. The database dump is a large,
untrusted tar.gz of CSV tables. The single-package API remains useful for `check`.

## Decision

An explicit `cache refresh --crates-dump` downloads the dump and builds 256 plain
JSON shards. A metadata file names an immutable generation and each shard's hash.
The metadata rename publishes a complete generation, so a failed refresh keeps
the preceding index. The builder streams CSV rows and partitions versions before
assembling one bounded shard at a time. No database or new module is needed.

`scan` prefers a fresh installed index; `check` retains the API. Missing, stale or
unreadable metadata uses the existing API/cache behavior, with a diagnostic for
an installed but unusable index. A failure reading a selected index is unavailable
data, never a quiet request to the per-crate API. Data excluded from this index is
reported as unavailable instead of inferred from zero values.

## Consequences

Refresh is an explicit large periodic download. The index supplies publication
times, available publishing users, yank flags, checksums and current owners.
Archive scripts, dependencies, download counts and trusted-publisher evidence are
not indexed in this first format. The dump makes no complete historical owner
log available. `cache status` reports the upstream snapshot's age, and `cache
clear` removes only recognized index files. Fixtures and tests use no network.
