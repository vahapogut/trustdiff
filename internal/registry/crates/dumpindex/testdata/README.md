# crates.io dump fixtures

`crates.csv`, `users.csv`, and `versions.csv` are synthetic CSV projections of the
recorded `serde.json`, `cfg-if.json`, and `paste.json` API responses in
`../../testdata/`. Those responses were recorded from
`https://crates.io/api/v1/crates/<name>` on 2026-09-09; their provenance is recorded
there. The CSV projection was made on 2026-09-29. Crate numeric IDs are synthetic;
user IDs, publishing accounts, checksums, versions, timestamps, and yank flags
come from the pinned API responses. These are not represented as a captured full
database dump. Fixture construction and synthetic examples use this repository's
Apache-2.0 license; no upstream code or package contents are copied here.

The CSV headers, nullable publisher, PostgreSQL bytea checksum format and timestamp
parser follow crates.io's public dump configuration and SQL export at upstream
commit `0498d51e0f06f379c8e570db1628763ad4be7927`, verified 2026-09-29:

- https://github.com/rust-lang/crates.io/blob/0498d51e0f06f379c8e570db1628763ad4be7927/crates/crates_io_database_dump/src/dump-db.toml
- https://github.com/rust-lang/crates.io/blob/0498d51e0f06f379c8e570db1628763ad4be7927/crates/crates_io_database_dump/src/snapshots/crates_io_database_dump__tests__sql_scripts%40export.sql.snap

Tests build tar.gz archives locally from these tables and separate entirely
synthetic records. The API comparison tests serve the independently recorded JSON
through httptest and compare the public facts both transports expose. They do not
compare unavailable trusted-publishing, scripts, dependencies, or download data.
