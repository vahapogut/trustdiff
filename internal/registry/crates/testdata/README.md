# Recorded fixtures

Real responses recorded once with `go run ./scripts/record-fixture`; tests serve them with httptest. Do not edit by hand.

## Why these fixtures

Every crates.io API response is small, so the crates were chosen for the facts they carry rather than for size:

- `serde`: the crate of the M1 acceptance scenario (`cargo:serde`) and of the integration tests. Its 316 versions also cover three yanked versions (1.0.95, 1.0.31, 0.7.6), a prerelease (1.0.172-alpha.0) and 174 versions with `published_by: null` from before crates.io recorded publishers. The owners document holds one user and one team (`github:serde-rs:publish`). The 1.0.229 dependency list has a required and an optional normal dependency; the 9.9.9 list is the 404 body for an unknown version.
- `cfg-if`: a tiny crate (16 versions) with one yanked version, 1.0.2, for the yanked mapping on its own.
- `memoffset` 0.9.1: a 9 KB archive with a `build.rs` whose normalized manifest carries no `build` key (cargo only started writing the auto-detected script into published manifests later in 2024), so the walk has to find the file itself. Its dependency list has only a build-kind (`autocfg`) and a dev-kind (`doc-comment`) entry, both excluded from `Dependencies`. Copyright Gilad Naaman, MIT license.
- `async-recursion` 1.1.1: a 15 KB procedural macro crate (`[lib] proc-macro = true`) without a build script. Copyright Robert Usher, MIT OR Apache-2.0.
- `paste` 1.0.15: an 18 KB crate that is both a procedural macro and has a build script declared in the manifest (`build = "build.rs"`), so the walk stops right after `Cargo.toml`. Copyright David Tolnay, MIT OR Apache-2.0.
- `rand_core`: versions 0.10.0 and 0.10.1 (and three release candidates) were published through trusted publishing and carry `trustpub_data` with `published_by: null`; older versions were token publishes by `dhardy`, and 0.4.3 was published after 0.10.1, so the list also has an out-of-order publish. The crate has `trustpub_only: true`.
- `not-found.json`: the 404 body for a crate that does not exist.

The archives are the real `.crate` files, verified against `versions[].checksum` in the crate documents before the tests open them.

## Recorded

- `serde.json`: GET https://crates.io/api/v1/crates/serde (HTTP 200, 440988 bytes, recorded 2026-09-09)
- `serde-owners.json`: GET https://crates.io/api/v1/crates/serde/owners (HTTP 200, 383 bytes, recorded 2026-09-09)
- `serde-1.0.229-dependencies.json`: GET https://crates.io/api/v1/crates/serde/1.0.229/dependencies (HTTP 200, 376 bytes, recorded 2026-09-09)
- `serde-9.9.9-dependencies.json`: GET https://crates.io/api/v1/crates/serde/9.9.9/dependencies (HTTP 404, 71 bytes, recorded 2026-09-09)
- `cfg-if.json`: GET https://crates.io/api/v1/crates/cfg-if (HTTP 200, 24375 bytes, recorded 2026-09-09)
- `memoffset.json`: GET https://crates.io/api/v1/crates/memoffset (HTTP 200, 34902 bytes, recorded 2026-09-09)
- `memoffset-0.9.1-dependencies.json`: GET https://crates.io/api/v1/crates/memoffset/0.9.1/dependencies (HTTP 200, 354 bytes, recorded 2026-09-09)
- `memoffset-0.9.1.crate`: GET https://static.crates.io/crates/memoffset/memoffset-0.9.1.crate (HTTP 200, 9032 bytes, recorded 2026-09-09)
- `async-recursion.json`: GET https://crates.io/api/v1/crates/async-recursion (HTTP 200, 24071 bytes, recorded 2026-09-09)
- `async-recursion-1.1.1-dependencies.json`: GET https://crates.io/api/v1/crates/async-recursion/1.1.1/dependencies (HTTP 200, 1108 bytes, recorded 2026-09-09)
- `async-recursion-1.1.1.crate`: GET https://static.crates.io/crates/async-recursion/async-recursion-1.1.1.crate (HTTP 200, 14874 bytes, recorded 2026-09-09)
- `paste.json`: GET https://crates.io/api/v1/crates/paste (HTTP 200, 52249 bytes, recorded 2026-09-09)
- `paste-1.0.15-dependencies.json`: GET https://crates.io/api/v1/crates/paste/1.0.15/dependencies (HTTP 200, 540 bytes, recorded 2026-09-09)
- `paste-1.0.15.crate`: GET https://static.crates.io/crates/paste/paste-1.0.15.crate (HTTP 200, 18374 bytes, recorded 2026-09-09)
- `rand_core.json`: GET https://crates.io/api/v1/crates/rand_core (HTTP 200, 65588 bytes, recorded 2026-09-09)
- `not-found.json`: GET https://crates.io/api/v1/crates/trustdiff-no-such-crate-zz (HTTP 404, 75 bytes, recorded 2026-09-09)
