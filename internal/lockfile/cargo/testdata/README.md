# Cargo.lock fixtures

Two real lockfiles, committed exactly as their projects published them, so that a
change in the format shows up here as a failing test rather than in somebody's
repository. Both were downloaded from `raw.githubusercontent.com` at the tag named
below.

| File | Project | Repository | Taken from | Date | License |
| --- | --- | --- | --- | --- | --- |
| `ripgrep-14.1.1.Cargo.lock` | ripgrep | https://github.com/BurntSushi/ripgrep | release `14.1.1` | 2024-09-09 | Unlicense OR MIT |
| `zoxide-v0.9.8.Cargo.lock` | zoxide | https://github.com/ajeetdsouza/zoxide | release `v0.9.8` | 2025-05-26 | MIT |

ripgrep is a Cargo workspace and its lockfile is format version 3: ten of its
packages carry no source because the workspace builds them, and the `ripgrep`
package lists the project's own dependencies. zoxide is a single crate and its
lockfile is format version 4.

The rest are hand written for the tests and say so in their first line. They are not
Cargo output:

| File | What it covers |
| --- | --- |
| `sources.Cargo.lock` | every source kind, a package with no checksum, a crate locked at two versions |
| `metadata-v1.Cargo.lock` | the first format versions: no version key, checksums in `[metadata]`, `<none>` for a git dependency |
| `broken.Cargo.lock` | tables the parser has to drop, followed by a package it can still read |
