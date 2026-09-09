# ADR 0002: Write the lockfile parsers rather than reuse osv-scalibr

Date: 2026-09-09
Status: accepted

## Context

Milestone M2 evaluates what a lockfile change adds, which needs a parser per format:
`package-lock.json`, `pnpm-lock.yaml`, `uv.lock` and `Cargo.lock` in M2, then
`yarn.lock`, `bun.lock`, `deno.lock`, `poetry.lock` and `requirements.txt` in M4.
Parsing lockfiles is solved work, and [google/osv-scalibr](https://github.com/google/osv-scalibr)
maintains extractors for all of them and more.

Three constraints decide this:

- The dependency policy allows the standard library plus six named modules, and any
  further module needs a written justification. The release also promises at most six
  direct dependencies and a binary under 15 MB.
- Every finding must be able to point at the line the entry sits on, because the SARIF
  output annotates the lockfile in a pull request.
- The tool exists because dependencies are a risk. Taking a large dependency to read
  dependency files would be hard to defend to the people the README asks to trust it.

Measured on 2026-09-09: a module that imports osv-scalibr resolves 393 modules and a
`go.sum` of 424 lines. The extractors also return the library's own inventory types,
which carry more than the checks need and none of the line positions they do need.

## Decision

Write the parsers, one small package per format under `internal/lockfile`, each
reading only what `internal/lockfile.Entry` holds: the package ref, where it was
resolved from, the integrity hash, whether the project depends on it directly, and the
line the entry starts on. A parser drops an entry it cannot read, with a reason on the
`Lockfile`, instead of failing the file: a lockfile that half parses is still worth
evaluating.

The formats stay within reach of the standard library and the modules already allowed:
JSON with `encoding/json` plus a token scanner for the line numbers, YAML with the
node API that already reports positions, TOML with `BurntSushi/toml` plus a line
scanner, and a small comment stripper for the JSONC files (`bun.lock`, `deno.jsonc`).

## Consequences

The parsers stay small and predictable, and each one is a single file a contributor can
add. Line numbers come out of the parse rather than a second pass.

The project owns the maintenance: a format that changes its shape (a new
`lockfileVersion`, a new `source` spelling) is our bug to fix, and the recorded fixtures
plus the weekly integration job are what catch it. That cost is accepted, and it is
bounded: the fields we read are the ones a lockfile cannot stop carrying without
ceasing to be a lockfile.

Reconsider if the list of formats grows well past the M4 set, or if a format arrives
whose parsing genuinely needs a solver rather than a reader.
