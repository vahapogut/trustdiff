# Recorded fixtures

Real responses recorded once with `go run ./scripts/record-fixture`; tests serve them with httptest. Do not edit by hand.

## Terms the data comes under

Every file below is a byte for byte copy of what jsr.io or api.jsr.io answered on
2026-09-09. All of it is registry metadata (version lists, publish times, account
display names, dependency declarations, download counts), served by JSR under its
own terms of use and usage policy at https://jsr.io/docs/usage-policy, which
explicitly permits publishing tooling designed to analyze packages. No package
source is recorded here, so no package's own license is redistributed: the closest
any file comes is the file manifest in `std-fs-1.0.24-meta.json`, which lists paths,
sizes and sha256 checksums without any file's content. The management API reports an
SPDX license per version where a package declares one, and reported "MIT" for
@std/fs 1.0.24 and null for both @luca packages on the recording date.

## Why these fixtures

(These bullets avoid the "- `file`:" form on purpose: the record script rewrites
lines in that form and appends new recordings at the end of the file, which is why
the list of recordings is the last section.)

- Scoped package with many versions, `@std/fs`: 69 versions, the shape most of the
  mapping is exercised against. Its meta.json carries a `createdAt` per version, so
  the publish times come from the registry API alone; two versions are yanked
  (0.229.0 and 0.228.0, both without provenance) and six are prereleases
  (1.0.0-rc.1 to 1.0.0-rc.6), which is what the ordering test reads. Its versions
  list has a real publishing account on every entry and a `rekorLogId` on most, with
  1.0.12 as a release that has none, so attestation and no attestation are both
  covered on one package. The dependency list of 1.0.24 names @std/path twelve
  times, once per sub-export the version imports from it, which is the deduplication
  case. The downloads answer is 90 days of daily buckets in both kinds.
- Single version, `@luca/cases`: one version, 1.0.0, published by an account and
  carrying a `rekorLogId`, with an empty dependency array. It is the smallest real
  package that still has every field set.
- meta.json from before the `createdAt` field, `@luca/flag`: two versions and a
  meta.json of 114 bytes whose version entries are empty objects, because the
  package was last published in January 2024 and its meta.json has not been
  regenerated since JSR started writing publish times into it. The publish times can
  therefore only come from the management API, and both versions have `user` and
  `rekorLogId` null, which is the "the registry records no publisher" path.
- Pagination, `@hono/hono`: 146 versions, more than the 100 the versions endpoint
  serves per page, recorded as the two pages the client asks for. meta.json lists all
  146 in one answer, so the test can tell a complete list from a truncated one.
- npm dependencies, `@oak/oak`: version 17.2.0 has `usesNpm: true` and a dependency
  list of 18 entries mixing kind "jsr" (@oak/commons and four @std packages, each
  repeated per sub-export) with kind "npm" (path-to-regexp), which is the case for
  the rule that npm entries stay out of the JSR dependency map.
- Endpoints recorded for the record and never requested by the client,
  `std-fs-1.0.24-meta.json`, `luca-cases-1.0.0-meta.json`,
  `std-fs-1.0.24-version.json` and `luca-cases-1.0.0-version.json`: the per-version
  registry document and the single-version management record. The package comment in
  `../doc.go` says why nothing in the model comes from either. They are here so a
  future reader can see their real shape, including that the per-version document
  carries no yanked flag and that the single-version record carries no publishing
  user.
- Not found, `meta-not-found.txt`, `package-not-found.json`, `version-not-found.json`
  and `scope-not-found.json`: the 404 bodies of both hosts. jsr.io answers the plain
  text "404 - Not Found" and api.jsr.io a JSON object with a `code` such as
  `packageNotFound`, `packageVersionNotFound` or `scopeNotFound`. The test server
  serves the first two for every path it does not know.

## Recorded files

- `std-fs-meta.json`: GET https://jsr.io/@std/fs/meta.json (HTTP 200, 3795 bytes, recorded 2026-09-09)
- `std-fs-package.json`: GET https://api.jsr.io/scopes/std/packages/fs (HTTP 200, 583 bytes, recorded 2026-09-09)
- `std-fs-versions.json`: GET https://api.jsr.io/scopes/std/packages/fs/versions (HTTP 200, 30560 bytes, recorded 2026-09-09)
- `std-fs-1.0.24-meta.json`: GET https://jsr.io/@std/fs/1.0.24_meta.json (HTTP 200, 28957 bytes, recorded 2026-09-09)
- `std-fs-1.0.24-version.json`: GET https://api.jsr.io/scopes/std/packages/fs/versions/1.0.24 (HTTP 200, 266 bytes, recorded 2026-09-09)
- `std-fs-1.0.24-dependencies.json`: GET https://api.jsr.io/scopes/std/packages/fs/versions/1.0.24/dependencies (HTTP 200, 1127 bytes, recorded 2026-09-09)
- `std-fs-downloads.json`: GET https://api.jsr.io/scopes/std/packages/fs/downloads (HTTP 200, 73959 bytes, recorded 2026-09-09)
- `std-members.json`: GET https://api.jsr.io/scopes/std/members (HTTP 200, 740 bytes, recorded 2026-09-09)
- `luca-cases-meta.json`: GET https://jsr.io/@luca/cases/meta.json (HTTP 200, 98 bytes, recorded 2026-09-09)
- `luca-cases-package.json`: GET https://api.jsr.io/scopes/luca/packages/cases (HTTP 200, 620 bytes, recorded 2026-09-09)
- `luca-cases-versions.json`: GET https://api.jsr.io/scopes/luca/packages/cases/versions (HTTP 200, 500 bytes, recorded 2026-09-09)
- `luca-cases-1.0.0-meta.json`: GET https://jsr.io/@luca/cases/1.0.0_meta.json (HTTP 200, 791 bytes, recorded 2026-09-09)
- `luca-cases-1.0.0-version.json`: GET https://api.jsr.io/scopes/luca/packages/cases/versions/1.0.0 (HTTP 200, 274 bytes, recorded 2026-09-09)
- `luca-cases-1.0.0-dependencies.json`: GET https://api.jsr.io/scopes/luca/packages/cases/versions/1.0.0/dependencies (HTTP 200, 2 bytes, recorded 2026-09-09)
- `luca-members.json`: GET https://api.jsr.io/scopes/luca/members (HTTP 200, 378 bytes, recorded 2026-09-09)
- `luca-flag-meta.json`: GET https://jsr.io/@luca/flag/meta.json (HTTP 200, 114 bytes, recorded 2026-09-09)
- `luca-flag-package.json`: GET https://api.jsr.io/scopes/luca/packages/flag (HTTP 200, 559 bytes, recorded 2026-09-09)
- `luca-flag-versions.json`: GET https://api.jsr.io/scopes/luca/packages/flag/versions (HTTP 200, 467 bytes, recorded 2026-09-09)
- `oak-oak-meta.json`: GET https://jsr.io/@oak/oak/meta.json (HTTP 200, 1795 bytes, recorded 2026-09-09)
- `oak-oak-package.json`: GET https://api.jsr.io/scopes/oak/packages/oak (HTTP 200, 675 bytes, recorded 2026-09-09)
- `oak-oak-versions.json`: GET https://api.jsr.io/scopes/oak/packages/oak/versions (HTTP 200, 12424 bytes, recorded 2026-09-09)
- `oak-oak-17.2.0-dependencies.json`: GET https://api.jsr.io/scopes/oak/packages/oak/versions/17.2.0/dependencies (HTTP 200, 1683 bytes, recorded 2026-09-09)
- `hono-hono-meta.json`: GET https://jsr.io/@hono/hono/meta.json (HTTP 200, 7832 bytes, recorded 2026-09-09)
- `hono-hono-package.json`: GET https://api.jsr.io/scopes/hono/packages/hono (HTTP 200, 602 bytes, recorded 2026-09-09)
- `hono-hono-versions-page1.json`: GET https://api.jsr.io/scopes/hono/packages/hono/versions?page=1&limit=100 (HTTP 200, 47387 bytes, recorded 2026-09-09)
- `hono-hono-versions-page2.json`: GET https://api.jsr.io/scopes/hono/packages/hono/versions?page=2&limit=100 (HTTP 200, 21799 bytes, recorded 2026-09-09)
- `meta-not-found.txt`: GET https://jsr.io/@luca/trustdiff-no-such-package-9f3a1c/meta.json (HTTP 404, 15 bytes, recorded 2026-09-09)
- `package-not-found.json`: GET https://api.jsr.io/scopes/luca/packages/trustdiff-no-such-package-9f3a1c (HTTP 404, 84 bytes, recorded 2026-09-09)
- `version-not-found.json`: GET https://api.jsr.io/scopes/luca/packages/flag/versions/9.9.9 (HTTP 404, 99 bytes, recorded 2026-09-09)
- `scope-not-found.json`: GET https://api.jsr.io/scopes/nosuchscope9f3a1c/members (HTTP 404, 80 bytes, recorded 2026-09-09)
