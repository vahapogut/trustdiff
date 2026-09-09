# Recorded fixtures

Real responses recorded once with `go run ./scripts/record-fixture`; tests serve them with httptest. Do not edit by hand.

## Why these fixtures

Every file below is a byte for byte copy of what registry.npmjs.org or
api.npmjs.org answered on 2026-09-09. Full packuments grow with the version
count, so the packages are the smallest real ones that show each shape the
client maps. (These bullets avoid the "- `file`:" form on purpose: the record
script rewrites lines in that form and appends new recordings at the end of
the file, which is why the list of recordings is the last section.)

- Healthy package, isarray.json: nine versions, one maintainer, ECDSA
  `dist.signatures` on every version and no attestations, so it is the
  signature-only baseline that the attestation case below is compared against.
  2.0.4 declares a test script and an empty dependencies object, which map to
  no scripts and no dependencies.
- Scoped name with attestations, sigstore-bundle.json (`@sigstore/bundle`,
  requested as `@sigstore%2Fbundle`): thirteen versions, every one of them with
  `dist.attestations` next to `dist.signatures`. 1.0.0 to 3.1.0 were published
  by bdehamer with a token and still carry provenance, because the attestation
  is produced by the workflow; 4.0.0 and 5.0.0 were published through trusted
  publishing, where `_npmUser` is the synthetic "GitHub Actions" account
  carrying a `trustedPublisher` object. The evidence did not change at the
  switch, the publishing account did, which is what TD002 sees on a legitimate
  package. The per-version `maintainers` set has two entries up to 4.0.0 and
  one at 5.0.0 (mylesborins removed), the TD003 shape.
- Publisher change, event-stream.json: the publicly documented handover. 3.3.4
  (2016-07-17) was published by dominictarr, 3.3.5 (2018-09-05) by right9ctrl,
  and the per-version `maintainers` set grows from one to two at 3.3.5, so
  Previous(3.3.5) is 3.3.4 and the five-version window before it is all
  dominictarr. 3.3.6 was unpublished and is named in `time` but absent from
  `versions`. Versions 2.1.2 to 3.0.18 have no `_npmUser`, 0.9.1 has only a
  `shasum` without `signatures` or `integrity`, and the registry lists the 84
  versions in an order that is not publish order. The current top-level
  maintainer is npm, which took the package over after the incident.
- Install script introduced, parcel-bundler.json: 1.2.0 has `test`, `format`,
  `build`, `prepublish` and `precommit` scripts and no install script; 1.2.1
  (2017-12-18) added `scripts.postinstall`, a `node -e` banner that prints a
  link to opencollective.com/parcel/donate, and every later version up to
  1.12.5 keeps it (35 of the 43 versions). Every version is deprecated
  ("Parcel v1 is no longer maintained"), which exercises the package-level
  deprecation rule, and the list has prerelease versions (1.0.0-alpha.1,
  1.10.0-beta.1) and a `beta` dist-tag.
- Security holding placeholder, flatmap-stream.json: what npm left after
  removing the malicious package of the event-stream incident (OSV
  MAL-2025-20690). The marker the client keys on is the description "security
  holding package", present both at the top level and in the single version
  `0.0.1-security`; the repository is github.com/npm/security-holder, the
  top-level maintainer is npm and the version was published by an npm employee.
  The removed 11.1.1 (2018-11-28) is still named in `time`, one day before the
  placeholder.
- Download counts, downloads-isarray.json, downloads-sigstore-bundle.json and
  downloads-bulk.json: the point endpoint for a plain and a scoped name (the
  scoped one requested with its slash intact, as the download-counts
  documentation shows) and one bulk answer holding two known names and `null`
  for an unknown one. The bulk endpoint refuses scoped names with HTTP 400, so
  there is no recording for that; the client never sends them in bulk.
- Not found, not-found.json and downloads-not-found.json: the 404 bodies of both
  APIs, served by the test server for every path it does not know.

## Recorded files

- `isarray.json`: GET https://registry.npmjs.org/isarray (HTTP 200, 17392 bytes, recorded 2026-09-09)
- `sigstore-bundle.json`: GET https://registry.npmjs.org/@sigstore%2Fbundle (HTTP 200, 25054 bytes, recorded 2026-09-09)
- `event-stream.json`: GET https://registry.npmjs.org/event-stream (HTTP 200, 119714 bytes, recorded 2026-09-09)
- `parcel-bundler.json`: GET https://registry.npmjs.org/parcel-bundler (HTTP 200, 223475 bytes, recorded 2026-09-09)
- `flatmap-stream.json`: GET https://registry.npmjs.org/flatmap-stream (HTTP 200, 3088 bytes, recorded 2026-09-09)
- `downloads-isarray.json`: GET https://api.npmjs.org/downloads/point/last-week/isarray (HTTP 200, 83 bytes, recorded 2026-09-09)
- `downloads-sigstore-bundle.json`: GET https://api.npmjs.org/downloads/point/last-week/@sigstore/bundle (HTTP 200, 90 bytes, recorded 2026-09-09)
- `not-found.json`: GET https://registry.npmjs.org/trustdiff-no-such-package-9f3a1c (HTTP 404, 21 bytes, recorded 2026-09-09)
- `downloads-not-found.json`: GET https://api.npmjs.org/downloads/point/last-week/trustdiff-no-such-package-9f3a1c (HTTP 404, 62 bytes, recorded 2026-09-09)
- `downloads-bulk.json`: GET https://api.npmjs.org/downloads/point/last-week/isarray,event-stream,trustdiff-no-such-package-9f3a1c (HTTP 200, 237 bytes, recorded 2026-09-09)
