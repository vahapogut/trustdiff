# Recorded fixtures

Real responses recorded once with `go run ./scripts/record-fixture`; tests serve them with httptest. Do not edit by hand.

## Why these fixtures

Every file below is a byte for byte copy of what pypi.org answered on 2026-09-09.
Each one stands for a case the client maps, and every project was chosen for
being small enough to read or for being the canonical case:

- `sampleproject.json` and `sampleproject-4.0.0.json`: the healthy case on a
  small project (7 releases, 17 KB). Every release ships a wheel and an sdist,
  `1.0` is listed without files, `1.3.1` has a second wheel uploaded a year after
  the release so the earliest upload time is the one that counts, and the project
  is owned by an organization (`ownership.organization` is `pypa`, `ownership.roles`
  is empty). 4.0.0 is the release the Integrity API documentation uses as its
  example, and `requires_dist` carries extras markers.
- `requests.json` and `requests-2.32.0.json`: the canonical project the milestone
  acceptance test checks (163 releases, 193 KB, the one large fixture). It has two
  fully yanked releases, `2.32.0` and `2.32.1` (yanked after CVE-2024-35195), a
  prerelease `2.34.0.dev1`, three releases without files, three user owners and
  `requires_dist` lines that spell `charset-normalizer` with a dash in 2.32.0 and
  with an underscore in 2.34.2, which is why dependency keys are normalized.
- `pycrypto.json` and `pycrypto-2.6.1.json`: an sdist-only project (13 releases,
  15 KB; unmaintained since 2014, so it will not change). No release ever had a
  wheel, `requires_dist` is null, and the `1.9a*` releases are prereleases listed
  without files.
- `provenance-sampleproject-4.0.0.json`: a PEP 740 provenance object (HTTP 200)
  with one attestation bundle whose publisher is the GitHub repository
  `pypa/sampleproject` and the workflow `release.yml`.
- `provenance-requests-2.32.0.json` and `provenance-pycrypto-2.6.1.json`: the
  HTTP 404 answer for a wheel and for an sdist without provenance (both predate
  attestation support on PyPI).
- `requests-2.32.99.json`: HTTP 404 for a version that does not exist.
- `not-found.json`: HTTP 404 for a project that does not exist; the test server
  answers every path it does not know with it.

The `ownership` object was present on every project and release response above
and is documented at https://docs.pypi.org/api/json/. The `releases` key of the
project JSON is documented as deprecated in favor of the Index API but is still
served and is what the version list is built from; if it disappears, the tests
in this package keep passing on the recordings and the integration job is what
will notice.

The bodies embed each project's long description as its authors published it:
sampleproject is MIT, requests is Apache-2.0 and pycrypto is public domain, per
the `info.license` field of each recording.

## Recorded files

- `sampleproject.json`: GET https://pypi.org/pypi/sampleproject/json (HTTP 200, 16661 bytes, recorded 2026-09-09)
- `requests.json`: GET https://pypi.org/pypi/requests/json (HTTP 200, 192973 bytes, recorded 2026-09-09)
- `pycrypto.json`: GET https://pypi.org/pypi/pycrypto/json (HTTP 200, 15129 bytes, recorded 2026-09-09)
- `sampleproject-4.0.0.json`: GET https://pypi.org/pypi/sampleproject/4.0.0/json (HTTP 200, 6241 bytes, recorded 2026-09-09)
- `requests-2.32.0.json`: GET https://pypi.org/pypi/requests/2.32.0/json (HTTP 200, 10262 bytes, recorded 2026-09-09)
- `pycrypto-2.6.1.json`: GET https://pypi.org/pypi/pycrypto/2.6.1/json (HTTP 200, 8597 bytes, recorded 2026-09-09)
- `requests-2.32.99.json`: GET https://pypi.org/pypi/requests/2.32.99/json (HTTP 404, 24 bytes, recorded 2026-09-09)
- `not-found.json`: GET https://pypi.org/pypi/trustdiff-this-project-does-not-exist-9f3a/json (HTTP 404, 24 bytes, recorded 2026-09-09)
- `provenance-sampleproject-4.0.0.json`: GET https://pypi.org/integrity/sampleproject/4.0.0/sampleproject-4.0.0-py3-none-any.whl/provenance (HTTP 200, 9060 bytes, recorded 2026-09-09) with Accept: application/vnd.pypi.integrity.v1+json
- `provenance-requests-2.32.0.json`: GET https://pypi.org/integrity/requests/2.32.0/requests-2.32.0-py3-none-any.whl/provenance (HTTP 404, 74 bytes, recorded 2026-09-09) with Accept: application/vnd.pypi.integrity.v1+json
- `provenance-pycrypto-2.6.1.json`: GET https://pypi.org/integrity/pycrypto/2.6.1/pycrypto-2.6.1.tar.gz/provenance (HTTP 404, 63 bytes, recorded 2026-09-09) with Accept: application/vnd.pypi.integrity.v1+json
