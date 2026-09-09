# Advisory archive fixtures

Three OSV records per ecosystem. The tests zip each directory into an `all.zip`
in a temporary directory and serve it with `net/http/httptest`, so no test here
touches the network.

The records are written by hand rather than recorded, because the point of each
one is a case the index has to get right, and a recorded record carries hundreds
of bytes that have nothing to do with it. Each follows the OSV schema as
published at https://ossf.github.io/osv-schema/ and as observed in the real
archives at `https://osv-vulnerabilities.storage.googleapis.com/<ecosystem>/all.zip`
on 2026-09-10 (npm 214,850,107 bytes and 228,889 records, PyPI 33,793,593 bytes
and 25,361 records, crates.io 3,429,918 bytes and 2,817 records). Ids that name a
real advisory carry that advisory's real shape; the `GHSA-w1th-drwn-*` ids and
`PYSEC-2026-1` are synthetic and say so in their summary. OSV data is published
under CC-BY-4.0.

| file | the case it covers |
| --- | --- |
| `npm/GHSA-35jh-r3h4-6jhm.json` | an `[introduced, fixed)` range, a database severity label, a CVSS v3 vector, and a second affected block for a PyPI package that the npm index must drop |
| `npm/MAL-2025-20690.json` | a malicious-package advisory: `introduced: "0"` and nothing else, so every version is affected, and no severity at all |
| `npm/GHSA-w1th-drwn-npm0.json` | a withdrawn advisory, which a lookup must never return |
| `pypi/GHSA-6d5v-tt3m-jt7v.json` | an `[introduced, last_affected]` range and a mixed case package name |
| `pypi/PYSEC-2026-1.json` | explicitly listed versions with no range, a name that needs PEP 503 normalizing (`Zope.Interface`), no summary so it comes from the details, and no severity |
| `pypi/GHSA-w1th-drwn-pyp0.json` | a withdrawn advisory |
| `cargo/GHSA-2226-4v3c-cff8.json` | a CVSS v3 vector with no database label, and a GIT range beside the SEMVER one that must be ignored because its events are commit hashes |
| `cargo/RUSTSEC-2026-0001.json` | a name that needs lower casing (`Serde`) and no severity |
| `cargo/GHSA-w1th-drwn-crt0.json` | a withdrawn advisory |
