# Recorded fixtures

Real responses recorded once with `go run ./scripts/record-fixture`; tests serve them with httptest. Do not edit by hand.

- `querybatch.json`: POST https://api.osv.dev/v1/querybatch (HTTP 200, 781 bytes, recorded 2026-09-09)
- `vuln-MAL-2025-20690.json`: GET https://api.osv.dev/v1/vulns/MAL-2025-20690 (HTTP 200, 687 bytes, recorded 2026-09-09)
- `vuln-GHSA-9x64-5r7x-2q53.json`: GET https://api.osv.dev/v1/vulns/GHSA-9x64-5r7x-2q53 (HTTP 200, 2775 bytes, recorded 2026-09-09)
- `vuln-GHSA-mh6f-8j2x-4483.json`: GET https://api.osv.dev/v1/vulns/GHSA-mh6f-8j2x-4483 (HTTP 200, 1773 bytes, recorded 2026-09-09)
- `vuln-GHSA-qw6h-vgh9-j6wx.json`: GET https://api.osv.dev/v1/vulns/GHSA-qw6h-vgh9-j6wx (HTTP 200, 2390 bytes, recorded 2026-09-09)
- `vuln-GHSA-rv95-896h-c2vc.json`: GET https://api.osv.dev/v1/vulns/GHSA-rv95-896h-c2vc (HTTP 200, 3341 bytes, recorded 2026-09-09)
- `vuln-GHSA-9hjg-9r4m-mvj7.json`: GET https://api.osv.dev/v1/vulns/GHSA-9hjg-9r4m-mvj7 (HTTP 200, 3695 bytes, recorded 2026-09-09)
- `vuln-GHSA-9wx4-h78v-vm56.json`: GET https://api.osv.dev/v1/vulns/GHSA-9wx4-h78v-vm56 (HTTP 200, 3638 bytes, recorded 2026-09-09)
- `vuln-GHSA-gc5v-m9x4-r6x2.json`: GET https://api.osv.dev/v1/vulns/GHSA-gc5v-m9x4-r6x2 (HTTP 200, 3524 bytes, recorded 2026-09-09)
- `vuln-PYSEC-2026-1872.json`: GET https://api.osv.dev/v1/vulns/PYSEC-2026-1872 (HTTP 200, 3587 bytes, recorded 2026-09-09)
- `vuln-PYSEC-2026-1873.json`: GET https://api.osv.dev/v1/vulns/PYSEC-2026-1873 (HTTP 200, 3530 bytes, recorded 2026-09-09)
- `vuln-PYSEC-2026-2275.json`: GET https://api.osv.dev/v1/vulns/PYSEC-2026-2275 (HTTP 200, 3047 bytes, recorded 2026-09-09)
- `vuln-GHSA-fjxv-7rqg-78g4.json`: GET https://api.osv.dev/v1/vulns/GHSA-fjxv-7rqg-78g4 (HTTP 200, 5883 bytes, recorded 2026-09-09)
- `vuln-RUSTSEC-2021-0145.json`: GET https://api.osv.dev/v1/vulns/RUSTSEC-2021-0145 (HTTP 200, 1838 bytes, recorded 2026-09-09)
- `vuln-not-found.json`: GET https://api.osv.dev/v1/vulns/TRUSTDIFF-NO-SUCH-ID-9f3a1c (HTTP 404, 46 bytes, recorded 2026-09-09)

## Why these fixtures

Recorded 2026-09-09 against the live API. Bullets below do not use the
"- `file`:" form on purpose: the record script rewrites lines in that form.

- The request body, querybatch-request.json, is the only hand-written file: three
  queries for npm flatmap-stream 0.1.1, npm express 4.17.1 and PyPI requests
  2.31.0, in the exact bytes the client sends, so the test server can match the
  client's body against it and answer with querybatch.json. The recorded answer
  lists three advisories for flatmap-stream, among them the malicious-package
  record MAL-2025-20690, two for express and six for requests: eleven distinct
  ids, and every one of them has its vuln-<id>.json below so the whole run can be
  replayed offline.
- MAL record, vuln-MAL-2025-20690.json: no severity, no references, a
  database_specific block with malicious-packages-origins only.
- GHSA record with a v3.1 vector and a label, vuln-GHSA-rv95-896h-c2vc.json
  (express open redirect): database_specific.severity MODERATE and
  CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N, which scores 6.1 with a changed
  scope. vuln-GHSA-qw6h-vgh9-j6wx.json carries both a CVSS_V3 and a CVSS_V4
  entry with the label LOW. vuln-GHSA-9x64-5r7x-2q53.json and
  vuln-GHSA-mh6f-8j2x-4483.json are the GitHub records about the same malicious
  flatmap-stream release, CRITICAL with a 9.8 vector and no aliases.
- GHSA record with only a CVSS_V4 entry, vuln-GHSA-fjxv-7rqg-78g4.json
  (form-data): the label CRITICAL still applies, the score stays 0 until a v4
  calculator exists.
- Record without any severity, vuln-RUSTSEC-2021-0145.json (atty): unknown
  severity, database_specific holds only a license.
- Records without a label, vuln-PYSEC-2026-1872.json, vuln-PYSEC-2026-1873.json
  and vuln-PYSEC-2026-2275.json: the score comes from the vector alone;
  PYSEC-2026-2275 also has no summary, so the client derives one from the first
  line of details. The GHSA twins vuln-GHSA-9hjg-9r4m-mvj7.json,
  vuln-GHSA-9wx4-h78v-vm56.json and vuln-GHSA-gc5v-m9x4-r6x2.json show the same
  vulnerabilities with labels.
- Not found, vuln-not-found.json: the 404 body of the vulns endpoint, served for
  any id the tests invent.
