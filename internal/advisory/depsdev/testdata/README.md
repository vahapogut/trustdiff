# Recorded fixtures

Real responses recorded once with `go run ./scripts/record-fixture`; tests serve them with httptest. Do not edit by hand.

- `versionbatch.json`: POST https://api.deps.dev/v3alpha/versionbatch (HTTP 200, 5618 bytes, recorded 2026-09-09)
- `findingsbatch.json`: POST https://api.deps.dev/v3alpha/findingsbatch (HTTP 200, 4819 bytes, recorded 2026-09-09)
- `similar-jost.json`: GET https://api.deps.dev/v3alpha/systems/NPM/packages/jost:similarlyNamedPackages (HTTP 200, 162 bytes, recorded 2026-09-09)
- `similar-express.json`: GET https://api.deps.dev/v3alpha/systems/NPM/packages/express:similarlyNamedPackages (HTTP 200, 64 bytes, recorded 2026-09-09)
- `similar-types-node.json`: GET https://api.deps.dev/v3alpha/systems/NPM/packages/%40types%2Fnode:similarlyNamedPackages (HTTP 200, 68 bytes, recorded 2026-09-09)
- `similar-not-found.json`: GET https://api.deps.dev/v3alpha/systems/NPM/packages/%40types%2Fnoed:similarlyNamedPackages (HTTP 404, 17 bytes, recorded 2026-09-09)

## Request bodies and why these packages

The two POST fixtures were recorded with the request bodies kept next to them,
`versionbatch-request.json` and `findingsbatch-request.json`, passed to the
script with `-post`. They are hand-written, and a test that changes them must
re-record the answer. (Bullets below do not use the "- `file`:" form on purpose:
the record script rewrites lines in that form.)

* versionbatch: express 4.19.2 (npm, an advisory key, no attestation), requests
  2.32.3 (PyPI, four advisory keys), @sigstore/bundle 3.1.0 (npm, verified SLSA
  provenance and attestation), serde 1.0.210 (crates.io) and express 99.99.99,
  a version that does not exist and comes back as the echoed request alone.
* findingsbatch: flatmap-stream 0.1.1 (removed by npm, so NOT_FOUND on the
  version with package-scoped MALICIOUS and VULNERABLE findings), request 2.88.2
  (DEPRECATED with a reason), boto3 1.43.90 (published the day before the
  recording, so COOLDOWN with an end), express 4.19.2 (REMEDIATION), express
  99.99.99 (NOT_FOUND) and the flatmap-stream package key, which has no
  requestedVersion.
* similar-jost: the docs example, the one popular-name query that returned
  neighbors. similar-express and similar-types-node show that a popular and a
  scoped name return an empty list; similar-not-found is the plain-text 404 for
  a name deps.dev has never indexed.
