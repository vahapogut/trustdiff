# npm attestation fixture

`sigstore-bundle-5.0.0.json` is the public registry response for
`@sigstore/bundle@5.0.0`, recorded on 2026-09-29 from
https://registry.npmjs.org/-/npm/v1/attestations/@sigstore%2fbundle@5.0.0
and pretty-printed without changing the encoded signed material.

SHA256 of this fixture:
`ea4edfccb7d1d9ec72943a237643617201a0f717a4122c197dabc732fcad3836`.
It is public factual attestation metadata; no package source is included.
The referenced sigstore-js project is Apache-2.0 licensed.
Ordinary tests only parse or replay this local response. The integration test
uses real Cosign to verify it and reject a deliberately modified signature.
