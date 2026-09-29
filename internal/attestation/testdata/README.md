# npm attestation fixture

`sigstore-bundle-5.0.0.json` is the public registry response for
`@sigstore/bundle@5.0.0`, recorded on 2026-09-29 from
https://registry.npmjs.org/-/npm/v1/attestations/@sigstore%2fbundle@5.0.0
and pretty-printed without changing the encoded signed material.

SHA256 of this fixture:
`b6db2dcd0d9fe5abb5ae62b5409d3d153396b94eac3264ea36500588606ef17d`.
It is public factual attestation metadata; no package source is included.
The referenced sigstore-js project is Apache-2.0 licensed.
Ordinary tests only parse or replay this local response. The integration test
uses real Cosign to verify it and reject a deliberately modified signature.
