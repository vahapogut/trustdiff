# Local npm provenance verification

The opt-in local verifier removes deps.dev from the decision about whether an
npm build attestation verifies. It requires the separately installed
[Cosign v3.1.3](https://github.com/sigstore/cosign/releases/tag/v3.1.3).

```sh
trustdiff check npm:@sigstore/bundle@5.0.0 --verify-npm-attestations
trustdiff scan . --verify-npm-attestations --cosign-bin /opt/tools/cosign
```

The adapter fetches the public npm attestation endpoint, selects SLSA provenance
v0.2 or v1, and checks the signed npm PURL, exact version and SHA512 integrity.
Cosign then verifies the DSSE signature, certificate, certificate-transparency
evidence and transparency-log evidence. GitHub Actions and GitLab CI identities
are supported. The certificate identity is recorded, and TD004 attributes local
verification to `cosign`. Neither an attestation nor a successful scan proves
that source code is benign. This command verifies metadata binding; it does not
download or execute the package archive.

Cosign normally obtains authenticated trust material through its TUF client.
`--sigstore-root <trusted-root.json>` selects a local Sigstore trusted-root file.
Obtain that file through a trusted channel such as a successfully updated Cosign
TUF cache; a root downloaded from an arbitrary source is not a trust anchor.
Offline mode requires this file and a previously cached npm response:

```sh
trustdiff check npm:@sigstore/bundle@5.0.0 --offline \
  --verify-npm-attestations --sigstore-root /trusted/trusted_root.json
```

Every subprocess has a 45-second timeout and 64 KiB output limits; invocations
are serialized and use fixed arguments without a shell. A bundle response is
limited to 2 MiB before parsing. Missing, unsupported, mismatched or invalid
evidence is reported as unavailable provenance, never a successful local
verification and never silently replaced by deps.dev. Set
`on_data_unavailable: fail` in the policy to require complete evidence (exit3).
Without the opt-in flag, the existing registry/deps.dev behavior is unchanged.

Ordinary tests use a recorded response and a fake process. The `integration`
test uses real Cosign on that response and proves a modified signature fails.
The CI live-integration job installs the same pinned verifier. See
[ADR0009](adr/0009-local-npm-attestation-verification.md).
