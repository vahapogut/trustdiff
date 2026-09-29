# 0009: Local npm attestations through an explicit Cosign verifier

Status: accepted, 2026-09-29.

## Context

M5 requires a verification path independent of deps.dev indexing. Implementing
Sigstore certificate, SCT, transparency-log and DSSE verification ourselves would
create a new cryptographic implementation to maintain. Importing Cosign's Go
module graph would exceed the existing direct-dependency and binary budgets.

## Decision

`--verify-npm-attestations` explicitly enables a local Cosign 3.1.3 adapter.
The ordinary binary retains its current metadata-only behavior and dependencies.
The adapter fetches public npm bundles through trustdiff's bounded HTTP cache,
selects SLSA provenance, and binds its signed subject to the exact npm package
name, version and SHA512 registry integrity. It passes that digest and algorithm
to `cosign verify-blob-attestation`, retaining certificate, SCT and transparency
log checks. No tarball is downloaded or executed. Only GitHub Actions and GitLab
CI issuers are supported. The verified certificate identity is reported; a valid
attestation does not establish that a repository or its source code is benign.

An executable path and trusted-root file can be selected explicitly. Without a
root file Cosign uses its upstream TUF trust distribution. Offline verification
requires a local root and a cached bundle; it never launches a network-capable
default-root lookup. The adapter bounds runtime and output and invokes no shell.
Verification failure leaves provenance explicitly unavailable, never rescued by
deps.dev in this mode. Local success is attributed to `cosign`, not the registry.

## Consequences

This feature is optional local verification, not an embedded Sigstore verifier.
Cosign is an additional installation only for users selecting this mode. The
six-module, CGO0 and 15MB default binary constraints remain in force. A pinned
real npm fixture plus tamper tests exercise the adapter and actual Cosign in
opt-in integration coverage; ordinary tests remain offline.

Sources checked 2026-09-29:
- https://github.com/sigstore/cosign/blob/v3.1.3/doc/cosign_verify-blob-attestation.md
- https://docs.sigstore.dev/cosign/system_config/custom_components/
- https://docs.npmjs.com/generating-provenance-statements/
