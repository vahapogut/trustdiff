package model

import "time"

// Publisher is an account that published a version or maintains a package.
type Publisher struct {
	Name  string `json:"name"`
	Email string `json:"email,omitempty"`
}

// ProvenanceKind is the strongest kind of publishing evidence a version carries.
type ProvenanceKind string

// Kinds from weakest to strongest. Strength() gives the order.
const (
	// ProvenanceNone means the registry exposes no signature or attestation.
	ProvenanceNone ProvenanceKind = "none"
	// ProvenanceSignature means a registry signature only (npm dist.signatures).
	ProvenanceSignature ProvenanceKind = "signature"
	// ProvenanceAttestation means a build attestation (npm provenance, PEP 740, SLSA).
	ProvenanceAttestation ProvenanceKind = "attestation"
	// ProvenanceTrustedPublisher means the registry recorded a trusted publishing
	// identity (PyPI trusted publishers, crates.io trustpub_data).
	ProvenanceTrustedPublisher ProvenanceKind = "trusted-publisher"
)

// Provenance describes how a version was published and whether that evidence was verified.
type Provenance struct {
	Kind ProvenanceKind `json:"kind"`
	// Verified is true when the registry or deps.dev verified the evidence.
	Verified bool `json:"verified"`
	// Identity is the workflow or repository the attestation names, when known.
	Identity string `json:"identity,omitempty"`
}

// Strength orders provenance so that a downgrade can be detected: a lower value for the
// new version than for the previous one is a regression.
func (p Provenance) Strength() int {
	base := 0
	switch p.Kind {
	case ProvenanceSignature:
		base = 1
	case ProvenanceAttestation:
		base = 2
	case ProvenanceTrustedPublisher:
		base = 3
	case ProvenanceNone, "":
		return 0
	}
	if p.Verified {
		return base*2 + 1
	}
	return base * 2
}

// VersionInfo is what a registry knows about one published version. Registry clients
// fill the fields they can; checks treat zero values as unknown, not as absent.
type VersionInfo struct {
	Ref         PackageRef `json:"ref"`
	PublishedAt time.Time  `json:"published_at"`

	// Publisher is the account that published this version (npm _npmUser,
	// crates.io published_by). Nil when the registry does not expose it.
	Publisher *Publisher `json:"publisher,omitempty"`
	// Maintainers is the maintainer or owner set recorded with this version.
	Maintainers []Publisher `json:"maintainers,omitempty"`

	Prerelease bool `json:"prerelease"`
	Yanked     bool `json:"yanked"`
	// Deprecated carries the deprecation message; empty means not deprecated.
	Deprecated string `json:"deprecated,omitempty"`

	// Scripts are the install-time scripts declared by the version, keyed by name
	// (preinstall, install, postinstall, prepare for npm). For crates.io the keys
	// are build.rs and proc-macro; for a PyPI sdist-only release the key is setup.py.
	Scripts map[string]string `json:"scripts,omitempty"`
	// Dependencies are the runtime dependencies declared by the version: name to requirement.
	Dependencies map[string]string `json:"dependencies,omitempty"`

	Provenance Provenance `json:"provenance"`

	// Integrity is the registry checksum in the form the ecosystem uses.
	Integrity string `json:"integrity,omitempty"`
	// WeeklyDownloads is the most recent weekly download count, or -1 when unknown.
	WeeklyDownloads int64 `json:"weekly_downloads"`
}

// HasInstallScript reports whether the version runs code at install time.
func (v *VersionInfo) HasInstallScript() bool { return len(v.Scripts) > 0 }
