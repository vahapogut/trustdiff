// Package depsdev talks to the deps.dev v3alpha API (Google Open Source Insights).
// It is an accelerator and a cross-check, never the only source: version facts
// (publish time, deprecation, verified attestations and SLSA provenance, cooldown),
// findings (MALICIOUS, DEPRECATED, COOLDOWN, LOW_USAGE, VULNERABLE) and similarly
// named packages. deps.dev has no Deno or JSR system; those refs report unsupported.
//
// Endpoints, verified 2026-09-09 against https://docs.deps.dev/api/v3alpha/:
//
//	POST https://api.deps.dev/v3alpha/versionbatch  (up to 5000 version keys)
//	POST https://api.deps.dev/v3alpha/findingsbatch
//	GET  https://api.deps.dev/v3alpha/systems/<SYSTEM>/packages/<name>:similarlyNamedPackages
package depsdev

import (
	"context"
	"errors"
	"time"

	"github.com/vahapogut/trustdiff/internal/httpcache"
	"github.com/vahapogut/trustdiff/internal/model"
)

// ErrUnsupported is returned for ecosystems deps.dev does not index (Deno, JSR).
var ErrUnsupported = errors.New("ecosystem not indexed by deps.dev")

// VersionFacts is what deps.dev knows about one package version.
type VersionFacts struct {
	// Found is false when deps.dev has never seen the version.
	Found       bool      `json:"found"`
	PublishedAt time.Time `json:"published_at,omitempty"`
	// IsDeprecated mirrors the registry deprecation flag as deps.dev sees it.
	IsDeprecated bool `json:"is_deprecated"`
	// AdvisoryKeys lists the advisory ids deps.dev links to the version.
	AdvisoryKeys []string `json:"advisory_keys,omitempty"`
	// AttestationVerified is true when deps.dev verified a build attestation
	// (npm provenance or PyPI PEP 740); SLSAVerified when it verified SLSA provenance.
	AttestationVerified bool `json:"attestation_verified"`
	SLSAVerified        bool `json:"slsa_verified"`
	// CooldownEnd is the end of the deps.dev cooldown window when one is reported.
	CooldownEnd time.Time `json:"cooldown_end,omitempty"`
}

// Finding is one deps.dev finding for a version.
type Finding struct {
	// Type is one of NOT_FOUND, MALICIOUS, DEPRECATED, COOLDOWN, LOW_USAGE, VULNERABLE, REMEDIATION.
	Type string `json:"type"`
	// Risk is the RISK_* level deps.dev assigns.
	Risk string `json:"risk,omitempty"`
	// Detail carries the human text deps.dev returns with the finding.
	Detail string `json:"detail,omitempty"`
}

// Similar is a package whose name resembles the queried one.
type Similar struct {
	Name string `json:"name"`
	// Popularity is the signal deps.dev returns to rank neighbors, when present.
	Popularity int64 `json:"popularity,omitempty"`
}

// Client is the deps.dev API client. All requests go through internal/httpcache.
type Client struct {
	http *httpcache.Client
	base string
}

// New returns a client using the shared HTTP cache.
func New(h *httpcache.Client) *Client {
	return &Client{http: h, base: "https://api.deps.dev/v3alpha"}
}

// Versions returns version facts for every ref deps.dev indexes, batched.
// Refs deps.dev has never seen are present with Found false.
func (c *Client) Versions(_ context.Context, _ []model.PackageRef) (map[model.PackageRef]VersionFacts, error) {
	return nil, errors.New("depsdev: Versions not implemented yet (task 1.7)")
}

// Findings returns the deps.dev findings for every ref, batched.
func (c *Client) Findings(_ context.Context, _ []model.PackageRef) (map[model.PackageRef][]Finding, error) {
	return nil, errors.New("depsdev: Findings not implemented yet (task 1.7)")
}

// SimilarNames returns packages with names similar to name in the ecosystem.
func (c *Client) SimilarNames(_ context.Context, _ model.Ecosystem, _ string) ([]Similar, error) {
	return nil, errors.New("depsdev: SimilarNames not implemented yet (task 1.7)")
}

// System maps an ecosystem to the deps.dev system name, or "" when unsupported.
func System(eco model.Ecosystem) string {
	switch eco {
	case model.NPM:
		return "NPM"
	case model.PyPI:
		return "PYPI"
	case model.Cargo:
		return "CARGO"
	default:
		return ""
	}
}
