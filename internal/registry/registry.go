// Package registry defines what every package registry client looks like to the
// rest of trustdiff: one Source per ecosystem that answers three questions (which
// versions exist and when they were published, what one version looks like in
// detail, and who maintains the package), plus the history helpers the checks use
// to find the previous version and the recent publishers. Concrete clients live in
// the subpackages npm, pypi, crates and deno and are the only code that knows the
// registries' HTTP shapes.
package registry

import (
	"context"
	"errors"
	"time"

	"github.com/vahapogut/trustdiff/internal/model"
)

// ErrNotFound means the registry has no package or version by that name.
var ErrNotFound = errors.New("not found in the registry")

// ErrUnsupported means the registry does not expose the requested data at all
// (for example PyPI download counts); callers report the check as skipped.
var ErrUnsupported = errors.New("not provided by this registry")

// VersionList is what a registry knows about a package as a whole. Every client
// fills Versions with the fields it can get from the package-level response; the
// per-version details that need extra requests come from VersionInfo.
type VersionList struct {
	Ecosystem model.Ecosystem
	// Name is the registry's canonical spelling of the package, which is also
	// the Name of every Ref in Versions. It can differ from what the caller asked
	// for where the registry answers aliases: crates.io serves serde_json for
	// serde-json and Serde. The runner settles a subject's ref on this spelling
	// before it asks anything else about the package, because OSV matches a
	// crates.io name as written and would answer nothing about the other one, which
	// reads exactly like a package with no advisories. PyPI names are PEP 503
	// normalized and npm names are case-sensitive as given.
	Name string
	// Latest is the registry's own idea of the current version (npm dist-tags.latest,
	// PyPI info.version, crates.io max_stable_version); empty when it has none.
	Latest string
	// Created and Modified are the package-level timestamps when the registry has them.
	Created  time.Time
	Modified time.Time
	// Deprecated carries a package-level deprecation or archival message.
	Deprecated string
	// Maintainers is the current maintainer or owner set at the time of the fetch.
	Maintainers []model.Publisher
	// Versions lists every published version, in the order the registry returned them.
	Versions []model.VersionInfo
	// Unknown records the package-level facts a client could not gather, keyed by
	// the model's facet constants with the reason as the value, the way
	// model.VersionInfo.Unknown records a version's. A registry that serves the
	// version list and the package record from different hosts can answer one and
	// not the other, and a check that read the zero value would report "not
	// deprecated" as a fact about a package nobody could ask about.
	Unknown map[string]string
}

// SetUnknown records a package-level fact that could not be gathered.
func (l *VersionList) SetUnknown(facet, reason string) {
	if l.Unknown == nil {
		l.Unknown = map[string]string{}
	}
	l.Unknown[facet] = reason
}

// Source is one registry. Implementations go through internal/httpcache, return
// ErrNotFound for unknown packages and versions, and never panic on unexpected JSON.
type Source interface {
	// Ecosystem names the registry.
	Ecosystem() model.Ecosystem
	// Versions returns the package with every version the registry lists.
	Versions(ctx context.Context, name string) (*VersionList, error)
	// VersionInfo returns the full detail of one version, including anything that
	// needs a separate request (dependencies, provenance, install scripts). A
	// facet that could not be gathered while the version itself was (a crate
	// archive that was not inspected, a PyPI integrity lookup that failed) does
	// not fail the call: the version comes back with that facet at its zero
	// value and named in VersionInfo.Unknown with the reason.
	VersionInfo(ctx context.Context, ref model.PackageRef) (*model.VersionInfo, error)
	// Owners returns the current maintainer or owner set.
	Owners(ctx context.Context, name string) ([]model.Publisher, error)
	// Downloads returns the most recent weekly download count, or ErrUnsupported.
	Downloads(ctx context.Context, name string) (int64, error)
}

// Registry maps ecosystems to their sources.
type Registry map[model.Ecosystem]Source

// For returns the source for an ecosystem.
func (r Registry) For(eco model.Ecosystem) (Source, bool) {
	s, ok := r[eco]
	return s, ok
}
