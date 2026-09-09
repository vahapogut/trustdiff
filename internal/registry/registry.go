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
	Name      string
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
}

// Source is one registry. Implementations go through internal/httpcache, return
// ErrNotFound for unknown packages and versions, and never panic on unexpected JSON.
type Source interface {
	// Ecosystem names the registry.
	Ecosystem() model.Ecosystem
	// Versions returns the package with every version the registry lists.
	Versions(ctx context.Context, name string) (*VersionList, error)
	// VersionInfo returns the full detail of one version, including anything that
	// needs a separate request (dependencies, provenance, install scripts).
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
