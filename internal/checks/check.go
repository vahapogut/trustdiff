// Package checks holds the trust checks (one file per TD id), the Subject they run
// against, the Loader that fetches and memoizes registry and advisory data, and the
// runner that evaluates every check for every subject with bounded concurrency and
// applies the policy (levels, off, allow entries, cooldown exclusions).
//
// A check depends on internal/model and on the interfaces in this file only; it
// never talks to a registry. Tests build a Subject by hand or through a fake Loader.
package checks

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/vahapogut/trustdiff/internal/advisory"
	"github.com/vahapogut/trustdiff/internal/advisory/depsdev"
	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/policy"
	"github.com/vahapogut/trustdiff/internal/registry"
)

// Loader fetches what checks need and memoizes it per run, so one packument serves
// every check. Prefetch warms the batch endpoints (OSV querybatch, deps.dev
// versionbatch, npm bulk downloads) for every subject of a run before checks start.
// Every method returns registry.ErrNotFound, registry.ErrUnsupported, or a wrapped
// httpcache error; a check turns those into a skipped entry, never into a pass.
type Loader interface {
	Prefetch(ctx context.Context, refs []model.PackageRef)
	Versions(ctx context.Context, eco model.Ecosystem, name string) (*registry.VersionList, error)
	VersionInfo(ctx context.Context, ref model.PackageRef) (*model.VersionInfo, error)
	Owners(ctx context.Context, eco model.Ecosystem, name string) ([]model.Publisher, error)
	Downloads(ctx context.Context, eco model.Ecosystem, name string) (int64, error)
	Advisories(ctx context.Context, ref model.PackageRef) ([]advisory.Advisory, error)
	DepsDev(ctx context.Context, ref model.PackageRef) (*depsdev.VersionFacts, error)
	SimilarNames(ctx context.Context, eco model.Ecosystem, name string) ([]depsdev.Similar, error)
}

// Data source names used as keys of Subject.Unavailable and in skipped reasons.
const (
	SourceRegistry  = "registry"
	SourceOwners    = "owners"
	SourceDownloads = "downloads"
	SourceOSV       = "osv"
	SourceDepsDev   = "deps.dev"
)

// Subject is one package version under evaluation together with everything the
// runner could gather for it. Nil pointers and entries in Unavailable say what
// could not be fetched; checks that need them report skipped with the reason.
type Subject struct {
	Ref      model.PackageRef
	Location *model.Location
	Direct   bool
	// Now is the run's clock; tests and the demo inject it (TRUSTDIFF_NOW).
	Now time.Time
	// Settings are the policy settings resolved for the subject's ecosystem.
	Settings policy.Settings
	// ResolvedLatest is true when the ref had no version and the runner picked the
	// latest stable one; the report says so.
	ResolvedLatest bool

	// Version is the evaluated version in full detail.
	Version *model.VersionInfo
	// Package is the whole version list, used for history.
	Package *registry.VersionList
	// Previous is the previous version per brief section 4.1 (nil for a first release).
	Previous *model.VersionInfo
	// PreviousInBase is the version the base lockfile had, when running diff and it
	// differs from Previous.
	PreviousInBase *model.VersionInfo
	// Owners is the current maintainer or owner set.
	Owners []model.Publisher
	// Advisories are the OSV advisories affecting the version.
	Advisories []advisory.Advisory
	// DepsDev holds the deps.dev facts, nil when unavailable or unsupported.
	DepsDev *depsdev.VersionFacts
	// DepsDevFindings are the deps.dev findings for the version (MALICIOUS, LOW_USAGE and so on).
	DepsDevFindings []depsdev.Finding
	// Downloads is the weekly download count, -1 when unknown.
	Downloads int64
	// Unavailable records, per data source name, why it could not be fetched.
	Unavailable map[string]error
	// Loader lets a check look up other packages (TD007 inspects introduced dependencies).
	Loader Loader
}

// Setting returns the effective policy setting of a check for this subject.
func (s *Subject) Setting(name string) policy.CheckSetting {
	if cfg, ok := s.Settings.Check(name); ok {
		return cfg
	}
	if cfg, ok := policy.DefaultCheck(name); ok {
		return cfg
	}
	return policy.CheckSetting{}
}

// Skipped reports whether a data source is unavailable and returns the reason.
func (s *Subject) Skipped(source string) (string, bool) {
	if err, ok := s.Unavailable[source]; ok && err != nil {
		return fmt.Sprintf("%s unavailable: %v", source, err), true
	}
	return "", false
}

// Result is what one check returns for one subject: any findings, or the reason it
// could not run. A check that ran and found nothing returns an empty Result.
type Result struct {
	Findings []model.Finding
	Skipped  *model.Skipped
}

// Skip builds a Result that reports the check as skipped.
func Skip(check, reason string) Result {
	return Result{Skipped: &model.Skipped{Check: check, Reason: reason}}
}

// Check is one trust check. ID is the stable TDnnn identifier, Name the policy
// name, Ecosystems the ecosystems it applies to (nil means all).
type Check interface {
	ID() string
	Name() string
	Ecosystems() []model.Ecosystem
	Run(ctx context.Context, s *Subject) Result
}

// AppliesTo reports whether a check applies to an ecosystem.
func AppliesTo(c Check, eco model.Ecosystem) bool {
	ecosystems := c.Ecosystems()
	if len(ecosystems) == 0 {
		return true
	}
	for _, e := range ecosystems {
		if e == eco {
			return true
		}
	}
	return false
}

var (
	registryMu sync.Mutex
	registered = map[string]Check{}
)

// Register adds a check; each check file calls it from init. Registering the same
// id twice is a programming error and panics.
func Register(c Check) {
	registryMu.Lock()
	defer registryMu.Unlock()
	if _, dup := registered[c.ID()]; dup {
		panic("checks: duplicate check id " + c.ID())
	}
	registered[c.ID()] = c
}

// All returns every registered check ordered by id.
func All() []Check {
	registryMu.Lock()
	defer registryMu.Unlock()
	out := make([]Check, 0, len(registered))
	for _, c := range registered {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID() < out[j].ID() })
	return out
}

// Lookup returns a check by id or policy name.
func Lookup(idOrName string) (Check, bool) {
	registryMu.Lock()
	defer registryMu.Unlock()
	if c, ok := registered[idOrName]; ok {
		return c, true
	}
	for _, c := range registered {
		if c.Name() == idOrName {
			return c, true
		}
	}
	return nil, false
}

// NewFinding builds a finding for a check with the subject's effective level.
func NewFinding(c Check, s *Subject, title, explanation string, evidence map[string]any) model.Finding {
	return model.Finding{
		ID:          c.ID(),
		Name:        c.Name(),
		Level:       s.Setting(c.Name()).Level,
		Ref:         s.Ref,
		Title:       title,
		Explanation: explanation,
		Evidence:    evidence,
		Location:    s.Location,
	}
}
