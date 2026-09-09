package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/policy"
)

// TD001 young-version reports a version published less than the policy cooldown
// ago (brief section 4). Applies to every ecosystem. The publish time comes from
// the registry; when the registry lists the version without a time, the deps.dev
// publishedAt for the same version is used instead. The check is skipped when the
// registry was unavailable or no source knows the publish time.
//
// Evidence keys:
//
//	published_at         RFC 3339 publish time of the version, in UTC
//	published_at_source  where the time came from: registry or deps.dev
//	age                  time since the publish in the policy spelling (6h, 2d12h);
//	                     negative when the publish time is after the run clock
//	age_seconds          the same as a whole number of seconds
//	cooldown             the effective cooldown for the ecosystem, policy spelling (3d)
//	cooldown_seconds     the same as a whole number of seconds
//	cooldown_ends_at     RFC 3339 time at which the version leaves the cooldown
type td001 struct{}

func init() { Register(td001{}) }

func (td001) ID() string                    { return "TD001" }
func (td001) Name() string                  { return "young-version" }
func (td001) Ecosystems() []model.Ecosystem { return nil }

// Run compares the version's age at the run clock with the effective cooldown.
func (c td001) Run(_ context.Context, s *Subject) Result {
	if s.Version == nil {
		return noVersionSkip(c, s)
	}
	publishedAt, source := s.Version.PublishedAt, SourceRegistry
	if publishedAt.IsZero() && s.DepsDev != nil && s.DepsDev.Found && !s.DepsDev.PublishedAt.IsZero() {
		publishedAt, source = s.DepsDev.PublishedAt, SourceDepsDev
	}
	if publishedAt.IsZero() {
		return Skip(c.ID(), fmt.Sprintf("publish time of %s is unknown", evaluatedRef(s).Version))
	}
	cooldown := s.Settings.Cooldown
	if cooldown <= 0 {
		cooldown = policy.DefaultCooldown
	}
	now := runClock(s)
	age := now.Sub(publishedAt)
	if age >= cooldown {
		return Result{}
	}
	ver := evaluatedRef(s).Version
	ends := publishedAt.Add(cooldown)
	title := fmt.Sprintf("Published %s, inside the %s cooldown", sinceText(now, publishedAt), policy.FormatDuration(cooldown))
	explanation := fmt.Sprintf("%s was published on %s, %s; the cooldown is %s, so the version has been public for too short a time for problems to be noticed and reported, and it leaves the cooldown on %s",
		ver, whenText(publishedAt), sinceThisRunText(now, publishedAt), policy.FormatDuration(cooldown), whenText(ends))
	if source == SourceDepsDev {
		explanation += " (publish time taken from deps.dev, the registry lists none)"
	}
	evidence := map[string]any{
		"published_at":        whenText(publishedAt),
		"published_at_source": source,
		"age":                 durationText(age),
		"age_seconds":         int64(age.Truncate(time.Second) / time.Second),
		"cooldown":            policy.FormatDuration(cooldown),
		"cooldown_seconds":    int64(cooldown / time.Second),
		"cooldown_ends_at":    whenText(ends),
	}
	return Result{Findings: []model.Finding{NewFinding(c, s, title, explanation, evidence)}}
}

// Helpers shared by the checks in this package.

// noVersionSkip is the Result of a check that needs the evaluated version's details
// when the runner could not load them: the registry's reason when it recorded one,
// a generic one otherwise.
func noVersionSkip(c Check, s *Subject) Result {
	if reason, ok := s.Skipped(SourceRegistry); ok {
		return Skip(c.ID(), reason)
	}
	return Skip(c.ID(), "version details unavailable")
}

// evaluatedRef is the ref of the evaluated version. The registry's own ref is
// preferred because it always carries the version, also when the subject's ref was
// bare and the runner resolved the latest stable version.
func evaluatedRef(s *Subject) model.PackageRef {
	if s.Version != nil && s.Version.Ref.HasVersion() {
		return s.Version.Ref
	}
	return s.Ref
}

// runClock is the run's clock. The runner always sets Subject.Now; the fallback
// keeps a hand-built Subject usable.
func runClock(s *Subject) time.Time {
	if s.Now.IsZero() {
		return time.Now()
	}
	return s.Now
}

// whenText renders a time for explanations and evidence: RFC 3339 in UTC.
func whenText(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// durationText renders a duration in the policy spelling, truncated to whole
// seconds; a negative duration keeps its sign (-6h).
func durationText(d time.Duration) string {
	d = d.Truncate(time.Second)
	if d < 0 {
		return "-" + policy.FormatDuration(-d)
	}
	return policy.FormatDuration(d)
}

// sinceText says how long ago t was at now: "6h ago", or "2h after the run clock"
// for a publish time in the future, which happens with a skewed clock.
func sinceText(now, t time.Time) string {
	d := now.Sub(t).Truncate(time.Second)
	if d < 0 {
		return policy.FormatDuration(-d) + " after the run clock"
	}
	return policy.FormatDuration(d) + " ago"
}

// sinceThisRunText is sinceText phrased relative to the run: "6h before this run".
func sinceThisRunText(now, t time.Time) string {
	d := now.Sub(t).Truncate(time.Second)
	if d < 0 {
		return policy.FormatDuration(-d) + " after this run's clock"
	}
	return policy.FormatDuration(d) + " before this run"
}
