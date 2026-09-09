package policy

import (
	"fmt"
	"time"

	"github.com/vahapogut/trustdiff/internal/model"
)

// CheckSetting is the resolved level and options of one check for one ecosystem.
type CheckSetting struct {
	Level model.Level
	// MinSeverity applies to vulnerability: findings below it are not reported.
	MinSeverity string
	// MinWeeklyDownloads applies to low-usage.
	MinWeeklyDownloads int64
}

// Settings are the resolved values for one ecosystem after defaults, the policy and
// the ecosystem override were applied in that order.
type Settings struct {
	Ecosystem              model.Ecosystem
	Cooldown               time.Duration
	PreviousVersionsWindow int
	OnDataUnavailable      OnDataUnavailable
	Checks                 map[string]CheckSetting
}

// Check returns the setting of a check by policy name.
func (s Settings) Check(name string) (CheckSetting, bool) {
	cfg, ok := s.Checks[name]
	return cfg, ok
}

// Effective resolves the settings for one ecosystem. A nil policy yields the built-in
// defaults. The result is a copy; changing it does not change the policy.
func (p *Policy) Effective(eco model.Ecosystem) Settings {
	s := Settings{
		Ecosystem:              eco,
		Cooldown:               DefaultCooldown,
		PreviousVersionsWindow: DefaultPreviousVersionsWindow,
		OnDataUnavailable:      DefaultOnDataUnavailable,
		Checks:                 make(map[string]CheckSetting, len(checkDefaults)),
	}
	for _, d := range checkDefaults {
		s.Checks[d.name] = d.setting
	}
	if p == nil {
		return s
	}
	if p.Cooldown != 0 {
		s.Cooldown = time.Duration(p.Cooldown)
	}
	if p.PreviousVersionsWindow != 0 {
		s.PreviousVersionsWindow = p.PreviousVersionsWindow
	}
	if p.OnDataUnavailable != "" {
		s.OnDataUnavailable = p.OnDataUnavailable
	}
	applyChecks(s.Checks, p.Checks)
	if override, ok := p.Ecosystems[eco]; ok {
		if override.Cooldown != 0 {
			s.Cooldown = time.Duration(override.Cooldown)
		}
		applyChecks(s.Checks, override.Checks)
	}
	return s
}

// applyChecks overlays the fields that were written onto the current settings.
func applyChecks(dst map[string]CheckSetting, src map[string]CheckConfig) {
	for name, cfg := range src {
		cur, ok := dst[name]
		if !ok {
			continue // Validate rejects unknown names; be lenient here
		}
		if cfg.Level != nil {
			cur.Level = *cfg.Level
		}
		if cfg.MinSeverity != nil {
			cur.MinSeverity = *cfg.MinSeverity
		}
		if cfg.MinWeeklyDownloads != nil {
			cur.MinWeeklyDownloads = *cfg.MinWeeklyDownloads
		}
		dst[name] = cur
	}
}

// CooldownExcluded reports whether the package is exempt from the young-version check.
func (p *Policy) CooldownExcluded(ref model.PackageRef) bool {
	if p == nil {
		return false
	}
	for _, pattern := range p.CooldownExclude {
		if pattern.Match(ref) {
			return true
		}
	}
	return false
}

// Allowed returns the first non-expired allow entry covering the check and package.
func (p *Policy) Allowed(check string, ref model.PackageRef, now time.Time) (*AllowEntry, bool) {
	if p == nil {
		return nil, false
	}
	for i := range p.Allow {
		entry := &p.Allow[i]
		if entry.Check != check || entry.Expired(now) {
			continue
		}
		if entry.Package.Match(ref) {
			return entry, true
		}
	}
	return nil, false
}

// ExpiredAllows returns the allow entries whose expiry date has passed. The runner
// reports each one with ExpiredAllowFinding so that a stale exception is noticed and
// renewed or removed instead of silently stopping to apply.
func (p *Policy) ExpiredAllows(now time.Time) []AllowEntry {
	if p == nil {
		return nil
	}
	var out []AllowEntry
	for _, entry := range p.Allow {
		if entry.Expired(now) {
			out = append(out, entry)
		}
	}
	return out
}

// ExpiredAllowFinding builds the warn finding for an expired allow entry. ref is the
// package the entry was consulted for; the finding is attached to that subject.
func ExpiredAllowFinding(entry *AllowEntry, ref model.PackageRef, now time.Time) model.Finding {
	expires := entry.Expires.String()
	today := now.UTC().Format(dateLayout)
	return model.Finding{
		ID:    ExpiredAllowID,
		Name:  ExpiredAllowName,
		Level: model.LevelWarn,
		Ref:   ref,
		Title: fmt.Sprintf("allow entry for %s on %s expired on %s", entry.Check, entry.Package, expires),
		Explanation: fmt.Sprintf("the policy allowed %s for %s until %s (reason: %s); today is %s, so the exception no longer applies and the check is reported again until the entry is renewed or removed",
			entry.Check, entry.Package, expires, entry.Reason, today),
		Evidence: map[string]any{
			"check":   entry.Check,
			"package": entry.Package.String(),
			"reason":  entry.Reason,
			"expires": expires,
		},
	}
}
