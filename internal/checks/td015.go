package checks

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/model/version"
	"github.com/vahapogut/trustdiff/internal/registry"
)

// TD015 version-anomaly reports a version number that does not fit the package's
// history. Two signals, each its own finding, both info by default:
//
//   - jump: the step from the previous release is far beyond the package's cadence
//     (brief section 4). The major component exceeds the previous release's by
//     more than one, or the minor by more than ten while the major is unchanged
//     (1.4.2 to 9.9.9), and the step also exceeds the largest step between
//     consecutive earlier releases, so a package that has jumped by three majors
//     before is not reported for doing it again. Calendar versioning, recognized
//     by a leading component that is a year between 1970 and 2100, is judged
//     against the calendar instead: a major step no larger than the years elapsed
//     between the two publish dates (tz 2023.1 to 2026.1 three years later), or a
//     minor step no larger than the months elapsed within one year (certifi
//     2026.1.4 to 2026.12.1), is the scheme at work, not a jump.
//   - out-of-order: the version sorts below a release of the same major (the same
//     major.minor while the major is 0) that was published earlier, so the upload is
//     not the newest of its own release line (1.2.5 after 1.4.2). A maintenance
//     release on an older line (django 4.2.16 after 5.1.0, express 4.x after 5.0.0)
//     is the normal shape of a maintained project and is not reported.
//
// Both signals use the release history in Subject.Package. Prereleases, yanked
// versions, versions without a publish time and versions that do not parse are left
// out of the comparison set; the previous release is the latest-published one that
// remains, which is what brief section 4.1 and registry.Previous define. The check
// is skipped without a version list, when the evaluated version is missing from it,
// does not parse or has no publish time, and when there is no earlier release.
//
// Evidence keys:
//
//	signal              jump or out-of-order
//	version             the evaluated version
//	published           its publish time, RFC 3339
//	previous            the previous release (jump only)
//	previous_published  its publish time, RFC 3339 (jump only)
//	major_step          the major increase from the previous release (jump only)
//	minor_step          the minor increase from the previous release (jump only)
//	earlier_releases    how many earlier releases the cadence was read from (jump only)
//	max_major_step      the largest major increase between consecutive earlier releases (jump only)
//	max_minor_step      the largest minor increase between consecutive earlier releases
//	                    that share a major (jump only)
//	calendar            true when the version numbers were read as calendar versioning (jump only)
//	earlier_version     the highest earlier-published release of the same line the
//	                    version sorts below (out-of-order only)
//	earlier_published   its publish time, RFC 3339 (out-of-order only)
//	earlier_above       how many earlier-published releases of the same line sort
//	                    above the version (out-of-order only)

// Thresholds of the jump signal: a step larger than these, and larger than any
// step in the package's own history, is a jump.
const (
	versionAnomalyMajorStep = 1
	versionAnomalyMinorStep = 10
)

// Bounds of a leading component read as a calendar year.
const (
	calendarFirstYear = 1970
	calendarLastYear  = 2100
)

type versionAnomaly struct{}

func init() { Register(versionAnomaly{}) }

// ID implements Check.
func (versionAnomaly) ID() string { return "TD015" }

// Name implements Check.
func (versionAnomaly) Name() string { return "version-anomaly" }

// Ecosystems implements Check; nil means every ecosystem.
func (versionAnomaly) Ecosystems() []model.Ecosystem { return nil }

// versionAnomalyRelease is one parsed release of the history.
type versionAnomalyRelease struct {
	info   *model.VersionInfo
	parsed version.Version
	major  int
	minor  int
}

// Run implements Check.
func (c versionAnomaly) Run(_ context.Context, s *Subject) Result {
	if s.Package == nil {
		if reason, down := s.Skipped(SourceRegistry); down {
			return Skip(c.ID(), reason)
		}
		return Skip(c.ID(), "no version history for "+s.Ref.Package().String())
	}
	info := s.Version
	if info == nil {
		info = registry.Find(s.Package, s.Ref.Version)
	}
	if info == nil {
		return Skip(c.ID(), fmt.Sprintf("version %s is not in the registry's version list", s.Ref.Version))
	}
	if info.PublishedAt.IsZero() {
		return Skip(c.ID(), fmt.Sprintf("no publish time for %s", s.Ref))
	}
	current, ok := c.parse(s.Ref.Ecosystem, info)
	if !ok {
		return Skip(c.ID(), fmt.Sprintf("version %q does not parse as a %s version", s.Ref.Version, s.Ref.Ecosystem))
	}
	earlier := c.earlier(s, info.PublishedAt)
	if len(earlier) == 0 {
		return Skip(c.ID(), fmt.Sprintf("no earlier release of %s to compare %s with", s.Ref.Package(), s.Ref.Version))
	}

	var findings []model.Finding
	if f, fired := c.jump(s, &current, earlier); fired {
		findings = append(findings, f)
	}
	if f, fired := c.outOfOrder(s, &current, earlier); fired {
		findings = append(findings, f)
	}
	return Result{Findings: findings}
}

// parse reads one release; ok is false when the version does not parse.
func (versionAnomaly) parse(eco model.Ecosystem, info *model.VersionInfo) (versionAnomalyRelease, bool) {
	parsed, err := version.Parse(eco, info.Ref.Version)
	if err != nil {
		return versionAnomalyRelease{}, false
	}
	major, minor, ok := versionAnomalyComponents(parsed)
	if !ok {
		return versionAnomalyRelease{}, false
	}
	return versionAnomalyRelease{info: info, parsed: parsed, major: major, minor: minor}, true
}

// earlier returns the releases published before publishedAt, oldest first, leaving
// out the evaluated version, prereleases, yanked versions, versions without a
// publish time and versions that do not parse.
func (c versionAnomaly) earlier(s *Subject, publishedAt time.Time) []versionAnomalyRelease {
	var out []versionAnomalyRelease
	for i := range s.Package.Versions {
		v := &s.Package.Versions[i]
		if v.Ref.Version == s.Ref.Version || v.Prerelease || v.Yanked || v.PublishedAt.IsZero() {
			continue
		}
		if !v.PublishedAt.Before(publishedAt) {
			continue
		}
		if r, ok := c.parse(s.Ref.Ecosystem, v); ok {
			out = append(out, r)
		}
	}
	slices.SortStableFunc(out, func(a, b versionAnomalyRelease) int { return a.info.PublishedAt.Compare(b.info.PublishedAt) })
	return out
}

// jump compares the evaluated version with the previous release and, when the step
// is larger than the thresholds and than any step of the package's own cadence,
// reports it against that cadence. Calendar versions are judged against the
// time elapsed between the two releases instead.
func (c versionAnomaly) jump(s *Subject, current *versionAnomalyRelease, earlier []versionAnomalyRelease) (model.Finding, bool) {
	previous := earlier[len(earlier)-1]
	majorStep := current.major - previous.major
	minorStep := current.minor - previous.minor
	maxMajor, maxMinor := cadence(earlier)
	majorJump := majorStep > max(versionAnomalyMajorStep, maxMajor)
	minorJump := majorStep == 0 && minorStep > max(versionAnomalyMinorStep, maxMinor)
	calendar := calendarYear(current.major) && calendarYear(previous.major)
	if calendar {
		years, months := elapsed(previous.info.PublishedAt, current.info.PublishedAt)
		if majorJump && majorStep <= years {
			majorJump = false
		}
		if minorJump && minorStep <= months {
			minorJump = false
		}
	}
	if !majorJump && !minorJump {
		return model.Finding{}, false
	}

	evidence := map[string]any{
		"signal":             "jump",
		"version":            s.Ref.Version,
		"published":          current.info.PublishedAt.UTC().Format(time.RFC3339),
		"previous":           previous.info.Ref.Version,
		"previous_published": previous.info.PublishedAt.UTC().Format(time.RFC3339),
		"major_step":         majorStep,
		"minor_step":         minorStep,
		"earlier_releases":   len(earlier),
		"max_major_step":     maxMajor,
		"max_minor_step":     maxMinor,
		"calendar":           calendar,
	}

	var title, step string
	if majorJump {
		title = fmt.Sprintf("version jumps from %s to %s", previous.info.Ref.Version, s.Ref.Version)
		step = fmt.Sprintf("raises the major from %d to %d", previous.major, current.major)
	} else {
		title = fmt.Sprintf("minor version jumps from %s to %s", previous.info.Ref.Version, s.Ref.Version)
		step = fmt.Sprintf("raises the minor from %d to %d within major %d", previous.minor, current.minor, current.major)
	}
	var cadenceText string
	if len(earlier) == 1 {
		cadenceText = fmt.Sprintf("%s is the only earlier release, so there is no cadence to compare with", previous.info.Ref.Version)
	} else {
		cadenceText = fmt.Sprintf("across the %d earlier releases, consecutive releases raised the major by at most %d and the minor by at most %d",
			len(earlier), maxMajor, maxMinor)
	}
	explanation := fmt.Sprintf("%s (published %s) %s from the previous release %s (published %s); %s",
		s.Ref, c.day(current.info.PublishedAt), step, previous.info.Ref.Version, c.day(previous.info.PublishedAt), cadenceText)
	if calendar {
		explanation += ", and the leading component reads as a calendar year, which the step outruns"
	}
	return NewFinding(c, s, title, explanation, evidence), true
}

// cadence returns the largest major step and the largest minor step within one
// major between consecutive earlier releases, in publish order.
func cadence(earlier []versionAnomalyRelease) (maxMajor, maxMinor int) {
	for i := 1; i < len(earlier); i++ {
		dMajor := earlier[i].major - earlier[i-1].major
		if dMajor > maxMajor {
			maxMajor = dMajor
		}
		if dMajor == 0 {
			if dMinor := earlier[i].minor - earlier[i-1].minor; dMinor > maxMinor {
				maxMinor = dMinor
			}
		}
	}
	return maxMajor, maxMinor
}

// calendarYear reports whether a leading component reads as a calendar year.
func calendarYear(major int) bool {
	return major >= calendarFirstYear && major <= calendarLastYear
}

// elapsed returns the calendar years and months from one publish time to another.
func elapsed(from, to time.Time) (years, months int) {
	from, to = from.UTC(), to.UTC()
	years = to.Year() - from.Year()
	months = years*12 + int(to.Month()) - int(from.Month())
	return years, months
}

// sameLine reports whether two releases belong to the same release line: the
// same major, or the same major.minor while the major is 0.
func sameLine(a, b *versionAnomalyRelease) bool {
	if a.major != b.major {
		return false
	}
	return a.major != 0 || a.minor == b.minor
}

// outOfOrder reports the evaluated version when an earlier-published release of
// the same line sorts above it.
func (c versionAnomaly) outOfOrder(s *Subject, current *versionAnomalyRelease, earlier []versionAnomalyRelease) (model.Finding, bool) {
	var highest *versionAnomalyRelease
	above := 0
	for i := range earlier {
		r := &earlier[i]
		if !sameLine(current, r) || current.parsed.Compare(r.parsed) >= 0 {
			continue
		}
		above++
		if highest == nil || r.parsed.Compare(highest.parsed) > 0 {
			highest = r
		}
	}
	if highest == nil {
		return model.Finding{}, false
	}
	evidence := map[string]any{
		"signal":            "out-of-order",
		"version":           s.Ref.Version,
		"published":         current.info.PublishedAt.UTC().Format(time.RFC3339),
		"earlier_version":   highest.info.Ref.Version,
		"earlier_published": highest.info.PublishedAt.UTC().Format(time.RFC3339),
		"earlier_above":     above,
	}
	title := fmt.Sprintf("%s published after %s, which sorts above it", s.Ref.Version, highest.info.Ref.Version)
	noun := "earlier release sorts"
	if above > 1 {
		noun = "earlier releases sort"
	}
	explanation := fmt.Sprintf("%s was published on %s but sorts below %s, published on %s; %d %s above it within the same release line, so this upload is not the newest version of its line",
		s.Ref, c.day(current.info.PublishedAt), highest.info.Ref.Version, c.day(highest.info.PublishedAt), above, noun)
	return NewFinding(c, s, title, explanation, evidence), true
}

func (versionAnomaly) day(t time.Time) string { return t.UTC().Format("2006-01-02") }

// versionAnomalyComponents returns the major and minor numbers of a parsed version.
// It reads the release segment of the canonical spelling: "vMAJOR.MINOR.PATCH[-pre]"
// for semver (x/mod/semver keeps the v and drops build metadata) and
// "[EPOCH!]N(.N)*[{a|b|rc}N][.postN][.devN][+local]" for PEP 440, so the release
// segment is the run of dot-separated numbers after an optional epoch. ok is false
// when there is no leading number or a component does not fit an int.
func versionAnomalyComponents(v version.Version) (major, minor int, ok bool) {
	s := v.Canonical
	if i := strings.IndexByte(s, '!'); i >= 0 {
		s = s[i+1:]
	}
	s = strings.TrimPrefix(s, "v")
	end := 0
	for end < len(s) && (s[end] == '.' || (s[end] >= '0' && s[end] <= '9')) {
		end++
	}
	parts := strings.Split(s[:end], ".")
	if parts[0] == "" {
		return 0, 0, false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, false
	}
	if len(parts) > 1 && parts[1] != "" {
		if minor, err = strconv.Atoi(parts[1]); err != nil {
			return 0, 0, false
		}
	}
	return major, minor, true
}
