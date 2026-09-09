package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"slices"
	"strings"

	"github.com/vahapogut/trustdiff/internal/model"
)

// The identity of the format and of the tool that wrote it.
const (
	sarifVersion = "2.1.0"
	// sarifSchemaURI is the schema the log declares. It is the OASIS publication of
	// SARIF 2.1.0 errata 01, the same document vendored under
	// testdata/sarif-schema-2.1.0.json that the tests validate against.
	sarifSchemaURI = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
	// toolInformationURI is where a reader of an annotation finds out what the tool is.
	toolInformationURI = "https://github.com/vahapogut/trustdiff"
	// checksDocURI is the rendered docs/checks.md; a rule's helpUri is this document
	// plus the anchor of the check's section, for example #td001-young-version.
	checksDocURI = "https://github.com/vahapogut/trustdiff/blob/main/docs/checks.md"
	// fingerprintKey names the partial fingerprint. The version is part of the key so
	// that changing how the value is computed does not silently merge two identities.
	fingerprintKey = "trustdiffFindingV1"
)

// SARIF writes the report as a SARIF 2.1.0 log with one run, so that a code scanning
// service can annotate the lockfile lines of a pull request.
//
// The run's driver is trustdiff with the build version and an informationUri. Its
// rules are one per check, whether or not the run produced a finding for it, taken
// from the table in this file: internal/checks imports this package, so this package
// cannot import it back and ask checks.All(). A finding whose check the table does
// not know still gets a rule, built from the finding itself, so a log never refers to
// a rule it does not carry. The rule metadata test keeps the table in step with
// docs/checks.md, which is also where every helpUri points.
//
// Levels map block to error, warn to warning and info to note. A finding that came
// from a lockfile gets a physicalLocation with the path and, when the parser knew it,
// the line; SARIF regions start at line 1, so a line of 0 leaves the region out
// rather than writing an invalid one. Each result carries a partial fingerprint over
// the check id, the package ref and the title, which is what keeps a re-run from
// adding a second annotation for a finding that is already there. The package ref and
// the evidence ride along in the result's property bag, since a SARIF result is
// otherwise identified only by its location.
//
// The output is indented with two spaces and ends with a newline, like the JSON
// writer, so that it stays readable in a terminal and diffs line by line.
type SARIF struct{}

// Write renders r to w in one call.
func (SARIF) Write(w io.Writer, r *Report) error {
	rules := sarifRules(r)
	index := make(map[string]int, len(rules))
	for i := range rules {
		index[rules[i].ID] = i
	}

	name := r.Tool.Name
	if name == "" {
		name = "trustdiff"
	}
	log := sarifLog{
		Schema:  sarifSchemaURI,
		Version: sarifVersion,
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           name,
				Version:        r.Tool.Version,
				InformationURI: toolInformationURI,
				Rules:          rules,
			}},
			Results: sarifResults(r, index),
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(log); err != nil {
		return fmt.Errorf("encode sarif log: %w", err)
	}
	return nil
}

// sarifLog is the whole document. The field order is the order SARIF examples use.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool sarifTool `json:"tool"`
	// Results is present even when empty: an empty array says the run scanned and
	// found nothing, while a missing one says the log only exports rule metadata.
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name string `json:"name"`
	// Version is the build version of the binary, omitted for a build that has none.
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

// sarifRule is one check, as a reportingDescriptor.
type sarifRule struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	ShortDescription sarifText `json:"shortDescription"`
	FullDescription  sarifText `json:"fullDescription"`
	HelpURI          string    `json:"helpUri"`
}

// sarifText is a multiformatMessageString or a message with plain text only.
type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string    `json:"ruleId"`
	RuleIndex int       `json:"ruleIndex"`
	Level     string    `json:"level"`
	Message   sarifText `json:"message"`
	// Locations is left out for a subject named on the command line, which has no file.
	Locations           []sarifLocation   `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	// Properties carries the package ref and the finding's evidence object.
	Properties map[string]any `json:"properties"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	// Region is nil when the lockfile parser did not record a line.
	Region *sarifRegion `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

// sarifResults renders every finding of every subject in the order the report holds
// them, which Build has already sorted.
func sarifResults(r *Report, index map[string]int) []sarifResult {
	count := 0
	for i := range r.Subjects {
		count += len(r.Subjects[i].Findings)
	}
	results := make([]sarifResult, 0, count)
	for i := range r.Subjects {
		s := &r.Subjects[i]
		for j := range s.Findings {
			results = append(results, sarifResultFor(&s.Findings[j], s, index))
		}
	}
	return results
}

func sarifResultFor(f *model.Finding, s *Subject, index map[string]int) sarifResult {
	properties := map[string]any{"ref": f.Ref.String()}
	if len(f.Evidence) != 0 {
		properties["evidence"] = f.Evidence
	}
	ruleIndex, ok := index[f.ID]
	if !ok {
		// sarifRules gives every finding a rule, so this is unreachable; -1 is how
		// SARIF spells "no rule index".
		ruleIndex = -1
	}
	return sarifResult{
		RuleID:              f.ID,
		RuleIndex:           ruleIndex,
		Level:               sarifLevel(f.Level),
		Message:             sarifText{Text: sarifMessage(f)},
		Locations:           sarifLocations(findingLocation(f, s)),
		PartialFingerprints: map[string]string{fingerprintKey: fingerprint(f)},
		Properties:          properties,
	}
}

// findingLocation is the finding's own location, falling back to the subject's, which
// is where a check that did not set one would have taken it from anyway.
func findingLocation(f *model.Finding, s *Subject) *model.Location {
	if f.Location != nil {
		return f.Location
	}
	return s.Location
}

// sarifLocations renders the lockfile location, or nothing at all when the subject
// was named on the command line and no file can be annotated.
func sarifLocations(loc *model.Location) []sarifLocation {
	if loc == nil || loc.Path == "" {
		return nil
	}
	physical := sarifPhysicalLocation{ArtifactLocation: sarifArtifactLocation{URI: artifactURI(loc.Path)}}
	if loc.Line > 0 {
		physical.Region = &sarifRegion{StartLine: loc.Line}
	}
	return []sarifLocation{{PhysicalLocation: physical}}
}

// artifactURI turns a lockfile path into the URI reference SARIF wants: the separator
// is always a forward slash, and characters a URI reference cannot carry unescaped,
// such as a space or a number sign, are percent encoded. The path stays relative when
// the report carries it relative, because a code scanning service resolves it against
// the checkout.
func artifactURI(path string) string {
	return (&url.URL{Path: filepath.ToSlash(path)}).EscapedPath()
}

// sarifLevel maps a finding level to the four SARIF levels. A finding at LevelOff
// cannot be produced by a check, and "none" is what SARIF calls a result that carries
// no severity.
func sarifLevel(level model.Level) string {
	switch level {
	case model.LevelBlock:
		return "error"
	case model.LevelWarn:
		return "warning"
	case model.LevelInfo:
		return "note"
	case model.LevelOff:
		return "none"
	}
	return "none"
}

// sarifMessage is the title, then the explanation as a second paragraph. A viewer
// that shows one line shows the title; one that shows the whole message shows the
// evidence with it.
func sarifMessage(f *model.Finding) string {
	if f.Explanation == "" {
		return f.Title
	}
	return f.Title + "\n\n" + f.Explanation
}

// fingerprint is the stable identity of a finding across runs: the check id, the
// package ref and the title. The lockfile line is deliberately left out, because a
// line moves whenever anything above it changes and the annotation should survive
// that. Half of a SHA-256 is plenty to keep two findings of one report apart.
func fingerprint(f *model.Finding) string {
	sum := sha256.Sum256([]byte(f.ID + "\x00" + f.Ref.String() + "\x00" + f.Title))
	return hex.EncodeToString(sum[:16])
}

// sarifRules is the rule list of the run: every check this package knows, in id
// order, followed by the checks only the findings know, also in id order.
func sarifRules(r *Report) []sarifRule {
	rules := make([]sarifRule, 0, len(checkRules))
	known := make(map[string]bool, len(checkRules))
	for i := range checkRules {
		rules = append(rules, checkRules[i].sarifRule())
		known[checkRules[i].ID] = true
	}

	var extra []*model.Finding
	for i := range r.Subjects {
		findings := r.Subjects[i].Findings
		for j := range findings {
			if f := &findings[j]; !known[f.ID] {
				known[f.ID] = true
				extra = append(extra, f)
			}
		}
	}
	slices.SortFunc(extra, func(a, b *model.Finding) int { return strings.Compare(a.ID, b.ID) })
	for _, f := range extra {
		rules = append(rules, unknownRule(f))
	}
	return rules
}

// unknownRule describes a check that is not in the table, so that a build whose
// checks are ahead of this file still writes a log with one rule per check. The
// metadata test fails when the table falls behind docs/checks.md, so this is a
// safety net rather than a path a release takes.
func unknownRule(f *model.Finding) sarifRule {
	name := f.Name
	if name == "" {
		name = f.ID
	}
	return sarifRule{
		ID:               f.ID,
		Name:             name,
		ShortDescription: sarifText{Text: f.Title},
		FullDescription:  sarifText{Text: "This build carries no description for " + f.ID + "; the documentation has one."},
		HelpURI:          helpURI(f.ID, name),
	}
}

// helpURI is the check's section in docs/checks.md. The anchor is the one a markdown
// renderer derives from the heading "## TD001 young-version".
func helpURI(id, name string) string {
	return checksDocURI + "#" + strings.ToLower(id) + "-" + name
}

// checkRule is what a SARIF reader needs to know about a check: the stable id, the
// policy name, one line for a list and a paragraph for a details pane.
type checkRule struct {
	ID    string
	Name  string
	Short string
	Full  string
}

func (c checkRule) sarifRule() sarifRule {
	return sarifRule{
		ID:               c.ID,
		Name:             c.Name,
		ShortDescription: sarifText{Text: c.Short},
		FullDescription:  sarifText{Text: c.Full},
		HelpURI:          helpURI(c.ID, c.Name),
	}
}

// checkRules is every check, in id order, summarized from docs/checks.md. It lives
// here because internal/checks imports this package for the report it fills in, so
// this package cannot import internal/checks to ask it. TD000 is not a registry check
// but a report of an expired policy entry; it carries an id and appears in findings,
// so it carries a rule too. Keep this list in step with docs/checks.md: the test
// TestCheckRulesMatchDocs compares the two.
var checkRules = []checkRule{
	{
		ID: "TD000", Name: "expired-allow",
		Short: "A policy allow entry has expired while it still matches this package.",
		Full: "An allow entry carries an expiry date that has passed, so the check it was written for " +
			"is evaluated again as if the entry were not there. The finding stays in the report until " +
			"someone renews the entry or removes it, which is what keeps a list of exceptions from rotting.",
	},
	{
		ID: "TD001", Name: "young-version",
		Short: "The version was published less than the cooldown ago.",
		Full: "A release that has been public for hours has not had the time it takes for a compromise " +
			"to be noticed and reported, and the malicious releases of the last years were removed within " +
			"hours. The cooldown defaults to 3d, and to 7d for crates.io; the publish time comes from the " +
			"registry, or from deps.dev when the registry records none.",
	},
	{
		ID: "TD002", Name: "publisher-changed",
		Short: "The publishing account is not among the publishers of the previous versions.",
		Full: "The account that published this version does not appear among the accounts that published " +
			"the previous releases, which is how a handover of a package shows up in the registry. The " +
			"window is the previous five non-prerelease, non-yanked releases by publish time.",
	},
	{
		ID: "TD003", Name: "maintainers-changed",
		Short: "The maintainer set differs from the set at the previous version.",
		Full: "Maintainers were added or removed between the previous version and this one. npm records " +
			"the set per version; crates.io and PyPI expose current ownership only, so there the comparison " +
			"is against the committed baseline.",
	},
	{
		ID: "TD004", Name: "trust-downgrade",
		Short: "The publishing evidence is weaker than the previous version's.",
		Full: "The previous version carried a verified build attestation or a trusted publishing record " +
			"and this one carries a bare signature or nothing. Strength runs none, signature, attestation, " +
			"trusted publisher, and a verified record ranks above an unverified one of the same kind.",
	},
	{
		ID: "TD005", Name: "install-script-introduced",
		Short: "The version added an install script the previous version did not declare.",
		Full: "An npm version declares preinstall, install, postinstall or prepare while the previous " +
			"version declared none. The first three run on every install of the package, so code that " +
			"arrives this way runs on the machine of everyone who updates.",
	},
	{
		ID: "TD006", Name: "install-script-present",
		Short: "The version runs code at install time.",
		Full: "The version runs code before or during installation: an npm install script, a crate with a " +
			"build.rs or a proc-macro library, or a PyPI release published as an sdist only, whose setup.py " +
			"executes on install. It is normal for many packages and is reported so that it is a decision.",
	},
	{
		ID: "TD007", Name: "new-dependency-introduced",
		Short: "The version declares a runtime dependency the previous version did not.",
		Full: "Every added dependency is reported on its own, so that a reviewed one can be allowed " +
			"separately. A new dependency that is itself young, barely used or unknown to deps.dev is " +
			"escalated, because a package that pulls in a payload usually pulls in a fresh one.",
	},
	{
		ID: "TD008", Name: "typosquat-suspect",
		Short: "The name looks like a misspelling of a popular package.",
		Full: "The name is a small edit away from a name on the ecosystem's popular list while the package " +
			"itself is not on that list, or deps.dev reports a much more popular package with a similar " +
			"name. The check compares names only; it says nothing about what the package contains.",
	},
	{
		ID: "TD009", Name: "malicious-advisory",
		Short: "A malicious package advisory covers this version.",
		Full: "OSV lists the version under an advisory whose id starts with MAL-, or deps.dev reports a " +
			"MALICIOUS finding for it. The two sources are consulted independently, so one of them being " +
			"unavailable does not silence the other.",
	},
	{
		ID: "TD010", Name: "vulnerability",
		Short: "An advisory at or above the configured severity affects this version.",
		Full: "OSV reports a vulnerability that affects the version and whose severity is at or above the " +
			"policy threshold, which defaults to high, one finding per advisory. The severity is the " +
			"advisory's own label, or the base score computed from its CVSS vector.",
	},
	{
		ID: "TD011", Name: "deprecated-or-yanked",
		Short: "The version or the package is deprecated, yanked or archived.",
		Full: "The registry marks the version yanked or deprecated, the package as a whole is deprecated " +
			"or archived, or deps.dev reports it deprecated. A yanked version is one the publisher asked " +
			"people to stop installing.",
	},
	{
		ID: "TD012", Name: "low-usage",
		Short: "The package has few weekly downloads.",
		Full: "Weekly downloads are below the policy threshold, which defaults to 500, or deps.dev reports " +
			"a LOW_USAGE finding. Low usage is not a defect; it says how many other people would have " +
			"noticed a problem before you did.",
	},
	{
		ID: "TD013", Name: "exotic-source",
		Short: "The lockfile entry resolves to a git repository, a tarball or an http URL.",
		Full: "The entry does not come from the ecosystem's registry, so what it installs is whatever that " +
			"URL serves at install time, and the registry checks in this list cannot be applied to it.",
	},
	{
		ID: "TD014", Name: "integrity-missing",
		Short: "The lockfile entry has no integrity hash, or resolves over plain http.",
		Full: "Without a hash the lockfile cannot tell that what it installs is what it locked, and a plain " +
			"http URL leaves the download to whatever is on the network path.",
	},
	{
		ID: "TD015", Name: "version-anomaly",
		Short: "The version number does not fit the package's history.",
		Full: "Either the step from the previous release is far beyond the package's own cadence, or the " +
			"version sorts below a release of its own line that was published earlier. Both are how a " +
			"mistaken or a hostile upload tends to look from outside.",
	},
}
