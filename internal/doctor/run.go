package doctor

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/vahapogut/trustdiff/internal/configfile"
	"github.com/vahapogut/trustdiff/internal/model"
)

// Options are the settings one doctor run works under.
type Options struct {
	// Params are what the rules judge against, before the manager being evaluated is
	// taken into account: Evaluate fills in each manager's own version and, through
	// Cooldowns, the wait its ecosystem's policy asks for.
	Params Params
	// Cooldowns is the cooldown the policy sets per ecosystem, so that a project
	// that waits three days for npm and seven for crates.io is told to configure
	// three in pnpm and seven wherever Cargo eventually accepts one. A manager whose
	// ecosystem is absent from the map is judged against Params.Cooldown.
	Cooldowns map[model.Ecosystem]time.Duration
	// Levels overrides a rule's default level by rule name. model.LevelOff turns
	// the rule off, which is how a project silences a row it has decided against.
	Levels map[string]model.Level
	// Fix writes the settings the files do not state, where the rule can be
	// written and the file allows it.
	Fix bool
	// Backup writes a timestamped copy of every file before changing it. It is on
	// unless a caller says otherwise, because a tool that edits somebody's
	// configuration without a way back is not one people run twice.
	Backup bool
}

// Scorecard is what one run found.
type Scorecard struct {
	// Root is the directory the run was pointed at.
	Root string
	// Managers are the package managers found, in the order detection returned
	// them.
	Managers []*Manager
	// Results are every rule evaluated against every manager, ordered by manager
	// and then by rule id.
	Results []Result
	// Notes are the things the run could not read, one line each. A note is not a
	// finding: it says the scorecard covers less than it was asked to.
	Notes []string
	// Changed are the files --fix wrote, relative to the root, sorted.
	Changed []string
	// Backups maps a changed file to the backup written beside it.
	Backups map[string]string
	// Failed are the files a fix could not write, relative to the root, sorted. A
	// run that was asked to write and could not is not a run that found nothing to
	// do, and the exit code follows on_data_unavailable for the same reason an
	// unreadable file does.
	Failed []string
}

// Counts returns how many results ended in each status, which is what the summary
// line and the exit code are built from.
func (s *Scorecard) Counts() map[Status]int {
	out := make(map[Status]int, 5)
	for i := range s.Results {
		out[s.Results[i].Status]++
	}
	return out
}

// Problems returns the results that are missing, wrong or unreadable at or above a
// level, which is what --ci fails on.
func (s *Scorecard) Problems(min model.Level) []Result {
	var out []Result
	for i := range s.Results {
		if r := &s.Results[i]; r.Status.Problem() && r.Level >= min && r.Level != model.LevelOff {
			out = append(out, *r)
		}
	}
	return out
}

// Evaluate runs every rule against every manager and, when asked, writes the
// settings it can. It takes the managers rather than finding them so that the
// caller can report what detection found before the slower work starts, and so
// that a test can evaluate a manager it built by hand.
func Evaluate(root string, managers []Manager, opts Options) (*Scorecard, error) { //nolint:gocritic // Options is the package API and reads better by value at the call sites
	if root == "" {
		root = "."
	}
	card := &Scorecard{Root: root, Backups: map[string]string{}}
	for i := range managers {
		m := &managers[i]
		card.Managers = append(card.Managers, m)
		params := opts.paramsFor(m)
		for _, rule := range RulesFor(m.ID) {
			level := opts.level(rule)
			if level == model.LevelOff {
				continue
			}
			results, notes := evaluateRule(root, m, rule, &params)
			for j := range results {
				results[j].Rule = rule
				results[j].Manager = m
				results[j].Level = level
				results[j].params = params
			}
			card.Results = append(card.Results, results...)
			card.Notes = append(card.Notes, notes...)
		}
	}
	if opts.Fix {
		applyFixes(root, card, &opts)
	}
	sort.Strings(card.Changed)
	sort.Strings(card.Failed)
	return card, nil
}

// paramsFor is what the rules judge one manager against: the run's parameters with
// this manager's own version and its ecosystem's cooldown filled in.
func (o *Options) paramsFor(m *Manager) Params {
	params := o.Params
	params.Version = m.Version
	params.VersionExact = m.VersionExact
	params.Cooldowns = o.Cooldowns
	if eco, ok := m.ID.Ecosystem(); ok {
		if cooldown, ok := o.Cooldowns[eco]; ok && cooldown > 0 {
			params.Cooldown = cooldown
		}
	}
	return params
}

// level is the level a rule is reported at, after the policy.
func (o *Options) level(r *Rule) model.Level {
	if l, ok := o.Levels[r.Name]; ok {
		return l
	}
	return r.Level
}

// evaluateRule judges one rule for one manager, and returns the notes for
// anything it could not read.
func evaluateRule(root string, m *Manager, rule *Rule, params *Params) ([]Result, []string) {
	applies, caveat := rule.Applies(m)
	if !applies {
		return []Result{{Status: StatusNotApplicable, Detail: caveat}}, nil
	}
	var results []Result
	var notes []string
	if rule.Scan != nil {
		scanned, err := rule.Scan.Scan(root, m, params)
		if err != nil {
			return []Result{{Status: StatusUnreadable, Detail: err.Error()}},
				[]string{fmt.Sprintf("%s: %v", rule.Name, err)}
		}
		results = scanned
	} else {
		results, notes = evaluateTargets(root, m, rule, params)
	}
	for i := range results {
		// An advice rule judges nothing, so its note is the whole content of the
		// line. Without this the scorecard prints a status and an id and leaves the
		// reader to guess what the question was.
		if results[i].Status == StatusAdvice && results[i].Detail == "" {
			results[i].Detail = rule.Note
		}
	}
	if caveat != "" {
		// The caveat rides on every result of the rule, because somebody deciding
		// whether to act on a line has to know what the answer rests on.
		for i := range results {
			results[i].Detail = appendSentence(results[i].Detail, caveat)
		}
	}
	return results, notes
}

// evaluateTargets reads the rule's files in order and judges the first one that
// states the key. A rule whose files all exist and state nothing is missing, and
// the file named is the one a fix would write.
func evaluateTargets(root string, m *Manager, rule *Rule, params *Params) ([]Result, []string) {
	var notes []string
	var fallback *Result
	for _, target := range rule.Targets {
		rel, full := targetPath(root, m, target)
		data, err := readConfig(full)
		switch {
		case errors.Is(err, os.ErrNotExist):
			// A file that is not there is not a problem by itself: another of the
			// rule's files may hold the setting, and only if none does is the first
			// one that may be created the place to write it.
			if fallback == nil && target.CreateIf {
				fallback = &Result{Status: StatusMissing, File: rel, target: target}
			}
			continue
		case err != nil:
			notes = append(notes, fmt.Sprintf("%s: %v", rel, err))
			return []Result{{Status: StatusUnreadable, Detail: fmt.Sprintf("could not be read: %v", err), File: rel}}, notes
		}
		doc := configfile.NewDoc(rel, target.Format, data)
		value, err := configfile.Get(doc, target.Key)
		if err != nil {
			notes = append(notes, fmt.Sprintf("%s: %v", rel, err))
			return []Result{{Status: StatusUnreadable, Detail: fmt.Sprintf("could not be read: %v", err), File: rel}}, notes
		}
		if !value.Found() {
			if fallback == nil {
				fallback = &Result{Status: StatusMissing, File: rel, target: target}
			}
			continue
		}
		status, detail := rule.Desired.Judge(&value, params)
		return []Result{{
			Status:  status,
			Detail:  detail,
			File:    rel,
			Line:    value.Line,
			Current: strings.TrimSpace(value.Raw),
			Want:    rule.Desired.Describe(params),
			target:  target,
		}}, notes
	}

	// No file states the key. The judgment still runs, because a manager whose own
	// default already does what the rule asks is not missing anything.
	status, detail := rule.Desired.Judge(&configfile.Value{}, params)
	res := Result{Status: status, Detail: detail, Want: rule.Desired.Describe(params)}
	if fallback != nil {
		res.File, res.target = fallback.File, fallback.target
	} else if len(rule.Targets) > 0 {
		rel, _ := targetPath(root, m, rule.Targets[0])
		res.File, res.target = rel, rule.Targets[0]
	}
	return []Result{res}, notes
}

// targetPath is where a rule's file is for this manager: the path to report,
// relative to the run root with forward slashes, and the path to open.
func targetPath(root string, m *Manager, t Target) (rel, full string) {
	rel = t.Name
	if m.Root != "" && m.Root != "." {
		rel = m.Root + "/" + t.Name
	}
	if m.UserScope() {
		// A user level file is named in full, because "pip.conf" alone would read
		// as a file of the repository and this one is not. Root is the directory it
		// lives in, which the scorecard already prints in the header, so only the
		// file name is joined here.
		full = filepath.Join(m.Base, filepath.FromSlash(t.Name))
		return filepath.ToSlash(full), full
	}
	return rel, filepath.Join(root, filepath.FromSlash(rel))
}
