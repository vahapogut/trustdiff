package doctor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vahapogut/trustdiff/internal/model"
)

// The fixture is written by hand rather than detected, so that this test is about
// the judgment and the writing and not about detection, which has its own.
const (
	pnpmWorkspace = `packages:
  - "apps/*"

# Wait before installing a release nobody has looked at yet.
minimumReleaseAge: 60
strictDepBuilds: true
`
	bunfig = `[install]
# A week, or so somebody thought.
minimumReleaseAge = 10080
`
)

// A repository whose settings are present and wrong is the case doctor exists for,
// and the one a person cannot see by reading their own file.
func TestEvaluateJudgesWhatTheFilesHold(t *testing.T) {
	root := writeFixture(t)
	card, err := Evaluate(root, fixtureManagers(), Options{Params: Params{Cooldown: threeDays, Version: "11.2.0", Now: fixedNow()}})
	if err != nil {
		t.Fatal(err)
	}

	pnpm := resultFor(t, card, "DR010")
	if pnpm.Status != StatusWeak {
		t.Errorf("pnpm minimumReleaseAge = %s (%s), want weak: 60 minutes is an hour, which pnpm waits", pnpm.Status, pnpm.Detail)
	}
	if pnpm.Line != 5 {
		t.Errorf("pnpm line = %d, want the line the key sits on", pnpm.Line)
	}
	bun := resultFor(t, card, "DR030")
	if bun.Status != StatusWeak || !strings.Contains(bun.Detail, "minutes") {
		t.Errorf("bun minimumReleaseAge = %s (%s), want weak and a word about the unit", bun.Status, bun.Detail)
	}
	if strict := resultFor(t, card, "DR011"); strict.Status != StatusSet {
		t.Errorf("strictDepBuilds = %s (%s), want set", strict.Status, strict.Detail)
	}
	// The npm file exists and is empty, so its settings are missing rather than
	// unreadable, and the fix knows where to write them.
	npm := resultFor(t, card, "DR001")
	if npm.Status != StatusMissing || npm.File != ".npmrc" {
		t.Errorf("npm min-release-age = %s in %q, want missing in .npmrc", npm.Status, npm.File)
	}
}

// Fixing writes the value each manager counts in for a key the file does not
// have, leaves everything else alone, and does nothing at all the second time. A
// key that is already there is never rewritten, which
// TestWeakValuesAreReportedAndNeverRewritten is about; this is the other half,
// that the value written for an absent one is in the manager's own unit.
func TestFixWritesEachManagersUnitAndIsIdempotent(t *testing.T) {
	root := writeFixture(t)
	opts := Options{
		Params: Params{Cooldown: threeDays, Version: "11.2.0", Now: fixedNow()},
		Fix:    true,
		Backup: true,
	}
	card, err := Evaluate(root, fixtureManagers(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(card.Changed) == 0 {
		t.Fatal("nothing was written")
	}

	workspace := readFile(t, root, "pnpm-workspace.yaml")
	for _, keep := range []string{`  - "apps/*"`, "# Wait before installing a release nobody has looked at yet.", "strictDepBuilds: true", "minimumReleaseAge: 60"} {
		if !strings.Contains(workspace, keep) {
			t.Errorf("the edit lost %q:\n%s", keep, workspace)
		}
	}
	// npm's file is the one with nothing in it, so npm's is the wait that gets
	// written, in npm's own unit.
	if npmrc := readFile(t, root, ".npmrc"); !strings.Contains(npmrc, "min-release-age=3") && !strings.Contains(npmrc, "min-release-age = 3") {
		t.Errorf(".npmrc does not hold the wait in days:\n%s", npmrc)
	}

	// A backup of every file that was changed, so there is a way back.
	for _, changed := range card.Changed {
		if card.Backups[changed] == "" {
			t.Errorf("%s was written with no backup beside it", changed)
		}
	}

	// The second run has nothing left to do, which is what makes doctor --fix safe
	// to put in a script.
	before := readFile(t, root, "pnpm-workspace.yaml")
	again, err := Evaluate(root, fixtureManagers(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(again.Changed) != 0 {
		t.Errorf("the second run wrote %v, want nothing", again.Changed)
	}
	if after := readFile(t, root, "pnpm-workspace.yaml"); after != before {
		t.Errorf("the second run changed the file:\n%s", after)
	}
}

// A rule the manager's version does not have is reported as not applicable, and
// never as a setting somebody forgot.
func TestEvaluateSkipsRulesTheVersionDoesNotHave(t *testing.T) {
	root := writeFixture(t)
	managers := []Manager{{ID: PNPM, Root: ".", Version: "10.20.0", VersionExact: true, Files: []string{"pnpm-workspace.yaml"}}}
	card, err := Evaluate(root, managers, Options{Params: Params{Cooldown: threeDays, Version: "10.20.0", Now: fixedNow()}})
	if err != nil {
		t.Fatal(err)
	}
	if got := resultFor(t, card, "DR012"); got.Status != StatusNotApplicable {
		t.Errorf("allowBuilds on pnpm 10.20 = %s, want not applicable: it arrived in 10.26", got.Status)
	}
	if got := resultFor(t, card, "DR013"); got.Status != StatusAdvice {
		t.Errorf("onlyBuiltDependencies on pnpm 10.20 = %s, want advice: that version reads the key, and which packages may build is not a tool's decision", got.Status)
	}
}

// A rule the policy turned off is not evaluated at all, so it cannot fail a gate
// and cannot be written by a fix.
func TestEvaluateHonoursARuleTurnedOff(t *testing.T) {
	root := writeFixture(t)
	opts := Options{
		Params: Params{Cooldown: threeDays, Version: "11.2.0", Now: fixedNow()},
		Levels: map[string]model.Level{"pnpm-minimum-release-age": model.LevelOff},
		Fix:    true,
	}
	card, err := Evaluate(root, fixtureManagers(), opts)
	if err != nil {
		t.Fatal(err)
	}
	for i := range card.Results {
		if r := &card.Results[i]; r.Rule != nil && r.Rule.ID == "DR010" {
			t.Fatalf("a rule set to off was evaluated anyway: %s", r.Status)
		}
	}
	if workspace := readFile(t, root, "pnpm-workspace.yaml"); !strings.Contains(workspace, "minimumReleaseAge: 60") {
		t.Errorf("a rule set to off was written anyway:\n%s", workspace)
	}
}

// A configuration file that is a symbolic link is not read. A repository in a pull
// request decides what its files are, and git records a link as a blob holding the
// link text, so a fork can commit .npmrc as a link to any path on the runner.
func TestEvaluateRefusesASymbolicLink(t *testing.T) {
	root := writeFixture(t)
	secret := filepath.Join(t.TempDir(), "secret.yaml")
	if err := os.WriteFile(secret, []byte("minimumReleaseAge: 99999\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "apps", "linked", "pnpm-workspace.yaml")
	if err := os.MkdirAll(filepath.Dir(link), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, link); err != nil {
		t.Skipf("this machine does not allow creating a symbolic link: %v", err)
	}

	managers := []Manager{{ID: PNPM, Root: "apps/linked", Version: "11.2.0", VersionExact: true, Files: []string{"apps/linked/pnpm-workspace.yaml"}}}
	card, err := Evaluate(root, managers, Options{Params: Params{Cooldown: threeDays, Version: "11.2.0", Now: fixedNow()}})
	if err != nil {
		t.Fatal(err)
	}
	got := resultFor(t, card, "DR010")
	if got.Status != StatusUnreadable {
		t.Fatalf("a linked file was read: %s (%s)", got.Status, got.Detail)
	}
	if !strings.Contains(got.Detail, "symbolic link") {
		t.Errorf("the reason does not say what the path is: %s", got.Detail)
	}
	if strings.Contains(got.Detail, "99999") || strings.Contains(got.Current, "99999") {
		t.Error("the content of the linked file reached the scorecard")
	}
}

// writeFixture builds the small repository the tests judge.
func writeFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	write(t, root, "pnpm-workspace.yaml", pnpmWorkspace)
	write(t, root, "bunfig.toml", bunfig)
	write(t, root, ".npmrc", "# the project's own registry settings go here\n")
	return root
}

// fixtureManagers are the managers the fixture would be detected as, built here so
// that these tests do not depend on detection.
func fixtureManagers() []Manager {
	return []Manager{
		{ID: PNPM, Root: ".", Version: "11.2.0", VersionExact: true, VersionSource: "the packageManager field", Files: []string{"pnpm-workspace.yaml"}},
		{ID: Bun, Root: ".", Version: "1.4.2", VersionExact: true, VersionSource: "bun --version", Files: []string{"bunfig.toml"}},
		{ID: NPM, Root: ".", Version: "12.0.2", VersionExact: true, VersionSource: "npm --version", Files: []string{".npmrc"}},
	}
}

// fixedNow is the clock the tests run on, so a backup name is the same every time.
func fixedNow() time.Time {
	return time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
}

func write(t *testing.T, root, name, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, root, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// resultFor returns the result of one rule, and fails when the run did not
// evaluate it.
func resultFor(t *testing.T, card *Scorecard, id string) Result {
	t.Helper()
	for i := range card.Results {
		if r := &card.Results[i]; r.Rule != nil && r.Rule.ID == id {
			return *r
		}
	}
	t.Fatalf("%s is not among the %d results", id, len(card.Results))
	return Result{}
}

// Deno's lock key turns the lockfile itself on and off, which is a different thing
// from not freezing it: with "lock": false nothing pins what an install fetches.
func TestDenoLockfileTurnedOffIsWrongRatherThanMissing(t *testing.T) {
	root := t.TempDir()
	write(t, root, "deno.json", "{\n  \"lock\": false\n}\n")
	managers := []Manager{{ID: Deno, Root: ".", Files: []string{"deno.json"}}}
	card, err := Evaluate(root, managers, Options{Params: Params{Cooldown: threeDays, Now: fixedNow()}})
	if err != nil {
		t.Fatal(err)
	}
	got := resultFor(t, card, "DR042")
	if got.Status != StatusWrong || !strings.Contains(got.Detail, "turned off") {
		t.Fatalf("lock false = %s (%s), want wrong", got.Status, got.Detail)
	}
	// The object form is the configured lockfile, and must not be reported at all.
	other := t.TempDir()
	write(t, other, "deno.json", "{\n  \"lock\": { \"frozen\": true }\n}\n")
	card, err = Evaluate(other, managers, Options{Params: Params{Cooldown: threeDays, Now: fixedNow()}})
	if err != nil {
		t.Fatal(err)
	}
	if got := resultFor(t, card, "DR042"); got.Status != StatusSet {
		t.Errorf("an object lock = %s (%s), want set", got.Status, got.Detail)
	}
	if got := resultFor(t, card, "DR041"); got.Status != StatusSet {
		t.Errorf("frozen inside the object = %s (%s), want set", got.Status, got.Detail)
	}
}

// A value the manager reads and acts on is never reported as a mistake, and
// --fix never rewrites one. Between them those two rules are what makes doctor
// safe to run over somebody else's repository: it fills in what is absent and
// reports what is there, and a deliberate setting is nobody's to overwrite.
//
// The three statuses divide as follows. wrong is a value the manager will not
// accept or reads as something other than what it says, which is a mistake and
// the writer wants to know. weak is a value the manager accepts that does less
// than the policy asks, which is a choice and the scorecard states it. missing
// is the key the file does not have, which is the only thing --fix writes.
func TestWeakValuesAreReportedAndNeverRewritten(t *testing.T) {
	root := writeFixture(t)
	opts := Options{
		Params: Params{Cooldown: threeDays, Version: "11.2.0", Now: fixedNow()},
		Fix:    true,
		Backup: true,
	}
	before := readFile(t, root, "pnpm-workspace.yaml")
	card, err := Evaluate(root, fixtureManagers(), opts)
	if err != nil {
		t.Fatal(err)
	}

	// pnpm reads 60 as sixty minutes and waits an hour, which is a real hour and
	// not a misunderstanding. It is less than the three days the policy asks for,
	// and that is what the scorecard says.
	pnpm := resultFor(t, card, "DR010")
	if pnpm.Status != StatusWeak {
		t.Errorf("pnpm minimumReleaseAge = %s (%s), want weak: pnpm waits the hour the file asks for", pnpm.Status, pnpm.Detail)
	}
	// Bun reads 10080 as seconds, which is under three hours, and whoever wrote it
	// meant a week in pnpm's unit. Bun still accepts it, so it is weak rather than
	// wrong, and the detail is where the unit confusion is said.
	bun := resultFor(t, card, "DR030")
	if bun.Status != StatusWeak || !strings.Contains(bun.Detail, "minutes") {
		t.Errorf("bun minimumReleaseAge = %s (%s), want weak and a word about the unit", bun.Status, bun.Detail)
	}
	if !pnpm.Status.Problem() || !bun.Status.Problem() {
		t.Error("a weak value is a problem the scorecard counts, or nobody reads it")
	}

	// Both values are still exactly what the file said. --fix may well have added
	// keys neither file had, which is its whole job, but not one line that was
	// already there was rewritten.
	after := readFile(t, root, "pnpm-workspace.yaml")
	if !strings.Contains(after, "minimumReleaseAge: 60") {
		t.Errorf("--fix rewrote the wait the file already held:\n%s", after)
	}
	if config := readFile(t, root, "bunfig.toml"); !strings.Contains(config, "minimumReleaseAge = 10080") {
		t.Errorf("--fix rewrote the wait bunfig.toml already held:\n%s", config)
	}
	for _, line := range strings.Split(before, "\n") {
		if trimmed := strings.TrimSpace(line); trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !strings.Contains(after, line) {
			t.Errorf("--fix lost the line %q:\n%s", line, after)
		}
	}
	// A key the file did not have is the one thing --fix writes.
	if npmrc := readFile(t, root, ".npmrc"); !strings.Contains(npmrc, "min-release-age=3") && !strings.Contains(npmrc, "min-release-age = 3") {
		t.Errorf(".npmrc does not hold the wait in days:\n%s", npmrc)
	}
}

// A value the manager will not read at all is still a mistake, and still says so.
func TestAValueTheManagerCannotReadIsWrong(t *testing.T) {
	root := t.TempDir()
	write(t, root, "bunfig.toml", "[install]\nminimumReleaseAge = \"three days\"\n")
	card, err := Evaluate(root, fixtureManagers(), Options{Params: Params{Cooldown: threeDays, Now: fixedNow()}})
	if err != nil {
		t.Fatal(err)
	}
	if got := resultFor(t, card, "DR030"); got.Status != StatusWrong {
		t.Errorf("bun minimumReleaseAge = %s (%s), want wrong: Bun counts seconds and will not read that", got.Status, got.Detail)
	}
}

// pnpm 11 flipped several defaults to the safe value at once. A rule that credits
// one of them without saying which version it arrived in tells a pnpm 10 project
// it is protected by a default that release does not have, which is the one
// mistake a scorecard must never make: the reader closes it and does nothing.
//
// The flip is listed in pnpm's own release notes for 11.0, read 2026-09-10:
// minimumReleaseAge to 1440, minimumReleaseAgeStrict to false, blockExoticSubdeps
// to true, strictDepBuilds to true, optimisticRepeatInstall to true and
// verifyDepsBeforeRun to install. The settings pages print the current default
// with no version beside it, so the pages alone cannot be read for this.
func TestPnpmDefaultsAreCreditedOnlyToTheVersionThatHasThem(t *testing.T) {
	tests := []struct {
		version string
		want    Status
	}{
		{version: "10.26.0", want: StatusMissing},
		{version: "11.2.0", want: StatusSet},
	}
	for _, tt := range tests {
		t.Run("pnpm "+tt.version, func(t *testing.T) {
			root := t.TempDir()
			write(t, root, "pnpm-workspace.yaml", "packages:\n  - \"apps/*\"\n")
			managers := []Manager{{
				ID: PNPM, Root: ".", Version: tt.version, VersionExact: true,
				VersionSource: "the packageManager field", Files: []string{"pnpm-workspace.yaml"},
			}}
			card, err := Evaluate(root, managers, Options{Params: Params{Cooldown: threeDays, Version: tt.version, Now: fixedNow()}})
			if err != nil {
				t.Fatal(err)
			}
			for _, id := range []string{"DR011", "DR014"} {
				got := resultFor(t, card, id)
				if got.Status != tt.want {
					t.Errorf("%s on pnpm %s = %s (%s), want %s", id, tt.version, got.Status, got.Detail, tt.want)
				}
			}
		})
	}
}
