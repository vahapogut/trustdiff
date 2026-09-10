package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"time"

	"github.com/spf13/cobra"

	"github.com/vahapogut/trustdiff/internal/doctor"
	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/policy"
	"github.com/vahapogut/trustdiff/internal/report"
)

func (a *App) newDoctorCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "doctor [<path>]",
		Short: "Audit or fix package manager hardening settings",
		Long: `Read the hardening settings the package managers of a repository already support
and say which are set, which are missing, and which are set to something that does
not do what the person who wrote it expected.

Every setting is native to the package manager: npm's min-release-age, pnpm's
minimumReleaseAge, Yarn's npmMinimalAgeGate, Bun's, Deno's, uv's, pip's, Poetry's,
and the cooldowns of Dependabot and Renovate. Their units disagree, so the same
three days is 3, 4320, 259200, P3D or "3 days" depending on the file, and a value
in the wrong unit is accepted everywhere without a word. The wait this recommends
is the cooldown your own policy already states.

--fix writes the settings it can, after printing the change as a diff and copying
the file beside itself. It replaces the lines that hold the value and nothing else,
so comments, key order and indentation survive, and running it twice changes
nothing the second time. A setting whose right answer is a judgment, such as which
packages may run a build script, is reported and never written.

--ci exits 1 on any setting that is not doing its job at or above the level the policy's
doctor section sets, which defaults to warn.

Nothing here reaches the network. A package manager on this machine is asked for
its version only when the repository's own files cannot say, and never with
--offline.`,
		Args: cobra.MaximumNArgs(1),
		RunE: a.runDoctor,
	}
	cmd.Flags().Bool("fix", false, "write the recommended settings, with a diff preview and backups")
	cmd.Flags().Bool("ci", false, "exit 1 when any setting is missing, weak, wrong or unreadable at or above the policy severity")
	cmd.Flags().Bool("user", false, "also report user-level configuration files")
	return cmd
}

func (a *App) runDoctor(cmd *cobra.Command, args []string) error {
	fix, err := cmd.Flags().GetBool("fix")
	if err != nil {
		return Usagef("--fix: %v", err)
	}
	ci, err := cmd.Flags().GetBool("ci")
	if err != nil {
		return Usagef("--ci: %v", err)
	}
	userScope, err := cmd.Flags().GetBool("user")
	if err != nil {
		return Usagef("--user: %v", err)
	}
	if fix && ci {
		return Usagef("--fix and --ci cannot be combined: --ci reports what is wrong so a job fails, and a job that repairs its own checkout hides the problem instead of fixing it")
	}

	root := "."
	if len(args) == 1 {
		root = args[0]
	}
	info, err := os.Stat(root)
	if err != nil {
		return Usagef("%v", err)
	}
	if !info.IsDir() {
		return Usagef("%s is not a directory: doctor reads the configuration of a repository, not one file", root)
	}

	opts, settings, err := a.doctorOptions(fix)
	if err != nil {
		return err
	}

	ctx := cmd.Context()
	managers, notes, err := doctor.Detect(ctx, root, doctor.DetectOptions{RunBinaries: !a.Opts.Offline})
	if err != nil {
		return Usagef("%v", err)
	}
	if userScope {
		found, userNotes := userManagers(managers)
		managers = append(managers, found...)
		notes = append(notes, userNotes...)
	}
	if len(managers) == 0 {
		notes = append(notes, fmt.Sprintf("no package manager found under %s: doctor looks for a lockfile, a manifest or a configuration file of one", root))
	}

	card, err := doctor.Evaluate(root, managers, opts)
	if err != nil {
		return fmt.Errorf("evaluate the hardening settings: %w", err)
	}
	card.Notes = append(notes, card.Notes...)
	return a.writeScorecard(card, settings, ci)
}

// writeScorecard renders the scorecard and returns the exit code as an error, the
// way the other commands do.
//
// Without --ci the code is 0 whatever the scorecard says: somebody asked what their
// settings are and has been told, and a command that failed for answering would be
// one people stop running. With --ci the level the policy sets is what a job fails
// on. A file that could not be read follows on_data_unavailable like everywhere
// else, because a scorecard that covers less than it was asked to is a partial
// answer rather than a pass.
func (a *App) writeScorecard(card *doctor.Scorecard, settings policy.DoctorSettings, ci bool) error {
	writer, err := report.NewDoctor(a.Opts.Format, report.Options{Color: a.Opts.Color, Width: a.Opts.Width})
	if err != nil {
		return Usagef("%v: doctor writes human, json or markdown; sarif annotates a lockfile line, which a configuration file does not have", err)
	}
	pol, policyPath, err := a.loadPolicyOrDefault()
	if err != nil {
		return err
	}
	pol, cooldown := a.applyCooldownOverride(pol)

	// Without --ci nothing fails, and the document says so in the field a script
	// reads for it. --fail-on is not what gates a scorecard: the policy's doctor
	// section is, and reporting the wrong one would tell a script the run was gated
	// by something it was not.
	failOn := model.LevelOff
	gate := "never"
	if ci {
		failOn = settings.CIMinSeverity
		gate = settings.CIMinSeverity.String()
	}
	doc := report.BuildDoctor(card, report.CurrentTool(), report.Policy{
		Path:     policyPath,
		Cooldown: cooldown,
		FailOn:   gate,
	}, failOn)
	if doc.Summary.ExitCode == ExitOK && unreadableFails(pol, card) {
		doc.SetExitCode(ExitUnavailable)
	}
	if err := writer.WriteDoctor(a.Stdout, doc); err != nil {
		return fmt.Errorf("write the scorecard: %w", err)
	}
	if doc.Summary.ExitCode != ExitOK {
		return Exit(doc.Summary.ExitCode, nil)
	}
	return nil
}

// unreadableFails reports whether a file the run could not read should make the
// exit code 3. It is the policy's own answer for a data source that could not be
// consulted, read from the top-level setting: a configuration file belongs to a
// package manager rather than to an ecosystem's registry, so there is no override
// to apply.
func unreadableFails(pol *policy.Policy, card *doctor.Scorecard) bool {
	incomplete := card.Counts()[doctor.StatusUnreadable] > 0 || len(card.Failed) > 0
	return incomplete && pol.Effective("").OnDataUnavailable == policy.OnDataUnavailableFail
}

// doctorOptions turns the policy and the flags into what a run works under. The
// wait it recommends is the project's own cooldown, per ecosystem, so a repository
// that waits three days for npm and seven for crates.io is told to configure each
// where it belongs.
func (a *App) doctorOptions(fix bool) (doctor.Options, policy.DoctorSettings, error) {
	pol, _, err := a.loadPolicyOrDefault()
	if err != nil {
		return doctor.Options{}, policy.DoctorSettings{}, err
	}
	pol, _ = a.applyCooldownOverride(pol)
	if err := pol.ValidateDoctorRules(doctorRuleNames()); err != nil {
		return doctor.Options{}, policy.DoctorSettings{}, Usagef("%v", err)
	}
	now, err := runClock(os.Getenv(nowEnv))
	if err != nil {
		return doctor.Options{}, policy.DoctorSettings{}, err
	}
	if now.IsZero() {
		now = time.Now()
	}
	settings := pol.EffectiveDoctor()

	base := policy.DefaultCooldown
	if pol != nil && pol.Cooldown != 0 {
		base = time.Duration(pol.Cooldown)
	}
	cooldowns := make(map[model.Ecosystem]time.Duration, len(model.Ecosystems()))
	for _, eco := range model.Ecosystems() {
		cooldowns[eco] = pol.Effective(eco).Cooldown
	}
	return doctor.Options{
		Params: doctor.Params{
			Cooldown:      base,
			Now:           now,
			PinExceptions: settings.PinExceptions,
		},
		Cooldowns: cooldowns,
		Levels:    settings.Levels,
		Fix:       fix,
		// A file is always copied before it is changed. A tool that edits somebody's
		// configuration with no way back is not one people run twice.
		Backup: fix,
	}, settings, nil
}

// doctorRuleNames are the rule names a policy file may name, for the error that
// lists the closest ones when it names something else.
func doctorRuleNames() []string {
	rules := doctor.Rules()
	names := make([]string, 0, len(rules))
	for _, r := range rules {
		names = append(names, r.Name)
	}
	sort.Strings(names)
	return names
}

// userManagers are the machine's own configuration files, which --user adds to the
// scorecard. They are reported and never written: a run inside one repository has
// no business changing what every other project on the computer installs with.
//
// Only the managers the repository already uses are looked at, because a scorecard
// that reported the pip configuration of a machine to a project that has no Python
// in it would be noise, and because the point of the flag is the case where a
// setting is missing from the repository and present on the machine.
func userManagers(project []doctor.Manager) ([]doctor.Manager, []string) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, []string{fmt.Sprintf("--user: the home directory could not be found: %v", err)}
	}
	config, err := os.UserConfigDir()
	if err != nil {
		config = filepath.Join(home, ".config")
	}
	wanted := map[doctor.ManagerID]bool{}
	for i := range project {
		wanted[project[i].ID] = true
	}

	var out []doctor.Manager
	for _, candidate := range userConfigFiles(home, config) {
		if !wanted[candidate.id] {
			continue
		}
		if _, err := os.Stat(filepath.Join(candidate.base, filepath.FromSlash(candidate.file))); err != nil {
			continue
		}
		out = append(out, doctor.Manager{
			ID: candidate.id,
			// The header names the directory, because a scorecard that printed
			// ".npmrc" for a file of the home directory beside ".npmrc" for a file
			// of the repository would be two lines nobody can tell apart.
			Root:     filepath.ToSlash(candidate.base),
			Base:     candidate.base,
			Evidence: []string{candidate.file + " in " + candidate.what},
			Files:    []string{candidate.file},
		})
	}
	return out, nil
}

// userConfig is one place a package manager keeps the settings of the person
// rather than of the project.
type userConfig struct {
	id   doctor.ManagerID
	base string
	file string
	what string
}

// userConfigFiles are the user level files doctor knows how to read. Windows keeps
// them under the roaming application data directory, which os.UserConfigDir
// returns, and the others under the home directory or XDG's configuration
// directory. A file that is not there is simply not reported.
func userConfigFiles(home, config string) []userConfig {
	// Only the managers whose user level file has the same name as the file the
	// rules read. pnpm keeps its own settings in a file called rc and Poetry in one
	// called config.toml, and a rule that went looking for pnpm-workspace.yaml or
	// poetry.toml in those directories would report a setting missing that is
	// written a few bytes away. Reporting nothing is better than reporting the
	// wrong file, and the two are listed here so the next person knows why they
	// are absent.
	files := []userConfig{
		{doctor.NPM, home, ".npmrc", "the home directory"},
		{doctor.Yarn, home, ".yarnrc.yml", "the home directory"},
	}
	if runtime.GOOS == "windows" {
		files = append(files, userConfig{doctor.Pip, filepath.Join(config, "pip"), "pip.ini", "the pip configuration directory"})
	} else {
		files = append(files, userConfig{doctor.Pip, filepath.Join(config, "pip"), "pip.conf", "the pip configuration directory"})
	}
	return files
}
