package cli

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func run(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = Main(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestMainExitCodes(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{name: "version prints identity", args: []string{"version"}, wantCode: ExitOK, wantStdout: "trustdiff dev (commit none"},
		{name: "version json", args: []string{"--format", "json", "version"}, wantCode: ExitOK, wantStdout: `"version": "dev"`},
		{name: "unimplemented command exits 2", args: []string{"check", "npm:express"}, wantCode: ExitUsage, wantStderr: "check: not implemented in dev"},
		{name: "unimplemented nested command exits 2", args: []string{"cache", "status"}, wantCode: ExitUsage, wantStderr: "cache status: not implemented"},
		{name: "check requires an argument", args: []string{"check"}, wantCode: ExitUsage, wantStderr: "requires at least 1 arg"},
		{name: "unknown command", args: []string{"nope"}, wantCode: ExitUsage, wantStderr: "unknown command"},
		{name: "unknown flag", args: []string{"--bogus", "version"}, wantCode: ExitUsage, wantStderr: "unknown flag"},
		{name: "bad format", args: []string{"--format", "xml", "version"}, wantCode: ExitUsage, wantStderr: "--format must be one of human, json, sarif, markdown"},
		{name: "bad fail-on", args: []string{"--fail-on", "maybe", "version"}, wantCode: ExitUsage, wantStderr: "--fail-on must be one of block, warn, never"},
		{name: "bad jobs", args: []string{"--jobs", "0", "version"}, wantCode: ExitUsage, wantStderr: "--jobs must be at least 1"},
		{name: "verbose logs to stderr", args: []string{"-v", "version"}, wantCode: ExitOK, wantStderr: "starting"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, stderr := run(t, tt.args...)
			if code != tt.wantCode {
				t.Fatalf("exit = %d, want %d (stderr: %s)", code, tt.wantCode, stderr)
			}
			if tt.wantStdout != "" && !strings.Contains(stdout, tt.wantStdout) {
				t.Fatalf("stdout = %q, want it to contain %q", stdout, tt.wantStdout)
			}
			if tt.wantStderr != "" && !strings.Contains(stderr, tt.wantStderr) {
				t.Fatalf("stderr = %q, want it to contain %q", stderr, tt.wantStderr)
			}
			if tt.wantStderr == "" && stderr != "" {
				t.Fatalf("stderr = %q, want empty", stderr)
			}
		})
	}
}

func TestStdoutStaysCleanOnErrors(t *testing.T) {
	_, stdout, _ := run(t, "check", "npm:express")
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty: stdout is reserved for reports", stdout)
	}
}

func TestVersionJSONShape(t *testing.T) {
	_, stdout, _ := run(t, "--format", "json", "version")
	var got map[string]string
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("version --format json is not a JSON object: %v\n%s", err, stdout)
	}
	for _, key := range []string{"version", "commit", "date", "go_version", "os", "arch"} {
		if got[key] == "" {
			t.Errorf("missing %q in %v", key, got)
		}
	}
}

func TestCommandTreeMatchesTheBrief(t *testing.T) {
	want := []string{
		"baseline",
		"cache clear",
		"cache refresh",
		"cache refresh-lists",
		"cache status",
		"check",
		"diff",
		"doctor",
		"hook install",
		"hook uninstall",
		"policy init",
		"policy validate",
		"scan",
		"version",
	}
	app := &App{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}
	var got []string
	var walk func(prefix string, cmd *cobra.Command)
	walk = func(prefix string, cmd *cobra.Command) {
		for _, sub := range cmd.Commands() {
			name := strings.TrimSpace(prefix + " " + sub.Name())
			if sub.Name() == "completion" || sub.Name() == "help" {
				continue
			}
			if sub.Runnable() {
				got = append(got, name)
			}
			walk(name, sub)
		}
	}
	walk("", app.newRootCommand())
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("runnable commands = %v\nwant %v", got, want)
	}
}

func TestGlobalFlagsMatchTheBrief(t *testing.T) {
	app := &App{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}
	root := app.newRootCommand()
	for _, name := range []string{"format", "policy", "offline", "no-cache", "cooldown", "fail-on", "jobs", "no-color", "verbose"} {
		if root.PersistentFlags().Lookup(name) == nil {
			t.Errorf("missing global flag --%s", name)
		}
	}
	if root.PersistentFlags().ShorthandLookup("v") == nil {
		t.Error("missing shorthand -v")
	}
}

func TestColorEnabled(t *testing.T) {
	env := func(vars map[string]string) func(string) (string, bool) {
		return func(k string) (string, bool) { v, ok := vars[k]; return v, ok }
	}
	tests := []struct {
		name     string
		noColor  bool
		env      map[string]string
		terminal bool
		want     bool
	}{
		{name: "terminal without flags", terminal: true, want: true},
		{name: "not a terminal", terminal: false, want: false},
		{name: "flag wins", noColor: true, terminal: true, want: false},
		{name: "NO_COLOR set to empty string still disables", env: map[string]string{"NO_COLOR": ""}, terminal: true, want: false},
		{name: "NO_COLOR set to 1", env: map[string]string{"NO_COLOR": "1"}, terminal: true, want: false},
		{name: "unrelated env is ignored", env: map[string]string{"TERM": "xterm"}, terminal: true, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := colorEnabled(tt.noColor, env(tt.env), tt.terminal); got != tt.want {
				t.Fatalf("colorEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTerminalWidthFallsBackForNonTerminals(t *testing.T) {
	if got := terminalWidth(&bytes.Buffer{}, 80); got != 80 {
		t.Fatalf("terminalWidth() = %d, want fallback 80", got)
	}
}
