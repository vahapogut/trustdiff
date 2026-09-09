package policy

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// noEnv is a getenv with nothing set; noConfig a user config dir that cannot be found.
func noEnv(string) string { return "" }

func noConfig() (string, error) { return "", errors.New("no user config dir") }

// writePolicy creates a minimal policy file at path, making its directory first.
func writePolicy(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("version: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestFindWalksUpward(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "a", "b", "c")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(root, "a", FileName)
	writePolicy(t, want)

	got, found, err := find(nested, noEnv, noConfig)
	if err != nil || !found || got != want {
		t.Fatalf("find(nested) = %q, %v, %v; want %q", got, found, err, want)
	}
	got, found, err = find(filepath.Join(root, "a"), noEnv, noConfig)
	if err != nil || !found || got != want {
		t.Fatalf("find(a) = %q, %v, %v; want %q", got, found, err, want)
	}
	if _, found, err := find(root, noEnv, noConfig); err != nil || found {
		t.Fatalf("find(root) found = %v, err = %v; want nothing", found, err)
	}
}

func TestFindFallsBackToUserConfig(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "config")
	want := filepath.Join(configDir, "trustdiff", "policy.yaml")
	writePolicy(t, want)
	userConfig := func() (string, error) { return configDir, nil }

	project := filepath.Join(root, "project")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	got, found, err := find(project, noEnv, userConfig)
	if err != nil || !found || got != want {
		t.Fatalf("find = %q, %v, %v; want the user config fallback %q", got, found, err, want)
	}

	// A project file wins over the fallback.
	local := filepath.Join(project, FileName)
	writePolicy(t, local)
	got, _, _ = find(project, noEnv, userConfig)
	if got != local {
		t.Fatalf("find = %q, want the project file %q", got, local)
	}
}

// The brief names $XDG_CONFIG_HOME/trustdiff/policy.yaml as the user-level fallback.
// os.UserConfigDir reads the variable on Linux only, so it is honored here directly,
// on every platform, and it wins over the platform directory.
func TestFindHonorsXDGConfigHome(t *testing.T) {
	root := t.TempDir()
	xdg := filepath.Join(root, "xdg")
	platform := filepath.Join(root, "platform")
	fromXDG := filepath.Join(xdg, "trustdiff", "policy.yaml")
	fromPlatform := filepath.Join(platform, "trustdiff", "policy.yaml")
	writePolicy(t, fromXDG)
	writePolicy(t, fromPlatform)
	project := filepath.Join(root, "project")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	env := func(vars map[string]string) func(string) string {
		return func(k string) string { return vars[k] }
	}
	platformDir := func() (string, error) { return platform, nil }

	got, found, err := find(project, env(map[string]string{"XDG_CONFIG_HOME": xdg}), platformDir)
	if err != nil || !found || got != fromXDG {
		t.Fatalf("find with XDG_CONFIG_HOME = %q, %v, %v; want %q", got, found, err, fromXDG)
	}
	// XDG_CONFIG_HOME does not need the platform directory at all.
	got, found, err = find(project, env(map[string]string{"XDG_CONFIG_HOME": xdg}), noConfig)
	if err != nil || !found || got != fromXDG {
		t.Fatalf("find with XDG_CONFIG_HOME and no platform dir = %q, %v, %v; want %q", got, found, err, fromXDG)
	}
	// An unset or relative XDG_CONFIG_HOME falls back to the platform directory.
	for name, vars := range map[string]map[string]string{
		"unset":    {},
		"empty":    {"XDG_CONFIG_HOME": ""},
		"relative": {"XDG_CONFIG_HOME": "config"},
	} {
		got, found, err = find(project, env(vars), platformDir)
		if err != nil || !found || got != fromPlatform {
			t.Fatalf("find with XDG_CONFIG_HOME %s = %q, %v, %v; want %q", name, got, found, err, fromPlatform)
		}
	}
}

func TestFindIgnoresDirectoriesNamedLikeTheFile(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, FileName), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, found, err := find(root, noEnv, noConfig); err != nil || found {
		t.Fatalf("a directory named %s was treated as a policy file (found=%v, err=%v)", FileName, found, err)
	}
}
