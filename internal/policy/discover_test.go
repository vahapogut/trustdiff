package policy

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestFindWalksUpward(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "a", "b", "c")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(root, "a", FileName)
	if err := os.WriteFile(want, []byte("version: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	noConfig := func() (string, error) { return "", errors.New("no user config dir") }

	got, found, err := find(nested, noConfig)
	if err != nil || !found || got != want {
		t.Fatalf("find(nested) = %q, %v, %v; want %q", got, found, err, want)
	}
	got, found, err = find(filepath.Join(root, "a"), noConfig)
	if err != nil || !found || got != want {
		t.Fatalf("find(a) = %q, %v, %v; want %q", got, found, err, want)
	}
	if _, found, err := find(root, noConfig); err != nil || found {
		t.Fatalf("find(root) found = %v, err = %v; want nothing", found, err)
	}
}

func TestFindFallsBackToUserConfig(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "config")
	want := filepath.Join(configDir, "trustdiff", "policy.yaml")
	if err := os.MkdirAll(filepath.Dir(want), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(want, []byte("version: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	userConfig := func() (string, error) { return configDir, nil }

	project := filepath.Join(root, "project")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	got, found, err := find(project, userConfig)
	if err != nil || !found || got != want {
		t.Fatalf("find = %q, %v, %v; want the user config fallback %q", got, found, err, want)
	}

	// A project file wins over the fallback.
	local := filepath.Join(project, FileName)
	if err := os.WriteFile(local, []byte("version: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, _, _ = find(project, userConfig)
	if got != local {
		t.Fatalf("find = %q, want the project file %q", got, local)
	}
}

func TestFindIgnoresDirectoriesNamedLikeTheFile(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, FileName), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, found, err := find(root, func() (string, error) { return "", errors.New("none") }); err != nil || found {
		t.Fatalf("a directory named %s was treated as a policy file (found=%v, err=%v)", FileName, found, err)
	}
}
