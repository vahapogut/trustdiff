package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func chdir(t *testing.T, dir string) {
	t.Helper()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })
}

func TestPolicyInitAndValidate(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)

	code, stdout, stderr := run(t, "policy", "init")
	if code != ExitOK {
		t.Fatalf("policy init exit = %d, stderr = %s", code, stderr)
	}
	if !strings.Contains(stdout, ".trustdiff.yaml") {
		t.Fatalf("policy init stdout = %q, want the written path", stdout)
	}
	if _, err := os.Stat(filepath.Join(dir, ".trustdiff.yaml")); err != nil {
		t.Fatalf("policy file not written: %v", err)
	}

	code, stdout, stderr = run(t, "policy", "validate")
	if code != ExitOK || !strings.Contains(stdout, ": valid") {
		t.Fatalf("policy validate exit = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}

	code, stdout, _ = run(t, "--format", "json", "policy", "validate")
	if code != ExitOK || !strings.Contains(stdout, `"valid": true`) {
		t.Fatalf("policy validate json exit = %d, stdout = %q", code, stdout)
	}

	// A second init must not overwrite the reviewed file.
	code, _, stderr = run(t, "policy", "init")
	if code != ExitUsage || !strings.Contains(stderr, "already exists") {
		t.Fatalf("second policy init exit = %d, stderr = %q", code, stderr)
	}

	// --output writes elsewhere, and validate honors --policy.
	other := filepath.Join(dir, "policies", "team.yaml")
	code, _, stderr = run(t, "policy", "init", "--output", other)
	if code != ExitOK {
		t.Fatalf("policy init --output exit = %d, stderr = %q", code, stderr)
	}
	code, stdout, _ = run(t, "--policy", other, "policy", "validate")
	if code != ExitOK || !strings.Contains(stdout, other) {
		t.Fatalf("policy validate --policy exit = %d, stdout = %q", code, stdout)
	}
}

func TestPolicyValidateReportsProblems(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)

	code, _, stderr := run(t, "policy", "validate")
	if code != ExitUsage || !strings.Contains(stderr, "no policy file found") {
		t.Fatalf("validate without a file exit = %d, stderr = %q", code, stderr)
	}

	bad := filepath.Join(dir, ".trustdiff.yaml")
	if err := os.WriteFile(bad, []byte("version: 1\nchecks:\n  bogus: warn\n  vulnerability: { min_severity: extreme }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := run(t, "policy", "validate")
	if code != ExitUsage {
		t.Fatalf("validate of an invalid file exit = %d, want 2", code)
	}
	for _, want := range []string{`unknown check "bogus"`, "min_severity must be one of"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, stderr)
		}
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty on failure", stdout)
	}
}
