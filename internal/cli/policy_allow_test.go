package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPolicyAllowPreviewWriteAndBackup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	original := []byte("# reviewed project\nversion: 1\n")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(nowEnv, "2026-09-29T12:00:00Z")
	args := []string{"policy", "allow", "TD014", "npm:vendored@1.2.3", "--policy", path, "--reason", "verified source", "--expires", "2026-10-31"}
	var out, stderr bytes.Buffer
	if code := Main(args, &out, &stderr); code != 0 {
		t.Fatalf("preview exit %d: %s", code, &stderr)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, original) {
		t.Fatal("preview changed policy")
	}
	if code := Main(append(args, "--write"), &out, &stderr); code != 0 {
		t.Fatalf("write exit %d: %s", code, &stderr)
	}
	backups, err := filepath.Glob(path + ".trustdiff-backup-*")
	if err != nil || len(backups) != 1 {
		t.Fatalf("missing backup: %v", err)
	}
	got, err = os.ReadFile(backups[0])
	if err != nil || !bytes.Equal(got, original) {
		t.Fatal("bad backup")
	}
	if code := Main(append(args, "--write"), &out, &stderr); code != 0 {
		t.Fatalf("idempotent exit %d: %s", code, &stderr)
	}
}

func TestPolicyAllowDefaultClockRejectsPastExpiryAndDatesBackup(t *testing.T) {
	t.Setenv(nowEnv, "")
	path := filepath.Join(t.TempDir(), "policy.yaml")
	original := []byte("version: 1\n")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"policy", "allow", "TD014", "npm:vendored@1.2.3", "--policy", path, "--reason", "verified source", "--write", "--expires"}
	var out, stderr bytes.Buffer
	if code := Main(append(args, "2000-01-01"), &out, &stderr); code != ExitUsage || !strings.Contains(stderr.String(), "already past") {
		t.Fatalf("default clock accepted expired exception: exit %d, stderr %s", code, &stderr)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, original) {
		t.Fatal("expired exception changed the policy")
	}
	now := time.Now().UTC()
	expires := now.AddDate(1, 0, 0).Format("2006-01-02")
	if code := Main(append(args, expires), &out, &stderr); code != ExitOK {
		t.Fatalf("future exception failed: exit %d, stderr %s", code, &stderr)
	}
	backups, err := filepath.Glob(path + ".trustdiff-backup-*")
	if err != nil || len(backups) != 1 {
		t.Fatalf("backups %v, error %v", backups, err)
	}
	stamp := strings.TrimPrefix(backups[0], path+".trustdiff-backup-")
	created, err := time.Parse("20060102T150405Z", stamp)
	if err != nil || created.Before(now.Add(-time.Second)) || created.After(time.Now().UTC()) {
		t.Fatalf("backup did not use the wall clock: %q, %v", stamp, err)
	}
}
