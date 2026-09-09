package textdiff

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// demoClock is the pinned clock the recorded demo runs on, so a backup name in a
// golden file and a backup name here are produced the same way.
var demoClock = time.Date(2026, 9, 9, 19, 30, 0, 0, time.UTC)

func TestWriteCreatesAFileWithTheGivenMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trustdiff.yml")
	if err := Write(path, []byte("checks: all\n"), 0o644); err != nil {
		t.Fatalf("Write() on a new file: %v", err)
	}
	if got := read(t, path); got != "checks: all\n" {
		t.Errorf("the new file holds %q, want %q", got, "checks: all\n")
	}
	assertPerm(t, path, 0o644)
}

func TestWriteReplacesTheContentAndKeepsTheExistingMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "go.sum")
	create(t, path, "old\n", 0o600)
	// The mode argument is deliberately wider than the file's own mode: an edit to
	// a file somebody made private must not publish it.
	if err := Write(path, []byte("new\n"), 0o666); err != nil {
		t.Fatalf("Write() over an existing file: %v", err)
	}
	if got := read(t, path); got != "new\n" {
		t.Errorf("the replaced file holds %q, want %q", got, "new\n")
	}
	assertPerm(t, path, 0o600)
}

func TestWriteLeavesNoTemporaryFileBehind(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "package-lock.json")
	if err := Write(path, []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("Write(): %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading the directory back: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "package-lock.json" {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("the directory holds %v, want only package-lock.json", names)
	}
}

func TestWriteRefusesADirectoryAndLeavesItAlone(t *testing.T) {
	dir := t.TempDir()
	// A directory standing where the file would be: the edit must fail rather than
	// do anything at all to what is inside it.
	path := filepath.Join(dir, "Cargo.lock")
	if err := os.Mkdir(path, 0o750); err != nil {
		t.Fatalf("creating the directory: %v", err)
	}
	inside := filepath.Join(path, "kept.txt")
	create(t, inside, "untouched\n", 0o644)

	err := Write(path, []byte("clobbered\n"), 0o644)
	if !errors.Is(err, ErrNotRegular) {
		t.Fatalf("Write() on a directory returned %v, want ErrNotRegular", err)
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("the error %q does not name the path %q", err, path)
	}
	if got := read(t, inside); got != "untouched\n" {
		t.Errorf("the file inside the directory now holds %q, want %q", got, "untouched\n")
	}
}

func TestWriteLeavesTheOriginalWhenItCannotWrite(t *testing.T) {
	dir := t.TempDir()
	original := filepath.Join(dir, "uv.lock")
	create(t, original, "original\n", 0o644)

	// A path under a plain file: nothing can be created in it, so Write fails at
	// the temporary file and the file that is standing in for the directory must
	// come through the failure unchanged.
	path := filepath.Join(original, "nested.lock")
	if err := Write(path, []byte("clobbered\n"), 0o644); err == nil {
		t.Fatal("Write() under a plain file succeeded, want a failure")
	}
	if got := read(t, original); got != "original\n" {
		t.Errorf("the original holds %q after the failed write, want %q", got, "original\n")
	}
}

func TestWriteRefusesASymbolicLink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "secret.txt")
	create(t, target, "secret\n", 0o600)
	link := filepath.Join(dir, "pnpm-lock.yaml")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("this machine does not let the test create a symbolic link: %v", err)
	}

	err := Write(link, []byte("clobbered\n"), 0o644)
	if !errors.Is(err, ErrNotRegular) {
		t.Fatalf("Write() through a symbolic link returned %v, want ErrNotRegular", err)
	}
	if got := read(t, target); got != "secret\n" {
		t.Errorf("the link target holds %q, want %q: Write followed the link", got, "secret\n")
	}
}

func TestBackupCopiesTheContentAndTheMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "go.mod")
	create(t, path, "module example.com/m\n", 0o640)

	backup, err := Backup(path, demoClock)
	if err != nil {
		t.Fatalf("Backup(): %v", err)
	}
	want := path + ".trustdiff-backup-20260909T193000Z"
	if backup != want {
		t.Errorf("Backup() returned %q, want %q", backup, want)
	}
	if got := read(t, backup); got != "module example.com/m\n" {
		t.Errorf("the backup holds %q, want %q", got, "module example.com/m\n")
	}
	if got := read(t, path); got != "module example.com/m\n" {
		t.Errorf("the original holds %q after the backup, want it unchanged", got)
	}
	assertPerm(t, backup, 0o640)
}

func TestBackupNamesTheFileWithACharacterWindowsAllows(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "requirements.txt")
	create(t, path, "flask==3.0.0\n", 0o644)

	backup, err := Backup(path, demoClock)
	if err != nil {
		t.Fatalf("Backup(): %v", err)
	}
	// A colon in a Windows path opens an alternate data stream instead of naming a
	// file, so the timestamp must not carry one. The volume letter's own colon is
	// not part of the name, so only the base name is checked.
	if base := filepath.Base(backup); strings.ContainsAny(base, `:*?"<>|`) {
		t.Errorf("the backup name %q holds a character Windows does not allow in a file name", base)
	}
	if _, err := os.Lstat(backup); err != nil {
		t.Errorf("the backup is not on disk under the name Backup returned: %v", err)
	}
}

func TestBackupUsesTheClockInUTC(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "poetry.lock")
	create(t, path, "content\n", 0o644)

	// The same instant as demoClock, seen from a zone three hours ahead: two
	// machines in two zones have to name the same backup the same way.
	east := time.FixedZone("UTC+3", 3*60*60)
	backup, err := Backup(path, demoClock.In(east))
	if err != nil {
		t.Fatalf("Backup(): %v", err)
	}
	if want := path + ".trustdiff-backup-20260909T193000Z"; backup != want {
		t.Errorf("Backup() returned %q, want %q", backup, want)
	}
}

func TestBackupRefusesToOverwriteAnExistingBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Gemfile.lock")
	create(t, path, "before the edit\n", 0o644)

	backup, err := Backup(path, demoClock)
	if err != nil {
		t.Fatalf("the first Backup(): %v", err)
	}
	// The edit trustdiff would have made, followed by a second run on the same
	// clock: the copy of the original must survive.
	if err := Write(path, []byte("after the edit\n"), 0o644); err != nil {
		t.Fatalf("Write(): %v", err)
	}
	again, err := Backup(path, demoClock)
	if !errors.Is(err, ErrBackupExists) {
		t.Fatalf("the second Backup() returned (%q, %v), want ErrBackupExists", again, err)
	}
	if again != "" {
		t.Errorf("the refused Backup() returned the path %q, want an empty string", again)
	}
	if !strings.Contains(err.Error(), backup) {
		t.Errorf("the error %q does not name the backup %q", err, backup)
	}
	if got := read(t, backup); got != "before the edit\n" {
		t.Errorf("the backup now holds %q, want the content from before the edit", got)
	}
}

func TestBackupRefusesADirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vendor")
	if err := os.Mkdir(path, 0o750); err != nil {
		t.Fatalf("creating the directory: %v", err)
	}
	if _, err := Backup(path, demoClock); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("Backup() on a directory returned %v, want ErrNotRegular", err)
	}
}

func TestBackupRefusesASymbolicLink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "secret.txt")
	create(t, target, "secret\n", 0o600)
	link := filepath.Join(dir, "yarn.lock")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("this machine does not let the test create a symbolic link: %v", err)
	}
	if _, err := Backup(link, demoClock); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("Backup() through a symbolic link returned %v, want ErrNotRegular", err)
	}
}

func TestBackupReportsAMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.lock")
	_, err := Backup(path, demoClock)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Backup() on a missing file returned %v, want os.ErrNotExist", err)
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("the error %q does not name the path %q", err, path)
	}
}

// create puts a file on disk for a test to work on.
func create(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatalf("creating %s: %v", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("setting the mode of %s: %v", path, err)
	}
}

// read returns the content of a file the test expects to exist.
func read(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return string(data)
}

// assertPerm checks the permission bits, on the systems that have them. Windows
// keeps only a read-only flag, so os.Chmod there cannot reproduce a Unix mode and
// an assertion about one would fail for a reason that says nothing about this
// package.
func assertPerm(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("inspecting %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Errorf("%s has mode %v, want %v", path, got, want)
	}
}
