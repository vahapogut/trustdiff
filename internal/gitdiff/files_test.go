package gitdiff

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// fixture reads one of the committed lockfiles under testdata.
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read the fixture %s: %v", name, err)
	}
	return data
}

// lockedRepo commits a real lockfile, then a change that edits it and adds a
// second one, which is the shape the diff command meets.
func lockedRepo(t *testing.T) (repo *testRepo, base string, locked []byte) {
	t.Helper()
	repo = newTestRepo(t)
	locked = fixture(t, "ripgrep-Cargo.lock")
	repo.writeBytes("Cargo.lock", locked)
	repo.write("README.md", "# demo\n")
	base = repo.commit("lock the dependencies")

	repo.writeBytes("Cargo.lock", append(slices.Clone(locked), []byte("\n# edited\n")...))
	repo.write("package-lock.json", "{\"lockfileVersion\": 3}\n")
	repo.commit("update the lock")
	return repo, base, locked
}

func TestFileAt(t *testing.T) {
	repo, base, locked := lockedRepo(t)
	r := repo.open(t)

	t.Run("returns the bytes the revision holds", func(t *testing.T) {
		got, err := r.FileAt(t.Context(), base, "Cargo.lock")
		if err != nil {
			t.Fatalf("FileAt: %v", err)
		}
		if !bytes.Equal(got, locked) {
			t.Errorf("FileAt returned %d bytes, want the %d committed (git must not convert line endings)", len(got), len(locked))
		}
	})

	t.Run("accepts a path on this machine", func(t *testing.T) {
		got, err := r.FileAt(t.Context(), base, r.Abs("Cargo.lock"))
		if err != nil {
			t.Fatalf("FileAt: %v", err)
		}
		if !bytes.Equal(got, locked) {
			t.Errorf("FileAt returned %d bytes, want the %d committed", len(got), len(locked))
		}
	})

	tests := []struct {
		name       string
		sha        string
		path       string
		wantErrIs  error
		wantErrHas []string
	}{
		{
			name:      "a lockfile the change adds",
			sha:       base,
			path:      "package-lock.json",
			wantErrIs: ErrNotAtRev,
		},
		{
			name:      "a path no revision ever had",
			sha:       base,
			path:      "crates/inner/Cargo.lock",
			wantErrIs: ErrNotAtRev,
		},
		{
			name:      "a ref instead of an object name",
			sha:       "HEAD",
			path:      "Cargo.lock",
			wantErrIs: ErrBadRevision,
		},
		{
			name:      "an abbreviated object name",
			sha:       base[:12],
			path:      "Cargo.lock",
			wantErrIs: ErrBadRevision,
		},
		{
			name:       "a path outside the repository",
			sha:        base,
			path:       "../elsewhere/Cargo.lock",
			wantErrHas: []string{"outside the repository"},
		},
		{
			name:       "no path at all",
			sha:        base,
			path:       ".",
			wantErrHas: []string{"names no file"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := r.FileAt(t.Context(), tt.sha, tt.path)
			if err == nil {
				t.Fatalf("FileAt(%q, %q) returned %d bytes, want an error", tt.sha, tt.path, len(got))
			}
			if tt.wantErrIs != nil && !errors.Is(err, tt.wantErrIs) {
				t.Errorf("FileAt(%q, %q) error = %v, want %v", tt.sha, tt.path, err, tt.wantErrIs)
			}
			for _, want := range tt.wantErrHas {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("FileAt(%q, %q) error = %v, want it to say %q", tt.sha, tt.path, err, want)
				}
			}
		})
	}
}

func TestChangedFiles(t *testing.T) {
	repo := newTestRepo(t)
	repo.write("Cargo.lock", "version = 3\n")
	repo.write("README.md", "# demo\n")
	base := repo.commit("lock the dependencies")

	// Committed on the branch, then the three states a working tree can be in:
	// edited, staged and deleted. The untracked file is the one git cannot
	// compare and this package documents as invisible.
	repo.write("src/main.rs", "fn main() {}\n")
	repo.commit("call the dependency")
	repo.write("Cargo.lock", "version = 4\n")
	repo.write("package-lock.json", "{\"lockfileVersion\": 3}\n")
	repo.run("add", "package-lock.json")
	repo.remove("README.md")
	repo.write("notes.txt", "not added\n")

	got, err := repo.open(t).ChangedFiles(t.Context(), base)
	if err != nil {
		t.Fatalf("ChangedFiles: %v", err)
	}
	slices.Sort(got)
	want := []string{"Cargo.lock", "README.md", "package-lock.json", "src/main.rs"}
	if !slices.Equal(got, want) {
		t.Errorf("ChangedFiles = %q, want %q", got, want)
	}
}

func TestChangedFilesRejectsARef(t *testing.T) {
	repo := newTestRepo(t)
	repo.write("Cargo.lock", "version = 3\n")
	repo.commit("lock the dependencies")

	if _, err := repo.open(t).ChangedFiles(t.Context(), "HEAD~1"); !errors.Is(err, ErrBadRevision) {
		t.Fatalf("ChangedFiles(\"HEAD~1\") error = %v, want ErrBadRevision", err)
	}
}

func TestLockfiles(t *testing.T) {
	repo := newTestRepo(t)
	repo.write(".gitignore", "node_modules/\n")
	repo.write("README.md", "# demo\n")
	repo.write("Cargo.lock", "version = 3\n")
	repo.write("crates/inner/package-lock.json", "{\"lockfileVersion\": 3}\n")
	repo.write("Cargo.toml", "[package]\n")
	// The copy an install left behind: git ignores it, so an audit never sees it.
	repo.write("node_modules/left-pad/package-lock.json", "{\"lockfileVersion\": 3}\n")
	repo.commit("lock the dependencies")

	got, err := repo.open(t).Lockfiles(t.Context())
	if err != nil {
		t.Fatalf("Lockfiles: %v", err)
	}
	// git lists tracked files in path order.
	want := []string{"Cargo.lock", "crates/inner/package-lock.json"}
	if !slices.Equal(got, want) {
		t.Errorf("Lockfiles = %q, want %q", got, want)
	}
}

// A lockfile that was written and never added is invisible to a comparison
// against a revision, so it has to be findable another way.
func TestUntrackedLockfiles(t *testing.T) {
	repo := newTestRepo(t)
	repo.write(".gitignore", "node_modules/\n")
	repo.write("Cargo.lock", "version = 3\n")
	repo.commit("lock the dependencies")
	repo.write("package-lock.json", "{\"lockfileVersion\": 3}\n")
	repo.write("notes.txt", "not a lockfile\n")
	// Ignored, the way an install's own copy is: an audit never looks at it.
	repo.write("node_modules/left-pad/package-lock.json", "{\"lockfileVersion\": 3}\n")
	// Staged counts as tracked, so it is compared and does not belong here.
	repo.write("crates/inner/Cargo.lock", "version = 3\n")
	repo.run("add", "crates/inner/Cargo.lock")

	got, err := repo.open(t).UntrackedLockfiles(t.Context())
	if err != nil {
		t.Fatalf("UntrackedLockfiles: %v", err)
	}
	want := []string{"package-lock.json"}
	if !slices.Equal(got, want) {
		t.Errorf("UntrackedLockfiles = %q, want %q", got, want)
	}
}
