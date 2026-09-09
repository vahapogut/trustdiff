package gitdiff

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vahapogut/trustdiff/internal/lockfile"
)

// The tests need names a parser recognizes without importing a format package,
// which would drag a parser and its fixtures into this package's tests. These
// two answer for the names Lockfiles looks for; nothing here ever parses.
func init() {
	lockfile.Register(namedParser("Cargo.lock"))
	lockfile.Register(namedParser("package-lock.json"))
}

type namedParser string

func (p namedParser) Name() string { return string(p) }

func (p namedParser) Detect(base string) bool { return strings.EqualFold(base, string(p)) }

func (p namedParser) Parse(path string, _ io.Reader) (*lockfile.Lockfile, error) {
	return &lockfile.Lockfile{Path: path, Format: string(p)}, nil
}

// testRepo is a repository built for one test under t.TempDir().
type testRepo struct {
	t   *testing.T
	git string
	dir string
}

// newTestRepo makes an empty repository, isolated from the machine's git
// configuration: a global or system core.autocrlf would otherwise rewrite what
// the tests commit, and Git for Windows ships one. The two configuration files
// are named inside the temporary directory and never created, which git reads as
// empty. The package under test inherits the environment of the test process, so
// this isolates it too.
func newTestRepo(t *testing.T) *testRepo {
	t.Helper()
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is not on PATH")
	}
	dir := t.TempDir()
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(dir, "absent-global-gitconfig"))
	t.Setenv("GIT_CONFIG_SYSTEM", filepath.Join(dir, "absent-system-gitconfig"))
	r := &testRepo{t: t, git: git, dir: dir}
	r.run("init", "--quiet")
	return r
}

// run executes one git command in the repository and fails the test if it does
// not succeed.
func (r *testRepo) run(args ...string) string {
	r.t.Helper()
	cmd := exec.CommandContext(r.t.Context(), r.git, args...)
	cmd.Dir = r.dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=trustdiff tests",
		"GIT_AUTHOR_EMAIL=tests@trustdiff.invalid",
		"GIT_COMMITTER_NAME=trustdiff tests",
		"GIT_COMMITTER_EMAIL=tests@trustdiff.invalid",
		"GIT_AUTHOR_DATE=2026-01-02T03:04:05+00:00",
		"GIT_COMMITTER_DATE=2026-01-02T03:04:05+00:00",
		"LC_ALL=C",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		r.t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// write puts content at a repository-relative path, creating directories.
func (r *testRepo) write(rel, content string) {
	r.t.Helper()
	r.writeBytes(rel, []byte(content))
}

func (r *testRepo) writeBytes(rel string, content []byte) {
	r.t.Helper()
	path := filepath.Join(r.dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		r.t.Fatalf("create the directory of %s: %v", rel, err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		r.t.Fatalf("write %s: %v", rel, err)
	}
}

// remove deletes a path from the working tree without telling git.
func (r *testRepo) remove(rel string) {
	r.t.Helper()
	if err := os.Remove(filepath.Join(r.dir, filepath.FromSlash(rel))); err != nil {
		r.t.Fatalf("remove %s: %v", rel, err)
	}
}

// commit stages everything and commits it, returning the new object name.
func (r *testRepo) commit(message string) string {
	r.t.Helper()
	r.run("add", "--all")
	r.run("commit", "--quiet", "--message", message)
	return r.run("rev-parse", "HEAD")
}

// open returns the package's handle on the repository.
func (r *testRepo) open(t *testing.T) *Repo {
	t.Helper()
	repo, err := Open(t.Context(), r.dir)
	if err != nil {
		t.Fatalf("Open(%s): %v", r.dir, err)
	}
	return repo
}

// forked builds the shape a pull request has: a commit both lines share, one
// more on the line that was left, and a branch of two commits that left at the
// fork. The branch has two commits so that the merge base and HEAD~1 are
// different commits and a test can tell which one an answer came from.
type forked struct {
	*testRepo
	// fork is the commit the two lines share, and the merge base every default
	// resolution should find.
	fork string
	// mainTip is the tip of the line the fork left, where origin/main points.
	mainTip string
	// previous is the commit before the checked out one, which is what HEAD~1
	// names.
	previous string
	// head is the tip of the branch that is checked out.
	head string
}

func newForkedRepo(t *testing.T) *forked {
	t.Helper()
	r := newTestRepo(t)
	f := &forked{testRepo: r}
	r.write("Cargo.lock", "version = 3\n")
	f.fork = r.commit("lock the dependencies")
	r.write("README.md", "# demo\n")
	f.mainTip = r.commit("describe the project")
	r.run("checkout", "--quiet", "-b", "update-a-dependency", f.fork)
	r.write("Cargo.lock", "version = 4\n")
	f.previous = r.commit("update a dependency")
	r.write("src/main.rs", "fn main() {}\n")
	f.head = r.commit("call the new dependency")
	return f
}

// trackOrigin points a remote-tracking ref at a commit, which is all a clone's
// origin/main is. No test here talks to a network.
func (r *testRepo) trackOrigin(ref, sha string) {
	r.t.Helper()
	r.run("update-ref", "refs/remotes/origin/"+ref, sha)
}

// sameDir compares two paths after resolving symbolic links, because a temporary
// directory is one on macOS and git answers with the resolved path.
func sameDir(t *testing.T, got, want string) bool {
	t.Helper()
	resolve := func(p string) string {
		if r, err := filepath.EvalSymlinks(p); err == nil {
			return filepath.Clean(r)
		}
		return filepath.Clean(p)
	}
	return resolve(got) == resolve(want)
}

func TestOpen(t *testing.T) {
	t.Run("finds the root from a subdirectory", func(t *testing.T) {
		repo := newTestRepo(t)
		repo.write("crates/inner/Cargo.lock", "version = 3\n")
		repo.commit("initial")

		r, err := Open(t.Context(), filepath.Join(repo.dir, "crates", "inner"))
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if !sameDir(t, r.Root(), repo.dir) {
			t.Errorf("Root() = %q, want %q", r.Root(), repo.dir)
		}
		if got, want := r.Abs("crates/inner/Cargo.lock"), filepath.Join(r.Root(), "crates", "inner", "Cargo.lock"); got != want {
			t.Errorf("Abs() = %q, want %q", got, want)
		}
	})

	t.Run("reports a directory that is not a repository", func(t *testing.T) {
		if _, err := exec.LookPath("git"); err != nil {
			t.Skip("git is not on PATH")
		}
		_, err := Open(t.Context(), t.TempDir())
		if !errors.Is(err, ErrNotRepository) {
			t.Fatalf("Open outside a repository: err = %v, want ErrNotRepository", err)
		}
	})
}

func TestValidSHA(t *testing.T) {
	tests := []struct {
		name string
		sha  string
		want bool
	}{
		{"a full object name", strings.Repeat("a1b2", 10), true},
		{"an abbreviated one", "a1b2c3d", false},
		{"a sha-256 name", strings.Repeat("ab", 32), false},
		{"uppercase", strings.Repeat("A1B2", 10), false},
		{"a ref", "HEAD", false},
		{"an option", strings.Repeat("a", 38) + "-x", false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validSHA(tt.sha); got != tt.want {
				t.Errorf("validSHA(%q) = %v, want %v", tt.sha, got, tt.want)
			}
		})
	}
}
