package gitdiff

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestResolveBase(t *testing.T) {
	tests := []struct {
		name string
		// prepare adds the refs the case needs to the forked repository.
		prepare func(f *forked)
		ref     string
		// refFrom names a ref the repository has to exist to write down.
		refFrom func(f *forked) string
		// want is the commit ResolveBase has to return, or nil when the case
		// expects an error.
		want       func(f *forked) string
		wantErrHas []string
	}{
		{
			name:    "defaults to the merge base with origin/main",
			prepare: func(f *forked) { f.trackOrigin("main", f.mainTip) },
			want:    func(f *forked) string { return f.fork },
		},
		{
			name: "falls back to the merge base with origin/HEAD",
			prepare: func(f *forked) {
				// A clone whose default branch is not called main: origin/HEAD is the
				// symbolic ref that says which one it is.
				f.trackOrigin("master", f.mainTip)
				f.run("symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/master")
			},
			want: func(f *forked) string { return f.fork },
		},
		{
			name: "falls back to HEAD~1 without a remote",
			want: func(f *forked) string { return f.previous },
		},
		{
			name: "resolves a branch",
			ref:  "update-a-dependency",
			want: func(f *forked) string { return f.head },
		},
		{
			// The tag names the tip of the line the fork left, and the base is the
			// commit the two lines share: what the branch did is what it added since
			// then, not what the other line did meanwhile.
			name:    "resolves a tag and takes the fork point",
			prepare: func(f *forked) { f.run("tag", "v1.2.0", f.mainTip) },
			ref:     "v1.2.0",
			want:    func(f *forked) string { return f.fork },
		},
		{
			// This is the shape a CI job passes: the tip of the base branch, from
			// the pull request event payload.
			name:    "reduces an object name to the fork point",
			refFrom: func(f *forked) string { return f.mainTip },
			want:    func(f *forked) string { return f.fork },
		},
		{
			// A commit on this line is its own fork point, so a base named by hand
			// in a linear history is used as it is.
			name:    "keeps an object name this line already contains",
			refFrom: func(f *forked) string { return f.previous },
			want:    func(f *forked) string { return f.previous },
		},
		{
			name:       "rejects a ref that does not exist",
			ref:        "origin/release",
			wantErrHas: []string{"origin/release"},
		},
		{
			name: "rejects a ref that names a file rather than a commit",
			// Without the ^{commit} suffix this would resolve to the blob and the
			// revision would leave the commit graph.
			ref:        "HEAD:Cargo.lock",
			wantErrHas: []string{"HEAD:Cargo.lock"},
		},
		{
			name:       "rejects a ref carrying a newline",
			ref:        "main\norigin/main",
			wantErrHas: []string{"newline"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newForkedRepo(t)
			if tt.prepare != nil {
				tt.prepare(f)
			}
			ref := tt.ref
			if tt.refFrom != nil {
				ref = tt.refFrom(f)
			}

			got, err := f.open(t).ResolveBase(t.Context(), ref)
			if tt.want == nil {
				if err == nil {
					t.Fatalf("ResolveBase(%q) = %q, want an error", ref, got)
				}
				for _, want := range tt.wantErrHas {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("ResolveBase(%q) error = %v, want it to name %q", ref, err, want)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveBase(%q): %v", ref, err)
			}
			if want := tt.want(f); got != want {
				t.Errorf("ResolveBase(%q) = %q, want %q", ref, got, want)
			}
		})
	}
}

// TestResolveBaseRejectsRefsThatLookLikeOptions is the reason this package runs
// git the way it does. The base ref arrives from a CI event payload and from the
// command line, and git has options that run a command of their own; none of
// them may be reachable through a ref.
//
// The assertion is on the argument vector rather than on what the option would
// have done if it had been read as one. "git rev-parse --verify" starts no
// upload-pack and no proxy command, and every one of these strings fails on its
// own once ^{commit} is appended, so a marker file would stay absent whether or
// not --end-of-options were passed: it would prove nothing. What has to hold is
// that the ref reaches git behind the separator.
func TestResolveBaseRejectsRefsThatLookLikeOptions(t *testing.T) {
	refs := []struct {
		name string
		ref  string
	}{
		{"an upload-pack command", "--upload-pack=touch " + filepath.Join(t.TempDir(), "pwned")},
		{"a proxy command", "-oProxyCommand=x"},
		{"an output redirection", "--output=" + filepath.Join(t.TempDir(), "written")},
		{"a ref that is only a dash", "-"},
	}
	for _, tt := range refs {
		t.Run(tt.name, func(t *testing.T) {
			f := newForkedRepo(t)
			f.trackOrigin("main", f.mainTip)

			got, err := f.open(t).ResolveBase(t.Context(), tt.ref)
			if err == nil {
				t.Fatalf("ResolveBase(%q) = %q, want an error", tt.ref, got)
			}
			if !strings.Contains(err.Error(), tt.ref) {
				t.Errorf("ResolveBase(%q) error = %v, want it to name the ref", tt.ref, err)
			}
			assertBehindEndOfOptions(t, err, tt.ref+"^{commit}")
		})
	}
}

// TestEndOfOptionsGuardsEveryRefArgument covers the other two commands a caller's
// value reaches. ChangedFiles and FileAt take a revision this package has already
// checked to be hexadecimal, so the separator is a second line of defense there;
// it is asserted so that removing it fails a test.
func TestEndOfOptionsGuardsEveryRefArgument(t *testing.T) {
	repo := newTestRepo(t)
	repo.write("Cargo.lock", "version = 3\n")
	repo.commit("lock the dependencies")
	r := repo.open(t)
	// A well-formed object name no repository holds, so git runs and fails.
	absent := strings.Repeat("a1b2", 10)

	t.Run("ChangedFiles", func(t *testing.T) {
		_, err := r.ChangedFiles(t.Context(), absent)
		if err == nil {
			t.Fatal("ChangedFiles on an absent revision returned no error")
		}
		assertBehindEndOfOptions(t, err, absent)
	})

	t.Run("FileAt", func(t *testing.T) {
		// An absent revision answers "does not exist in", which this package reads
		// as ErrNotAtRev and reports without git's own words. A canceled context
		// is a failure it passes through, so the argument vector survives.
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		_, err := r.FileAt(ctx, absent, "Cargo.lock")
		if err == nil {
			t.Fatal("FileAt with a canceled context returned no error")
		}
		assertBehindEndOfOptions(t, err, absent+":Cargo.lock")
	})
}

// assertBehindEndOfOptions checks that the failed git command carried
// --end-of-options before the argument that holds a caller's value.
func assertBehindEndOfOptions(t *testing.T, err error, arg string) {
	t.Helper()
	var cmdErr *CommandError
	if !errors.As(err, &cmdErr) {
		t.Fatalf("error = %v, want a CommandError carrying the argument vector", err)
	}
	sep := slices.Index(cmdErr.Args, "--end-of-options")
	value := slices.Index(cmdErr.Args, arg)
	if value < 0 {
		t.Fatalf("argv = %q, want it to carry %q", cmdErr.Args, arg)
	}
	if sep < 0 || sep > value {
		t.Errorf("argv = %q, want --end-of-options before %q", cmdErr.Args, arg)
	}
}

// TestResolveBaseInAShallowClone covers what CI looks like by default:
// actions/checkout clones with fetch-depth 1, and then neither the base commit
// the event names nor any merge base is in the object store. The message has to
// say that rather than repeat git's exit status.
func TestResolveBaseInAShallowClone(t *testing.T) {
	f := newForkedRepo(t)
	clone := filepath.Join(t.TempDir(), "shallow")
	// A local path would be hard-linked and the depth ignored, so the source is
	// named as a file URL. Nothing here talks to a network.
	url := "file:///" + strings.TrimPrefix(filepath.ToSlash(f.dir), "/")
	f.run("clone", "--quiet", "--depth", "1", "--branch", "update-a-dependency", url, clone)
	shallow := &testRepo{t: t, git: f.git, dir: clone}
	// Without origin/HEAD the clone has none of the three default candidates: the
	// remote has no main, and HEAD~1 was never fetched.
	shallow.run("update-ref", "-d", "refs/remotes/origin/HEAD")
	r := shallow.open(t)

	t.Run("a named base the clone does not hold", func(t *testing.T) {
		_, err := r.ResolveBase(t.Context(), f.fork)
		if err == nil {
			t.Fatal("ResolveBase returned no error for a commit the shallow clone does not hold")
		}
		if !strings.Contains(err.Error(), "fetch-depth: 0") {
			t.Errorf("error = %v, want it to say the clone is shallow", err)
		}
	})

	t.Run("no base at all", func(t *testing.T) {
		_, err := r.ResolveBase(t.Context(), "")
		if !errors.Is(err, ErrNoBase) {
			t.Fatalf("ResolveBase(\"\") error = %v, want ErrNoBase", err)
		}
		if !strings.Contains(err.Error(), "fetch-depth: 0") {
			t.Errorf("error = %v, want it to say the clone is shallow", err)
		}
	})
}

// A path typed into --base is the other thing that does not resolve, and the
// message names the flag that does take a file.
func TestResolveBaseNamesBaseFileForAPath(t *testing.T) {
	f := newForkedRepo(t)
	path := filepath.Join(f.dir, "Cargo.lock")

	_, err := f.open(t).ResolveBase(t.Context(), path)
	if err == nil {
		t.Fatalf("ResolveBase(%q) resolved a file path", path)
	}
	if !strings.Contains(err.Error(), "--base-file") {
		t.Errorf("error = %v, want it to name --base-file", err)
	}
}

func TestResolveBaseWithoutAnyBase(t *testing.T) {
	repo := newTestRepo(t)
	repo.write("Cargo.lock", "version = 3\n")
	repo.commit("the only commit")

	_, err := repo.open(t).ResolveBase(t.Context(), "")
	if !errors.Is(err, ErrNoBase) {
		t.Fatalf("ResolveBase(\"\") error = %v, want ErrNoBase", err)
	}
	for _, want := range []string{originMain, originHEAD, headParent, "--base"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("ResolveBase(\"\") error = %v, want it to name %q", err, want)
		}
	}
}
