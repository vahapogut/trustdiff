package gitdiff

import (
	"errors"
	"os"
	"path/filepath"
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
			name:    "resolves a tag",
			prepare: func(f *forked) { f.run("tag", "v1.2.0", f.mainTip) },
			ref:     "v1.2.0",
			want:    func(f *forked) string { return f.mainTip },
		},
		{
			name:    "resolves an object name unchanged",
			refFrom: func(f *forked) string { return f.mainTip },
			want:    func(f *forked) string { return f.mainTip },
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
func TestResolveBaseRejectsRefsThatLookLikeOptions(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "pwned")
	refs := []struct {
		name string
		ref  string
	}{
		{"an upload-pack command", "--upload-pack=touch " + marker},
		{"a proxy command", "-oProxyCommand=x"},
		{"an output redirection", "--output=" + marker},
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
			if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("%s exists: the ref reached git as an option", marker)
			}
		})
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
