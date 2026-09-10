package lockfile_test

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/vahapogut/trustdiff/internal/lockfile"
	_ "github.com/vahapogut/trustdiff/internal/lockfile/bun"
	_ "github.com/vahapogut/trustdiff/internal/lockfile/cargo"
	_ "github.com/vahapogut/trustdiff/internal/lockfile/deno"
	_ "github.com/vahapogut/trustdiff/internal/lockfile/npm"
	_ "github.com/vahapogut/trustdiff/internal/lockfile/pipreq"
	_ "github.com/vahapogut/trustdiff/internal/lockfile/pnpm"
	_ "github.com/vahapogut/trustdiff/internal/lockfile/poetry"
	_ "github.com/vahapogut/trustdiff/internal/lockfile/uv"
	_ "github.com/vahapogut/trustdiff/internal/lockfile/yarn"
)

// hookPattern reads the files pattern out of .pre-commit-hooks.yaml. The file is
// at the root of the repository, read the way internal/report reads docs/checks.md
// for the same kind of assertion: a document that has to keep up with the code is
// worth failing a test over when it does not.
func hookPattern(t *testing.T) *regexp.Regexp {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", ".pre-commit-hooks.yaml"))
	if err != nil {
		t.Fatalf("read .pre-commit-hooks.yaml: %v", err)
	}
	var hooks []struct {
		ID    string `yaml:"id"`
		Files string `yaml:"files"`
	}
	if err := yaml.Unmarshal(data, &hooks); err != nil {
		t.Fatalf("parse .pre-commit-hooks.yaml: %v", err)
	}
	for _, h := range hooks {
		if h.ID != "trustdiff-diff" {
			continue
		}
		re, err := regexp.Compile(h.Files)
		if err != nil {
			t.Fatalf("the files pattern of %s does not compile: %v", h.ID, err)
		}
		return re
	}
	t.Fatal("no trustdiff-diff hook in .pre-commit-hooks.yaml")
	return nil
}

// TestPreCommitHookRunsOnEveryFormatTheParsersRead is finding F20 of
// docs/review-2026-09-10.md. pre-commit decides whether to run a hook at all from
// the files pattern, and that pattern named four of the nine formats this release
// reads. A repository whose gate was the hook could change a yarn.lock, a
// bun.lock, a deno.lock, a poetry.lock or a requirements file and never be
// stopped, which is the worst shape a gate can have: it is installed, it is green,
// and it is not looking.
//
// The list is taken from the registered parsers rather than written out here, so a
// tenth format cannot be added without this failing.
func TestPreCommitHookRunsOnEveryFormatTheParsersRead(t *testing.T) {
	pattern := hookPattern(t)
	parsers := lockfile.Parsers()
	if len(parsers) < 9 {
		t.Fatalf("%d parsers registered; the blank imports above are not doing their job", len(parsers))
	}
	for _, p := range parsers {
		name := p.Name()
		t.Run(name, func(t *testing.T) {
			// The name a parser answers to, at the root and in a subdirectory,
			// because a monorepo keeps every one of them below the top.
			for _, path := range []string{name, "apps/web/" + name} {
				if !pattern.MatchString(path) {
					t.Errorf("the hook does not run on %s, which %s reads", path, name)
				}
			}
		})
	}
}

// The requirements parser answers to more than one name, and the hook has to run
// on all of them. These are the shapes internal/lockfile/pipreq documents: the word
// at either end of the name, joined by any of the separators people use, and any
// .txt inside a requirements directory.
func TestPreCommitHookRunsOnTheRequirementsShapes(t *testing.T) {
	pattern := hookPattern(t)
	for _, name := range []string{
		"requirements.txt",
		"requirements-dev.txt",
		"requirements_test.txt",
		"requirements.dev.txt",
		"dev-requirements.txt",
		"ci_requirements.txt",
		"requirements/base.txt",
		"requirements/prod.txt",
		"services/api/requirements-dev.txt",
		"REQUIREMENTS.TXT",
	} {
		t.Run(name, func(t *testing.T) {
			if _, ok := lockfile.For(name); !ok {
				t.Fatalf("no parser reads %s; the fixture is wrong, not the pattern", name)
			}
			if !pattern.MatchString(name) {
				t.Errorf("the hook does not run on %s", name)
			}
		})
	}
}

// The pattern decides whether the hook runs, not what it reads: pass_filenames is
// false and diff finds the lockfiles in git itself, so a pattern that is wider than
// the parsers costs one run that reports nothing and a pattern that is narrower
// costs the gate. It should still not run on a repository's ordinary files.
func TestPreCommitHookDoesNotRunOnEverything(t *testing.T) {
	pattern := hookPattern(t)
	for _, name := range []string{
		"go.mod",
		"README.md",
		"docs/requirements.md",
		"src/index.ts",
		"package.json",
		"Cargo.toml",
	} {
		t.Run(name, func(t *testing.T) {
			if pattern.MatchString(name) {
				t.Errorf("the hook runs on %s, which holds no locked dependency", name)
			}
		})
	}
}
