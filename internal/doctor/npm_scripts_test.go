package doctor

import (
	"strings"
	"testing"
)

// strict-allow-scripts turns npm's install-script policy from a warning into a hard
// error, and the rule wrote it into any .npmrc it found. On a project that has
// never reviewed its install scripts that is not hardening, it is an npm install
// that fails on every dependency with a postinstall, and a project whose install
// broke because a hardening tool wrote the line will take the line back out.
// Finding F15 of docs/review-2026-09-10.md.
func TestNpmStrictAllowScriptsWaitsForAReviewedPackageJSON(t *testing.T) {
	tests := []struct {
		name        string
		packageJSON string
		npmrc       string
		status      Status
		writes      bool
		says        []string
	}{
		{
			name:        "nothing has been reviewed, so there is nothing to be strict about",
			packageJSON: `{"name": "demo", "dependencies": {"esbuild": "^0.25.0"}}`,
			npmrc:       "min-release-age=3\n",
			status:      StatusAdvice,
			writes:      false,
			says:        []string{"allowScripts", "approve-scripts"},
		},
		{
			// The key is there and approves nothing, which is the same install: every
			// dependency with a script is unreviewed and every one of them fails.
			name:        "an allowScripts nobody has put anything in",
			packageJSON: `{"name": "demo", "allowScripts": {}}`,
			npmrc:       "min-release-age=3\n",
			status:      StatusAdvice,
			writes:      false,
		},
		{
			name:        "a project that has reviewed its install scripts",
			packageJSON: `{"name": "demo", "allowScripts": {"esbuild": true, "sharp": false}}`,
			npmrc:       "min-release-age=3\n",
			status:      StatusSet,
			writes:      true,
		},
		{
			// Somebody turned it on themselves. Whatever package.json says, that is
			// their line and it is doing what the rule asks.
			name:        "the setting already on, without a review beside it",
			packageJSON: `{"name": "demo"}`,
			npmrc:       "strict-allow-scripts=true\n",
			status:      StatusSet,
			writes:      true,
		},
		{
			name:        "the setting explicitly off beside a review",
			packageJSON: `{"name": "demo", "allowScripts": {"esbuild": true}}`,
			npmrc:       "strict-allow-scripts=false\n",
			status:      StatusWeak,
			writes:      false,
			says:        []string{"should be true"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			write(t, root, "package.json", tt.packageJSON+"\n")
			write(t, root, ".npmrc", tt.npmrc)
			managers := []Manager{{
				ID: NPM, Root: ".", Version: "12.0.0", VersionExact: true,
				VersionSource: "npm --version", Files: []string{".npmrc", "package.json"},
			}}
			card, err := Evaluate(root, managers, Options{
				Params: Params{Cooldown: threeDays, Version: "12.0.0", Now: fixedNow()},
				Fix:    true,
			})
			if err != nil {
				t.Fatal(err)
			}
			got := resultFor(t, card, "DR002")
			if got.Status != tt.status {
				t.Fatalf("DR002 = %s (%s), want %s", got.Status, got.Detail, tt.status)
			}
			for _, want := range tt.says {
				if !strings.Contains(got.Detail, want) {
					t.Errorf("detail does not say %q:\n%s", want, got.Detail)
				}
			}
			after := readFile(t, root, ".npmrc")
			if written := strings.Contains(after, "strict-allow-scripts=true"); written != tt.writes {
				t.Errorf("strict-allow-scripts=true present = %t, want %t:\n%s", written, tt.writes, after)
			}
		})
	}
}

// The machine's own .npmrc is not a project, so there is no package.json beside it
// to review and nothing to be strict about. It is reported and never written, which
// is what UserScope already guarantees for the writing half.
func TestNpmStrictAllowScriptsSaysNothingStrictAboutAUserFile(t *testing.T) {
	root := t.TempDir()
	home := t.TempDir()
	write(t, home, ".npmrc", "min-release-age=3\n")
	managers := []Manager{{
		ID: NPM, Root: ".", Base: home,
		Version: "12.0.0", VersionExact: true,
		VersionSource: "npm --version", Files: []string{".npmrc"},
	}}
	card, err := Evaluate(root, managers, Options{
		Params: Params{Cooldown: threeDays, Version: "12.0.0", Now: fixedNow()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := resultFor(t, card, "DR002"); got.Status != StatusAdvice {
		t.Errorf("DR002 = %s (%s), want advice", got.Status, got.Detail)
	}
}
