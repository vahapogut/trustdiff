package cli

import (
	"context"
	"net/url"
	"strings"

	"github.com/vahapogut/trustdiff/internal/checks"
	"github.com/vahapogut/trustdiff/internal/guarddog"
	"github.com/vahapogut/trustdiff/internal/lockfile"
	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/report"
)

type codeScanner interface {
	Scan(context.Context, model.PackageRef) (guarddog.Result, error)
}

var guardDogFactory = func(a *App) (codeScanner, error) {
	return guarddog.New(guarddog.Options{Binary: a.Opts.GuardDogBinary, Timeout: a.Opts.GuardDogTimeout, Offline: a.Opts.Offline})
}

// addGuardDog appends attributed evidence without changing any trustdiff finding.
// A requested scan that did not finish cannot turn into a successful empty result.
func (a *App) addGuardDog(ctx context.Context, rep *report.Report, inputs []checks.Input) {
	if !a.Opts.GuardDog {
		return
	}
	rep.GuardDogRequested = true
	var scanner codeScanner
	var setupErr error
	initialized := false
	seen := map[model.PackageRef]bool{}
	for i := range rep.Subjects {
		s := &rep.Subjects[i]
		if s.Verdict != report.VerdictWarn && s.Verdict != report.VerdictBlock {
			continue
		}
		// A Git/path/archive entry is not the registry release that happens to have
		// its name. Keep that lack of coverage explicit in the supplement.
		nonRegistry := i < len(inputs) && inputs[i].Lock != nil && !publicRegistryEntry(inputs[i].Lock)
		if nonRegistry {
			rep.GuardDog = append(rep.GuardDog, model.Analysis{Ref: s.Ref, Source: guarddog.SourceURL, Status: "unavailable", Message: "locked source is not an identified public registry release; no substitute package was scanned"})
			continue
		}
		if seen[s.Ref] {
			continue
		}
		seen[s.Ref] = true
		if !initialized {
			scanner, setupErr = guardDogFactory(a)
			initialized = true
		}
		var result model.Analysis
		if setupErr != nil {
			result = model.Analysis{Ref: s.Ref, Source: guarddog.SourceURL, Status: "unavailable", Message: setupErr.Error()}
		} else {
			result, _ = scanner.Scan(ctx, s.Ref)
		}
		rep.GuardDog = append(rep.GuardDog, result)
	}
	for i := range rep.GuardDog {
		r := &rep.GuardDog[i]
		if r.Status != "completed" && rep.Summary.ExitCode == ExitOK {
			rep.SetExitCode(ExitUnavailable)
		}
	}
}

func publicRegistryEntry(entry *lockfile.Entry) bool {
	if entry.Source != lockfile.SourceRegistry || entry.Bundled {
		return false
	}
	if entry.Ref.Ecosystem == model.Cargo {
		return entry.Resolved == "registry+https://github.com/rust-lang/crates.io-index" || entry.Resolved == "sparse+https://index.crates.io/"
	}
	u, err := url.Parse(entry.Resolved)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" || u.RawQuery != "" || u.ForceQuery || strings.Contains(entry.Resolved, "#") {
		return false
	}
	switch entry.Ref.Ecosystem {
	case model.NPM:
		if !strings.EqualFold(u.Host, "registry.npmjs.org") || model.NPMNameProblem(entry.Ref.Name) != "" || entry.Ref.Version == "" {
			return false
		}
		// npm's public tarball path identifies both the package and exact version.
		// Verified 2026-09-29 against is-number@7.0.0 and @sigstore/bundle@5.0.0
		// version documents from https://registry.npmjs.org.
		// URL.Path is decoded once, so equivalent percent-encoding is accepted but
		// another package/version on the same registry host is not substituted.
		name := entry.Ref.Name
		if _, base, scoped := strings.Cut(name, "/"); scoped {
			name = base
		}
		return u.Path == "/"+entry.Ref.Name+"/-/"+name+"-"+entry.Ref.Version+".tgz"
	case model.PyPI:
		return strings.EqualFold(u.Host, "files.pythonhosted.org") || strings.EqualFold(u.Host, "pypi.org")
	default:
		return false
	}
}
