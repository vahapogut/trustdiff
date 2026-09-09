package checks

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/vahapogut/trustdiff/internal/advisory"
	"github.com/vahapogut/trustdiff/internal/advisory/depsdev"
	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/policy"
	"github.com/vahapogut/trustdiff/internal/registry"
	"github.com/vahapogut/trustdiff/internal/typosquat"
)

// fakeLoaderT answers SimilarNames and Downloads for TD008; every other method
// reports the source as not configured.
type fakeLoaderT struct {
	similar    []depsdev.Similar
	similarErr error
	downloads  map[string]int64
	calls      []string
}

func (l *fakeLoaderT) Prefetch(context.Context, []model.PackageRef) {}
func (l *fakeLoaderT) Versions(context.Context, model.Ecosystem, string) (*registry.VersionList, error) {
	return nil, ErrNotConfigured
}
func (l *fakeLoaderT) VersionInfo(context.Context, model.PackageRef) (*model.VersionInfo, error) {
	return nil, ErrNotConfigured
}
func (l *fakeLoaderT) Owners(context.Context, model.Ecosystem, string) ([]model.Publisher, error) {
	return nil, ErrNotConfigured
}
func (l *fakeLoaderT) Advisories(context.Context, model.PackageRef) ([]advisory.Advisory, error) {
	return nil, ErrNotConfigured
}
func (l *fakeLoaderT) DepsDev(context.Context, model.PackageRef) (*depsdev.VersionFacts, error) {
	return nil, ErrNotConfigured
}

func (l *fakeLoaderT) SimilarNames(_ context.Context, eco model.Ecosystem, name string) ([]depsdev.Similar, error) {
	l.calls = append(l.calls, fmt.Sprintf("similar %s:%s", eco, name))
	return l.similar, l.similarErr
}

func (l *fakeLoaderT) Downloads(_ context.Context, eco model.Ecosystem, name string) (int64, error) {
	l.calls = append(l.calls, fmt.Sprintf("downloads %s:%s", eco, name))
	n, ok := l.downloads[name]
	if !ok {
		return -1, registry.ErrNotFound
	}
	return n, nil
}

var listDateT = time.Date(2026, time.September, 9, 0, 0, 0, 0, time.UTC)

// newTyposquatT builds the check over a small popular list per ecosystem.
func newTyposquatT() *typosquatSuspect {
	lists := typosquat.NewLists(
		&typosquat.List{Ecosystem: model.NPM, Fetched: listDateT, Names: []string{"express", "lodash", "react", "@types/node", "cross-env"}},
		&typosquat.List{Ecosystem: model.PyPI, Fetched: listDateT, Names: []string{"requests", "colorama"}},
		&typosquat.List{Ecosystem: model.Cargo, Fetched: listDateT, Names: []string{"serde", "tokio"}},
	)
	return &typosquatSuspect{lists: lists, load: func() *typosquat.Lists { panic("load must not be called when lists are set") }}
}

func subjectT(ref string, loader Loader, downloads int64) *Subject {
	return &Subject{
		Ref:       model.MustParseRef(ref),
		Now:       listDateT,
		Settings:  (*policy.Policy)(nil).Effective(model.MustParseRef(ref).Ecosystem),
		Downloads: downloads,
		Loader:    loader,
	}
}

func TestTyposquatSuspectRegistered(t *testing.T) {
	for _, key := range []string{"TD008", "typosquat-suspect"} {
		got, ok := Lookup(key)
		if !ok || got.ID() != "TD008" || got.Name() != "typosquat-suspect" {
			t.Errorf("Lookup(%q) = %v, %v", key, got, ok)
		}
	}
	if def, ok := policy.DefaultCheck("typosquat-suspect"); !ok || def.Level != model.LevelBlock {
		t.Errorf("default setting = %+v, %v; want block", def, ok)
	}
	if !AppliesTo(registeredTyposquat, model.Deno) || registeredTyposquat.Ecosystems() != nil {
		t.Error("TD008 must apply to every ecosystem")
	}
}

func TestTyposquatSuspect(t *testing.T) {
	tests := []struct {
		name     string
		ref      string
		loader   *fakeLoaderT
		down     int64
		skipped  string
		want     int
		evidence map[string]string
		text     []string
		calls    []string
	}{
		{
			name: "popular name is never a suspect",
			ref:  "npm:express@4.19.2",
			loader: &fakeLoaderT{
				similar: []depsdev.Similar{{Name: "lodash"}},
			},
			down: -1,
			want: 0,
		},
		{
			name: "popular name in another spelling",
			ref:  "pypi:Requests@2.32.0",
			down: -1,
			want: 0,
		},
		{
			name: "edit distance without a loader",
			ref:  "npm:exprss@1.0.0",
			down: -1,
			want: 1,
			evidence: map[string]string{
				"candidate":    "exprss",
				"neighbor":     "express",
				"rule":         "edit-distance",
				"distance":     "1",
				"list_fetched": "2026-09-09",
			},
			text: []string{`"exprss"`, `"express"`, "within 1 edit(s)", "rule edit-distance"},
		},
		{
			name: "separator swap with the deps.dev neighbor confirming",
			ref:  "npm:crossenv@1.0.0",
			loader: &fakeLoaderT{
				similar: []depsdev.Similar{{Name: "crossenv"}, {Name: "cross-env"}},
			},
			down: -1,
			want: 1,
			evidence: map[string]string{
				"neighbor":          "cross-env",
				"rule":              "separator-swap",
				"deps_dev_neighbor": "cross-env",
			},
			text:  []string{`"crossenv"`, `"cross-env"`, "only in separators", "deps.dev also lists"},
			calls: []string{"similar npm:crossenv"},
		},
		{
			name: "deps.dev neighbor in the popular list on its own",
			ref:  "npm:xpress-server@1.0.0",
			loader: &fakeLoaderT{
				similar: []depsdev.Similar{{Name: "express"}},
			},
			down: -1,
			want: 1,
			evidence: map[string]string{
				"candidate":         "xpress-server",
				"deps_dev_neighbor": "express",
			},
			text:  []string{`"xpress-server"`, `"express"`, "deps.dev lists the much more popular"},
			calls: []string{"similar npm:xpress-server"},
		},
		{
			name: "deps.dev neighbor with far more downloads",
			ref:  "npm:leftpad-fork@1.0.0",
			loader: &fakeLoaderT{
				similar:   []depsdev.Similar{{Name: "leftpad"}, {Name: "left-pad"}},
				downloads: map[string]int64{"leftpad": 900, "left-pad": 2_000_000},
			},
			down:     10,
			want:     1,
			evidence: map[string]string{"deps_dev_neighbor": "left-pad"},
			calls:    []string{"similar npm:leftpad-fork", "downloads npm:leftpad", "downloads npm:left-pad"},
		},
		{
			name: "deps.dev neighbor not popular enough",
			ref:  "npm:leftpad-fork@1.0.0",
			loader: &fakeLoaderT{
				similar:   []depsdev.Similar{{Name: "leftpad"}},
				downloads: map[string]int64{"leftpad": 900},
			},
			down:  10,
			want:  0,
			calls: []string{"similar npm:leftpad-fork", "downloads npm:leftpad"},
		},
		{
			name: "unknown own downloads skip the download comparison",
			ref:  "npm:leftpad-fork@1.0.0",
			loader: &fakeLoaderT{
				similar:   []depsdev.Similar{{Name: "left-pad"}},
				downloads: map[string]int64{"left-pad": 2_000_000},
			},
			down:  -1,
			want:  0,
			calls: []string{"similar npm:leftpad-fork"},
		},
		{
			name: "deps.dev error is no cross-check",
			ref:  "npm:exprss@1.0.0",
			loader: &fakeLoaderT{
				similarErr: errors.New("deps.dev: 503"),
			},
			down: -1,
			want: 1,
			evidence: map[string]string{
				"neighbor": "express",
			},
			calls: []string{"similar npm:exprss"},
		},
		{
			name: "deps.dev error alone finds nothing",
			ref:  "npm:unrelated-thing@1.0.0",
			loader: &fakeLoaderT{
				similarErr: errors.New("deps.dev: 503"),
			},
			down: -1,
			want: 0,
		},
		{
			name: "download lookups are bounded",
			ref:  "npm:unrelated-thing@1.0.0",
			loader: &fakeLoaderT{
				similar:   []depsdev.Similar{{Name: "a"}, {Name: "b"}, {Name: "c"}, {Name: "d"}, {Name: "e"}, {Name: "f"}},
				downloads: map[string]int64{"f": 5_000_000},
			},
			down:  1,
			want:  0,
			calls: []string{"similar npm:unrelated-thing", "downloads npm:a", "downloads npm:b", "downloads npm:c", "downloads npm:d", "downloads npm:e"},
		},
		{
			name: "pypi affix",
			ref:  "pypi:python-requests@1.0.0",
			down: -1,
			want: 1,
			evidence: map[string]string{
				"neighbor": "requests",
				"rule":     "language-affix",
				"distance": "7",
			},
			text: []string{`"python-requests"`, `"requests"`, "language prefix or suffix"},
		},
		{
			name: "cargo transposition",
			ref:  "cargo:sedre@1.0.0",
			down: -1,
			want: 1,
			evidence: map[string]string{
				"neighbor": "serde",
				"rule":     "transposition",
			},
			text: []string{`"sedre"`, `"serde"`, "adjacent characters swapped"},
		},
		{
			name:    "ecosystem without a list",
			ref:     "deno:oak@1.0.0",
			down:    -1,
			skipped: "no popular package list for deno",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newTyposquatT()
			var loader Loader
			if tt.loader != nil {
				loader = tt.loader
			}
			s := subjectT(tt.ref, loader, tt.down)
			res := c.Run(context.Background(), s)
			if tt.skipped != "" {
				if res.Skipped == nil || res.Skipped.Check != c.Name() || res.Skipped.Reason != tt.skipped {
					t.Fatalf("Run() = %+v, want skipped %q", res, tt.skipped)
				}
				return
			}
			if res.Skipped != nil {
				t.Fatalf("Run() skipped: %s", res.Skipped.Reason)
			}
			if len(res.Findings) != tt.want {
				t.Fatalf("Run() returned %d findings, want %d: %+v", len(res.Findings), tt.want, res.Findings)
			}
			if tt.loader != nil && tt.calls != nil && strings.Join(tt.loader.calls, ",") != strings.Join(tt.calls, ",") {
				t.Errorf("loader calls = %v, want %v", tt.loader.calls, tt.calls)
			}
			if tt.want == 0 {
				return
			}
			f := res.Findings[0]
			if f.ID != "TD008" || f.Name != "typosquat-suspect" || f.Level != model.LevelBlock || f.Ref != s.Ref {
				t.Errorf("finding identity = %s %s %s %s", f.ID, f.Name, f.Level, f.Ref)
			}
			for key, want := range tt.evidence {
				got, ok := f.Evidence[key]
				if !ok || fmt.Sprint(got) != want {
					t.Errorf("evidence[%s] = %v (present %v), want %s", key, got, ok, want)
				}
			}
			if _, ok := f.Evidence["deps_dev_neighbor"]; ok && tt.evidence["deps_dev_neighbor"] == "" {
				t.Errorf("evidence carries deps_dev_neighbor %v, want none", f.Evidence["deps_dev_neighbor"])
			}
			for _, fragment := range tt.text {
				if !strings.Contains(f.Explanation, fragment) {
					t.Errorf("explanation %q lacks %q", f.Explanation, fragment)
				}
			}
			if f.Title == "" || !strings.Contains(f.Title, `"`+fmt.Sprint(f.Evidence["candidate"])+`"`) {
				t.Errorf("title %q does not quote the candidate", f.Title)
			}
		})
	}
}

func TestTyposquatSuspectPolicyLevel(t *testing.T) {
	c := newTyposquatT()
	s := subjectT("npm:exprss@1.0.0", nil, -1)
	s.Settings.Checks["typosquat-suspect"] = policy.CheckSetting{Level: model.LevelWarn}
	res := c.Run(context.Background(), s)
	if len(res.Findings) != 1 || res.Findings[0].Level != model.LevelWarn {
		t.Errorf("Run() = %+v, want one warn finding", res)
	}
}

// TestTyposquatSuspectLazyLoad checks that the lists are loaded once, on first
// use, and that SetTyposquatLists replaces them.
func TestTyposquatSuspectLazyLoad(t *testing.T) {
	loads := 0
	custom := typosquat.NewLists(&typosquat.List{Ecosystem: model.NPM, Fetched: listDateT, Names: []string{"express"}})
	c := &typosquatSuspect{load: func() *typosquat.Lists { loads++; return custom }}
	for range 3 {
		if res := c.Run(context.Background(), subjectT("npm:exprss@1.0.0", nil, -1)); len(res.Findings) != 1 {
			t.Fatalf("Run() = %+v, want one finding", res)
		}
	}
	if loads != 1 {
		t.Errorf("lists loaded %d times, want once", loads)
	}
	c.set(typosquat.NewLists(&typosquat.List{Ecosystem: model.NPM, Fetched: listDateT, Names: []string{"exprss"}}))
	if res := c.Run(context.Background(), subjectT("npm:exprss@1.0.0", nil, -1)); len(res.Findings) != 0 {
		t.Errorf("Run() after set = %+v, want no finding", res)
	}
}

// TestTyposquatSuspectEmbedded runs the registered check with its real lists
// once, so the lazy load path and the embedded snapshot are exercised.
func TestTyposquatSuspectEmbedded(t *testing.T) {
	c := &typosquatSuspect{load: loadTyposquatLists}
	res := c.Run(context.Background(), subjectT("pypi:reqeusts@1.0.0", nil, -1))
	if len(res.Findings) != 1 || res.Findings[0].Evidence["neighbor"] != "requests" {
		t.Errorf("Run() = %+v, want a finding naming requests", res)
	}
	if res := c.Run(context.Background(), subjectT("pypi:requests@2.32.0", nil, -1)); len(res.Findings) != 0 || res.Skipped != nil {
		t.Errorf("Run() for a popular package = %+v, want nothing", res)
	}
}
