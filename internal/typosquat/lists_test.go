package typosquat

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vahapogut/trustdiff/internal/httpcache"
	"github.com/vahapogut/trustdiff/internal/model"
)

var fetchedDay = time.Date(2026, time.September, 9, 0, 0, 0, 0, time.UTC)

func TestParseListRoundTrip(t *testing.T) {
	in := &List{
		Ecosystem: model.PyPI,
		Source:    "https://example.test/a.json https://example.test/b.json",
		Fetched:   fetchedDay,
		License:   "MIT; see https://example.test/LICENSE",
		Names:     []string{"Requests", "boto3", "requests", "python_dateutil"},
	}
	data := in.Encode()
	if want := "# NOTICE source: https://example.test/a.json https://example.test/b.json; fetched: 2026-09-09; license: MIT; see https://example.test/LICENSE\n"; !bytes.HasPrefix(data, []byte(want)) {
		t.Errorf("Encode() starts with %q, want %q", data[:min(len(data), len(want))], want)
	}
	got, err := ParseList(model.PyPI, data)
	if err != nil {
		t.Fatal(err)
	}
	if got.Source != in.Source || !got.Fetched.Equal(in.Fetched) || got.License != in.License {
		t.Errorf("ParseList() provenance = %q %s %q, want %q %s %q", got.Source, got.Fetched, got.License, in.Source, in.Fetched, in.License)
	}
	if want := []string{"boto3", "python-dateutil", "requests"}; !slices.Equal(got.Names, want) {
		t.Errorf("ParseList() names = %v, want %v", got.Names, want)
	}
	if got.Ecosystem != model.PyPI {
		t.Errorf("ParseList() ecosystem = %s", got.Ecosystem)
	}
}

func TestParseListRejects(t *testing.T) {
	tests := []struct {
		name string
		data string
		want string
	}{
		{"empty", "", "empty file"},
		{"no notice", "requests\n", "must start with"},
		{"two fields", "# NOTICE source: x; fetched: 2026-09-09\nrequests\n", "source, fetched and license"},
		{"wrong key", "# NOTICE origin: x; fetched: 2026-09-09; license: MIT\nrequests\n", "field 1 must start with"},
		{"bad date", "# NOTICE source: x; fetched: yesterday; license: MIT\nrequests\n", "fetched"},
		{"empty license", "# NOTICE source: x; fetched: 2026-09-09; license: \nrequests\n", "license is empty"},
		{"no names", "# NOTICE source: x; fetched: 2026-09-09; license: MIT\n# only comments\n\n", "no names"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseList(model.NPM, []byte(tt.data))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("ParseList() error = %v, want one containing %q", err, tt.want)
			}
		})
	}
}

func TestParseListIgnoresCommentsAndBlankLines(t *testing.T) {
	data := "# NOTICE source: x; fetched: 2026-09-09; license: MIT\n\n# a comment\nexpress\n  lodash  \n\n"
	got, err := ParseList(model.NPM, []byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"express", "lodash"}; !slices.Equal(got.Names, want) {
		t.Errorf("names = %v, want %v", got.Names, want)
	}
}

// TestEmbedded checks the generated snapshot: every listed ecosystem has a
// substantial, sorted, unique list with full provenance, in a file that stays
// under 15000 lines.
func TestEmbedded(t *testing.T) {
	lists := Embedded()
	minNames := map[model.Ecosystem]int{model.NPM: 10000, model.PyPI: 10000, model.Cargo: 4000}
	for _, eco := range listed {
		t.Run(string(eco), func(t *testing.T) {
			list, ok := lists.List(eco)
			if !ok {
				t.Fatal("no list")
			}
			if len(list.Names) < minNames[eco] {
				t.Errorf("%d names, want at least %d", len(list.Names), minNames[eco])
			}
			if !slices.IsSorted(list.Names) || slices.Compact(slices.Clone(list.Names)) == nil || len(slices.Compact(slices.Clone(list.Names))) != len(list.Names) {
				t.Error("names are not sorted and unique")
			}
			for _, name := range list.Names {
				if name != Canonical(eco, name) {
					t.Errorf("name %q is not canonical", name)
					break
				}
			}
			if !strings.HasPrefix(list.Source, "https://") {
				t.Errorf("source %q is not a URL", list.Source)
			}
			if list.License == "" {
				t.Error("license is empty")
			}
			if list.Fetched.Year() < 2026 {
				t.Errorf("fetched %s is implausible", list.Fetched)
			}
			if lists.Origin(eco) != "embedded" {
				t.Errorf("origin = %q", lists.Origin(eco))
			}
			data, err := fs.ReadFile(embedded, dataFile(eco))
			if err != nil {
				t.Fatal(err)
			}
			if lines := bytes.Count(data, []byte("\n")); lines >= 15000 {
				t.Errorf("%s has %d lines, want fewer than 15000", dataFile(eco), lines)
			}
			set, ok := lists.Popular(eco)
			if !ok || set.Len() != len(list.Names) {
				t.Errorf("Popular() has %d names, list has %d", set.Len(), len(list.Names))
			}
		})
	}
	if _, ok := lists.Popular(model.Deno); ok {
		t.Error("Deno has a popular list, none was generated")
	}
}

// listServer serves the recorded and truncated fixtures under testdata and
// records every request path.
type listServer struct {
	*httptest.Server
	mu       sync.Mutex
	requests []string
}

func newListServer(t *testing.T) *listServer {
	t.Helper()
	s := &listServer{}
	mux := http.NewServeMux()
	serve := func(pattern, fixture string) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			s.record(r)
			http.ServeFile(w, r, filepath.Join("testdata", fixture))
		})
	}
	serve("/top-pypi-packages.min.json", "top-pypi-packages.json")
	serve("/top.js", "npm-high-impact-top.js")
	serve("/raw.json", "npm-rank.json")
	mux.HandleFunc("/api/v1/crates", func(w http.ResponseWriter, r *http.Request) {
		s.record(r)
		q := r.URL.Query()
		if q.Get("sort") != "downloads" || q.Get("per_page") != "100" {
			http.Error(w, "unexpected query "+r.URL.RawQuery, http.StatusBadRequest)
			return
		}
		switch q.Get("page") {
		case "1":
			http.ServeFile(w, r, filepath.Join("testdata", "crates-page1.json"))
		case "2":
			http.ServeFile(w, r, filepath.Join("testdata", "crates-page2.json"))
		default:
			http.Error(w, "no such page", http.StatusNotFound)
		}
	})
	s.Server = httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

func (s *listServer) record(r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, r.URL.RequestURI())
}

func (s *listServer) sources(pages int) Sources {
	return Sources{
		PyPI:          s.URL + "/top-pypi-packages.min.json",
		NPMHighImpact: s.URL + "/top.js",
		NPMRank:       s.URL + "/raw.json",
		Crates:        s.URL + "/api/v1/crates",
		CratesPages:   pages,
	}
}

func newTestClient(t *testing.T, server *listServer) *httpcache.Client {
	t.Helper()
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client, err := httpcache.New(httpcache.Options{
		Dir:       t.TempDir(),
		UserAgent: "trustdiff-test",
		Retries:   -1,
		HostRPS:   map[string]float64{u.Host: 1000},
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestFetch(t *testing.T) {
	server := newListServer(t)
	client := newTestClient(t, server)
	now := func() time.Time { return fetchedDay.Add(13 * time.Hour) }
	lists, err := Fetch(context.Background(), client, WithSources(server.sources(2)), WithNow(now))
	if err != nil {
		t.Fatal(err)
	}
	want := map[model.Ecosystem][]string{
		model.NPM:   {"ansi-styles", "brace-expansion", "chalk", "commander", "debug", "fs-extra", "minimatch", "semver", "tslib"},
		model.PyPI:  {"boto3", "certifi", "idna", "packaging", "typing-extensions"},
		model.Cargo: {"base64", "bitflags", "getrandom", "hashbrown", "libc", "proc-macro2", "quote", "rand", "rand_core", "syn"},
	}
	if len(lists) != len(want) {
		t.Fatalf("Fetch() returned %d lists, want %d", len(lists), len(want))
	}
	for _, list := range lists {
		names := slices.Clone(list.Names)
		slices.Sort(names)
		if !slices.Equal(names, want[list.Ecosystem]) {
			t.Errorf("%s names = %v, want %v", list.Ecosystem, names, want[list.Ecosystem])
		}
		if !list.Fetched.Equal(fetchedDay) {
			t.Errorf("%s fetched = %s, want %s", list.Ecosystem, list.Fetched, fetchedDay)
		}
		if list.License == "" || !strings.Contains(list.Source, server.URL) {
			t.Errorf("%s provenance = %q %q", list.Ecosystem, list.Source, list.License)
		}
	}
	wantRequests := []string{
		"/top.js", "/raw.json", "/top-pypi-packages.min.json",
		"/api/v1/crates?sort=downloads&per_page=100&page=1",
		"/api/v1/crates?sort=downloads&per_page=100&page=2",
	}
	if !slices.Equal(server.requests, wantRequests) {
		t.Errorf("requests = %v, want %v", server.requests, wantRequests)
	}
}

func TestFetchLimit(t *testing.T) {
	server := newListServer(t)
	client := newTestClient(t, server)
	lists, err := Fetch(context.Background(), client, WithSources(server.sources(2)), WithLimit(3))
	if err != nil {
		t.Fatal(err)
	}
	for _, list := range lists {
		if len(list.Names) != 3 {
			t.Errorf("%s has %d names, want 3", list.Ecosystem, len(list.Names))
		}
	}
	// The cap keeps the most popular names: rank order, not alphabetical.
	if npm := lists[0]; npm.Ecosystem != model.NPM || !slices.Equal(npm.Names, []string{"semver", "minimatch", "debug"}) {
		t.Errorf("npm names = %v, want the three highest ranked", npm.Names)
	}
}

func TestFetchErrors(t *testing.T) {
	server := newListServer(t)
	client := newTestClient(t, server)
	tests := []struct {
		name   string
		change func(*Sources)
		want   string
	}{
		{"pypi missing", func(s *Sources) { s.PyPI = server.URL + "/missing.json" }, "pypi list: GET"},
		{"npm wrong shape", func(s *Sources) { s.NPMHighImpact = server.URL + "/raw.json" }, "npm list: parsing"},
		{"crates page missing", func(s *Sources) { s.CratesPages = 3 }, "cargo list: GET"},
		{"nil client", nil, "client is required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sources := server.sources(2)
			c := client
			if tt.change == nil {
				c = nil
			} else {
				tt.change(&sources)
			}
			_, err := Fetch(context.Background(), c, WithSources(sources))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Fetch() error = %v, want one containing %q", err, tt.want)
			}
		})
	}
}

func TestRefreshAndLoad(t *testing.T) {
	server := newListServer(t)
	client := newTestClient(t, server)
	cacheDir := t.TempDir()
	now := func() time.Time { return fetchedDay.Add(9 * time.Hour) }

	if err := Refresh(context.Background(), client, cacheDir, WithSources(server.sources(2)), WithNow(now)); err != nil {
		t.Fatal(err)
	}
	for _, eco := range listed {
		if _, err := os.Stat(filepath.Join(ListsDir(cacheDir), string(eco)+".txt")); err != nil {
			t.Errorf("refreshed %s list: %v", eco, err)
		}
	}

	t.Run("fresh copy is preferred", func(t *testing.T) {
		lists := Load(cacheDir, fetchedDay.AddDate(0, 0, 29), nil)
		for _, eco := range listed {
			if got, want := lists.Origin(eco), filepath.Join(ListsDir(cacheDir), string(eco)+".txt"); got != want {
				t.Errorf("%s origin = %q, want %q", eco, got, want)
			}
		}
		set, _ := lists.Popular(model.Cargo)
		if set.Len() != 10 || !set.Has("hashbrown") {
			t.Errorf("cargo set has %d names, want the 10 fixture crates", set.Len())
		}
	})
	t.Run("stale copy falls back to embedded", func(t *testing.T) {
		lists := Load(cacheDir, fetchedDay.AddDate(0, 0, 31), nil)
		for _, eco := range listed {
			if got := lists.Origin(eco); got != "embedded" {
				t.Errorf("%s origin = %q, want embedded", eco, got)
			}
		}
	})
	t.Run("corrupt copy falls back for that ecosystem only", func(t *testing.T) {
		path := filepath.Join(ListsDir(cacheDir), "npm.txt")
		if err := os.WriteFile(path, []byte("not a list\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		lists := Load(cacheDir, fetchedDay.AddDate(0, 0, 1), nil)
		if got := lists.Origin(model.NPM); got != "embedded" {
			t.Errorf("npm origin = %q, want embedded", got)
		}
		if got := lists.Origin(model.PyPI); got == "embedded" {
			t.Errorf("pypi origin = %q, want the refreshed file", got)
		}
	})
}

func TestLoadWithoutRefreshedCopy(t *testing.T) {
	lists := Load(filepath.Join(t.TempDir(), "never-created"), fetchedDay, nil)
	for _, eco := range listed {
		if got := lists.Origin(eco); got != "embedded" {
			t.Errorf("%s origin = %q, want embedded", eco, got)
		}
	}
	if set, ok := lists.Popular(model.NPM); !ok || !set.Has("express") {
		t.Error("embedded npm list does not know express")
	}
}

func TestRefreshWritesNothingOnFailure(t *testing.T) {
	server := newListServer(t)
	client := newTestClient(t, server)
	cacheDir := t.TempDir()
	sources := server.sources(2)
	sources.Crates = server.URL + "/nowhere"
	err := Refresh(context.Background(), client, cacheDir, WithSources(sources))
	if err == nil || !strings.Contains(err.Error(), "refreshing popular lists: cargo list") {
		t.Fatalf("Refresh() error = %v", err)
	}
	if _, statErr := os.Stat(ListsDir(cacheDir)); !errors.Is(statErr, fs.ErrNotExist) {
		t.Errorf("lists directory exists after a failed refresh: %v", statErr)
	}
}

func TestNewLists(t *testing.T) {
	lists := NewLists(&List{Ecosystem: model.NPM, Fetched: fetchedDay, Names: []string{"express"}}, nil)
	if set, ok := lists.Popular(model.NPM); !ok || !set.Has("express") || lists.Origin(model.NPM) != "custom" {
		t.Errorf("NewLists() npm = %v, %v, origin %q", set.Names(), ok, lists.Origin(model.NPM))
	}
	if _, ok := lists.Popular(model.PyPI); ok {
		t.Error("NewLists() has a pypi list it was not given")
	}
}

func TestParseNPMHighImpact(t *testing.T) {
	tests := []struct {
		name string
		data string
		want []string
		err  string
	}{
		{"names", "export const top = [\n  'semver',\n  'ansi-styles'\n]\n", []string{"semver", "ansi-styles"}, ""},
		{"scoped", "export const top = ['@types/node']", []string{"@types/node"}, ""},
		{"wrong prefix", "[\"semver\"]", nil, "starting with"},
		{"unterminated", "export const top = ['semver", nil, "unterminated"},
		{"empty", "export const top = []", nil, "no names"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseNPMHighImpact([]byte(tt.data))
			if tt.err != "" {
				if err == nil || !strings.Contains(err.Error(), tt.err) {
					t.Errorf("error = %v, want one containing %q", err, tt.err)
				}
				return
			}
			if err != nil || !slices.Equal(got, tt.want) {
				t.Errorf("names = %v, %v; want %v", got, err, tt.want)
			}
		})
	}
}

func TestParseCratesPage(t *testing.T) {
	names, next, err := parseCratesPage([]byte(`{"crates":[{"name":"syn"},{"name":"quote"}],"meta":{"total":2,"next_page":null}}`))
	if err != nil || !slices.Equal(names, []string{"syn", "quote"}) || next != "" {
		t.Errorf("parseCratesPage() = %v, %q, %v", names, next, err)
	}
	if _, _, err := parseCratesPage([]byte(`{"crates":`)); err == nil {
		t.Error("truncated JSON parsed")
	}
}
