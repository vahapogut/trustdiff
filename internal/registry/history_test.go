package registry

import (
	"testing"
	"time"

	"github.com/vahapogut/trustdiff/internal/model"
)

func day(n int) time.Time { return time.Date(2026, time.January, 1+n, 0, 0, 0, 0, time.UTC) }

func v(ver string, published int, pre, yanked bool, publisher string) model.VersionInfo {
	info := model.VersionInfo{Ref: model.PackageRef{Ecosystem: model.NPM, Name: "lib", Version: ver}, Prerelease: pre, Yanked: yanked}
	if published >= 0 {
		info.PublishedAt = day(published)
	}
	if publisher != "" {
		info.Publisher = &model.Publisher{Name: publisher}
	}
	return info
}

func sample() *VersionList {
	return &VersionList{
		Ecosystem: model.NPM,
		Name:      "lib",
		Latest:    "1.3.0",
		Versions: []model.VersionInfo{
			v("1.0.0", 0, false, false, "alice"),
			v("1.1.0", 2, false, false, "alice"),
			v("1.1.1", 3, false, true, "alice"),      // yanked
			v("1.2.0-rc.1", 4, true, false, "alice"), // prerelease
			v("1.2.0", 5, false, false, "alice"),
			v("0.9.9", 6, false, false, "bob"), // published out of order, later in time
			v("1.3.0", 8, false, false, "carol"),
			v("2.0.0-beta.1", 9, true, false, "carol"),
			v("1.4.0", -1, false, false, "dave"), // no publish time
		},
	}
}

func ref(ver string) model.PackageRef {
	return model.PackageRef{Ecosystem: model.NPM, Name: "lib", Version: ver}
}

func TestPreviousIsByPublishTimeNotByVersion(t *testing.T) {
	list := sample()
	tests := []struct {
		version string
		want    string
	}{
		{"1.3.0", "0.9.9"},        // 0.9.9 was published after 1.2.0, so it is the previous release
		{"1.2.0", "1.1.0"},        // skips the yanked 1.1.1 and the rc
		{"1.1.0", "1.0.0"},        // first release has no previous
		{"1.0.0", ""},             // nothing earlier
		{"2.0.0-beta.1", "1.3.0"}, // a prerelease still has a previous stable
		{"1.4.0", ""},             // no publish time, no history
		{"9.9.9", ""},             // unknown version
	}
	for _, tt := range tests {
		got := Previous(list, ref(tt.version))
		gotVersion := ""
		if got != nil {
			gotVersion = got.Ref.Version
		}
		if gotVersion != tt.want {
			t.Errorf("Previous(%s) = %q, want %q", tt.version, gotVersion, tt.want)
		}
	}
}

func TestWindowNewestFirstWithoutPrereleasesOrYanked(t *testing.T) {
	list := sample()
	got := Window(list, ref("1.3.0"), 5)
	want := []string{"0.9.9", "1.2.0", "1.1.0", "1.0.0"}
	if len(got) != len(want) {
		t.Fatalf("Window = %d entries, want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i].Ref.Version != w {
			t.Errorf("Window[%d] = %s, want %s", i, got[i].Ref.Version, w)
		}
	}
	if got := Window(list, ref("1.3.0"), 2); len(got) != 2 || got[0].Ref.Version != "0.9.9" || got[1].Ref.Version != "1.2.0" {
		t.Errorf("Window(n=2) = %v", got)
	}
	if got := Window(list, ref("1.3.0"), 0); got != nil {
		t.Errorf("Window(n=0) = %v, want nil", got)
	}
	if got := Window(nil, ref("1.3.0"), 3); got != nil {
		t.Errorf("Window(nil) = %v, want nil", got)
	}
}

func TestLatestStable(t *testing.T) {
	list := sample()
	if got := LatestStable(list); got == nil || got.Ref.Version != "1.3.0" {
		t.Fatalf("LatestStable with a registry latest = %v", got)
	}
	// A prerelease or yanked "latest" is ignored and the highest stable version wins by version order.
	list.Latest = "2.0.0-beta.1"
	if got := LatestStable(list); got == nil || got.Ref.Version != "1.4.0" {
		t.Fatalf("LatestStable without a usable registry latest = %v, want 1.4.0", got)
	}
	list.Latest = "1.1.1"
	if got := LatestStable(list); got == nil || got.Ref.Version != "1.4.0" {
		t.Fatalf("LatestStable with a yanked registry latest = %v, want 1.4.0", got)
	}
	only := &VersionList{Ecosystem: model.NPM, Versions: []model.VersionInfo{v("1.0.0-rc.1", 0, true, false, "")}}
	if got := LatestStable(only); got != nil {
		t.Fatalf("LatestStable with only prereleases = %v, want nil", got)
	}
	if got := LatestStable(nil); got != nil {
		t.Fatal("LatestStable(nil) must be nil")
	}
}

func TestFind(t *testing.T) {
	list := sample()
	if got := Find(list, "1.2.0"); got == nil || got.Publisher.Name != "alice" {
		t.Fatalf("Find(1.2.0) = %v", got)
	}
	if Find(list, "nope") != nil || Find(nil, "1.0.0") != nil {
		t.Fatal("Find must return nil for unknown versions and nil lists")
	}
}
