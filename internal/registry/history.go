package registry

import (
	"sort"

	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/model/version"
)

// Find returns the entry for a version, or nil.
func Find(list *VersionList, ver string) *model.VersionInfo {
	if list == nil {
		return nil
	}
	for i := range list.Versions {
		if list.Versions[i].Ref.Version == ver {
			return &list.Versions[i]
		}
	}
	return nil
}

// Previous returns the previous version as brief section 4.1 defines it: the
// non-prerelease, non-yanked version with the latest publish time before the
// evaluated version's publish time. Versions without a publish time are ignored.
// nil when there is none or the evaluated version is unknown.
func Previous(list *VersionList, ref model.PackageRef) *model.VersionInfo {
	history := Window(list, ref, 1)
	if len(history) == 0 {
		return nil
	}
	return &history[0]
}

// Window returns up to n releases published before the evaluated version, newest
// first, excluding prereleases, yanked versions and versions without a publish time.
// It is the lookback of publisher-changed (TD002).
func Window(list *VersionList, ref model.PackageRef, n int) []model.VersionInfo {
	current := Find(list, ref.Version)
	if current == nil || current.PublishedAt.IsZero() || n <= 0 {
		return nil
	}
	var earlier []model.VersionInfo
	for i := range list.Versions {
		v := &list.Versions[i]
		if v.Ref.Version == ref.Version || v.Prerelease || v.Yanked || v.PublishedAt.IsZero() {
			continue
		}
		if v.PublishedAt.Before(current.PublishedAt) {
			earlier = append(earlier, *v)
		}
	}
	sort.SliceStable(earlier, func(i, j int) bool { return earlier[i].PublishedAt.After(earlier[j].PublishedAt) })
	if len(earlier) > n {
		earlier = earlier[:n]
	}
	return earlier
}

// LatestStable returns the version a bare ref resolves to: the registry's own
// latest when it is a stable, non-yanked version, otherwise the highest stable
// non-yanked version by version order. nil when the package has no stable release.
func LatestStable(list *VersionList) *model.VersionInfo {
	if list == nil {
		return nil
	}
	if latest := Find(list, list.Latest); latest != nil && !latest.Prerelease && !latest.Yanked {
		return latest
	}
	var candidates []string
	byVersion := make(map[string]*model.VersionInfo, len(list.Versions))
	for i := range list.Versions {
		v := &list.Versions[i]
		if v.Prerelease || v.Yanked {
			continue
		}
		candidates = append(candidates, v.Ref.Version)
		byVersion[v.Ref.Version] = v
	}
	best, ok := version.LatestStable(list.Ecosystem, candidates)
	if !ok {
		return nil
	}
	return byVersion[best]
}
