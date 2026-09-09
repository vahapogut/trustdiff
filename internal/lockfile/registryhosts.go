package lockfile

import "strings"

// An unknown host counts as the registry a project installs from when it carries a
// real part of the file: at least a tenth of the downloads recorded, and at least
// registryFloor of them whatever the file's size.
//
// The floor is what a share alone cannot do. In a file of two packages an outlier
// serves half of them, so a share test alone calls it the registry and the
// substitution this exists to catch passes. The floor in turn cannot judge a small
// file that installs everything from one private host, where the honest answer is
// that the host is the project's registry. So a host below the floor is still
// accepted when the file names no public registry at all and no other host serves
// more: that is a project wholly on its own registry, not one entry pointed
// elsewhere.
const (
	registryShare = 10
	registryFloor = 3
)

// RegistryHosts tells the registry a project installs from apart from a host one
// entry points at on its own.
//
// A lockfile in a pull request is text the author chose, and a tarball URL is the
// one field an install actually fetches, so "it looks like a registry" cannot be
// decided from the URL alone: a host serving <name>/-/<name>-<version>.tgz is a
// shape anybody can serve. What a substitution cannot fake is agreement with the
// rest of the file. A host is therefore the project's registry when it is one of
// the hosts known to be one, or when it serves more than a quarter of the downloads
// the file records; a lone outlier is not, and the entry is reported as resolved
// from a URL, which is what TD013 exists to show.
//
// The zero value is not usable; start one with NewRegistryHosts.
type RegistryHosts struct {
	known  map[string]bool
	counts map[string]int
	total  int
	// sawKnown is true once a download names a host known to be a registry, which
	// says the project installs from a public registry in this file.
	sawKnown bool
	// largest is the highest count any single host reached.
	largest int
}

// NewRegistryHosts starts a count whose known hosts are always registries. The
// caller keeps ownership of known, which is only read.
func NewRegistryHosts(known map[string]bool) *RegistryHosts {
	return &RegistryHosts{known: known, counts: make(map[string]int)}
}

// NPMRegistryHosts starts a count for an npm lockfile. The two hosts are the ones
// whose tarball URLs do not follow the <name>/-/<file>.tgz layout every other
// registry serves, so no count could recognize them. It lives here because
// package-lock.json and pnpm-lock.yaml both record npm tarball URLs and have to
// answer this the same way. Verified 2026-09-09.
func NPMRegistryHosts() *RegistryHosts {
	return NewRegistryHosts(map[string]bool{
		// The public registry npm and pnpm install from by default.
		"registry.npmjs.org": true,
		// GitHub Packages, whose tarball path is /download/<name>/<version>/<sha>.
		"npm.pkg.github.com": true,
	})
}

// Count records one download the file states, by its host.
func (h *RegistryHosts) Count(host string) {
	host = strings.ToLower(host)
	if host == "" {
		return
	}
	h.counts[host]++
	h.total++
	if h.counts[host] > h.largest {
		h.largest = h.counts[host]
	}
	if h.known[host] {
		h.sawKnown = true
	}
}

// Known reports whether the host is a registry however few entries name it.
func (h *RegistryHosts) Known(host string) bool {
	return h.known[strings.ToLower(host)]
}

// Serves reports whether the host carries enough of the file's downloads to be the
// registry it installs from. A host nothing was counted for never does.
func (h *RegistryHosts) Serves(host string) bool {
	n := h.counts[strings.ToLower(host)]
	switch {
	case n == 0:
		return false
	case n >= registryFloor && n*registryShare >= h.total:
		// A real part of a file large enough to say so.
		return true
	default:
		// Too few to judge by share: accept only the predominant host of a file
		// that names no public registry, which is a project on its own registry.
		return !h.sawKnown && n >= h.largest
	}
}
