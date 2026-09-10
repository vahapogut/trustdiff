package gitdiff

import (
	"github.com/vahapogut/trustdiff/internal/lockfile"
	"github.com/vahapogut/trustdiff/internal/model"
)

// Change is one package both lockfiles lock, at a different version or from a
// different place.
type Change struct {
	// Base is the entry the base revision locked. The report compares against it,
	// and it is the "previous version in the base lockfile" of brief section 4.1.
	Base lockfile.Entry
	// Head is the entry the working tree locks. This is the version the checks
	// evaluate.
	Head lockfile.Entry
}

// Changes is what a lockfile change did. Added and Changed are the entries the
// diff command evaluates; Removed is reported and never fetched.
type Changes struct {
	// Added are the entries only the head lockfile has, in its order.
	Added []lockfile.Entry
	// Changed are the entries both files have at a different version, or at the
	// same version from a different source or under a different hash, in head
	// order.
	Changed []Change
	// Removed are the entries only the base lockfile had, in its order.
	Removed []lockfile.Entry
}

// Empty reports whether the two lockfiles lock the same set of versions.
func (c Changes) Empty() bool {
	return len(c.Added) == 0 && len(c.Changed) == 0 && len(c.Removed) == 0
}

// Diff reports what changed between the lockfile at the base revision and the
// one in the working tree, matching entries by ecosystem and name so that a
// version bump reads as one change rather than as a removal and an addition.
// Either side may be nil: a lockfile the change adds has no base, and one it
// deletes has no head.
//
// Within one name, versions both files lock are matched first, so a file that
// locks the same package at several versions, which npm does routinely, reports
// only the version that moved. Within one version, a copy is matched with the copy
// of itself that installs the same artifact. What is left over is paired in file
// order, and the remainder is added or removed.
//
// An entry at the same version counts as changed when its source or its
// integrity hash differs. TD013 and TD014 judge the entry as it stands, an
// exotic source and a missing hash; TD016 is the one that reads both sides and
// says the version stayed while the hash, the source or the location moved.
//
// The resolved location is compared for every entry the ecosystem's own registry
// does not serve. For a registry entry it is ignored, because moving a project to
// a mirror rewrites every one of them and changes nothing about the packages that
// are installed. For a git, url or path entry it is the identity of what gets
// installed: the same version repointed at another repository, another tarball or
// another directory installs other code, and nothing else in the entry says so.
//
// Lines that install one artifact are one entry, the first of them, and the
// package counts as direct if any of them is; lines that disagree about the
// artifact are entries of their own, each matched with the copy of itself on the
// other side, so a change that repoints one copy and leaves the other alone is one
// change and not a change to both. internal/lockfile.Installs decides which lines
// are which.
func Diff(base, head *lockfile.Lockfile) Changes {
	baseEntries := base.Installs()
	headEntries := head.Installs()

	byVersion := make(map[versionKey][]int, len(baseEntries))
	byName := make(map[key][]int, len(baseEntries))
	for i := range baseEntries {
		e := &baseEntries[i]
		vk := versionKeyOf(e)
		byVersion[vk] = append(byVersion[vk], i)
		k := keyOf(e)
		byName[k] = append(byName[k], i)
	}

	// partner[i] is the base entry the head entry i corresponds to, or -1 when the
	// head entry is new; taken marks the base entries already spoken for. The three
	// passes go from the most certain pairing to the least, and each takes only what
	// the one before it left, so a copy that did not move is claimed by itself before
	// a copy that did can reach for it.
	partner := make([]int, len(headEntries))
	taken := make([]bool, len(baseEntries))
	for i := range headEntries {
		partner[i] = -1
	}
	// A version the base locks at more than one place has one entry per artifact, so
	// the base copy that installs the same thing is the one this head entry is a later
	// reading of. Without this a change touching one copy would read as a change to
	// the other and a removal of this one.
	for i := range headEntries {
		if j, ok := twinOf(baseEntries, byVersion[versionKeyOf(&headEntries[i])], taken, &headEntries[i]); ok {
			partner[i] = j
			taken[j] = true
		}
	}
	// What is left over at one version is paired in file order: two copies that both
	// moved are still one pair each.
	for i := range headEntries {
		if partner[i] >= 0 {
			continue
		}
		if j, ok := nextFree(byVersion[versionKeyOf(&headEntries[i])], taken); ok {
			partner[i] = j
			taken[j] = true
		}
	}
	// A head entry with no twin at its own version takes the next entry of the
	// same name the base still has: that pair is the version bump.
	for i := range headEntries {
		if partner[i] >= 0 {
			continue
		}
		if j, ok := nextFree(byName[keyOf(&headEntries[i])], taken); ok {
			partner[i] = j
			taken[j] = true
		}
	}

	changes := Changes{}
	for i := range headEntries {
		h := &headEntries[i]
		j := partner[i]
		if j < 0 {
			changes.Added = append(changes.Added, *h)
			continue
		}
		b := &baseEntries[j]
		if !lockfile.SameArtifact(b, h) {
			changes.Changed = append(changes.Changed, Change{Base: *b, Head: *h})
		}
	}
	for i := range baseEntries {
		if !taken[i] {
			changes.Removed = append(changes.Removed, baseEntries[i])
		}
	}
	return changes
}

// key identifies a package across the two files: the ecosystem and the name,
// never the version, so that a bump matches instead of looking like a swap.
type key struct {
	ecosystem model.Ecosystem
	name      string
}

// versionKey is the key of one exact locked version.
type versionKey struct {
	key
	version string
}

func keyOf(e *lockfile.Entry) key {
	return key{ecosystem: e.Ref.Ecosystem, name: e.Ref.Name}
}

func versionKeyOf(e *lockfile.Entry) versionKey {
	return versionKey{key: keyOf(e), version: e.Ref.Version}
}

// twinOf returns the base entry among these candidates that installs the same
// artifact as the head entry and nothing has claimed yet.
func twinOf(baseEntries []lockfile.Entry, candidates []int, taken []bool, h *lockfile.Entry) (int, bool) {
	for _, i := range candidates {
		if !taken[i] && lockfile.SameArtifact(&baseEntries[i], h) {
			return i, true
		}
	}
	return 0, false
}

// nextFree returns the first of these base entries that nothing has claimed yet.
func nextFree(candidates []int, taken []bool) (int, bool) {
	for _, i := range candidates {
		if !taken[i] {
			return i, true
		}
	}
	return 0, false
}
