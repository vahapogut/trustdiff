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
// only the version that moved. What is left over is paired in file order, and
// the remainder is added or removed.
//
// An entry at the same version counts as changed when its source or its
// integrity hash differs: swapping a registry download for a git revision or
// dropping the hash is what TD013 and TD014 exist to catch. The resolved URL on
// its own is not compared, because moving a project to a registry mirror
// rewrites every one of them and changes nothing about the packages.
//
// Entries repeating one exact version are collapsed into the first of them, the
// one the earliest line mentions, and the package counts as direct if any of
// them is.
func Diff(base, head *lockfile.Lockfile) Changes {
	baseEntries := normalize(base)
	headEntries := normalize(head)

	byVersion := make(map[versionKey]int, len(baseEntries))
	byName := make(map[key][]int, len(baseEntries))
	for i := range baseEntries {
		e := &baseEntries[i]
		byVersion[versionKeyOf(e)] = i
		k := keyOf(e)
		byName[k] = append(byName[k], i)
	}

	// partner[i] is the base entry the head entry i corresponds to, or -1 when the
	// head entry is new; taken marks the base entries already spoken for.
	partner := make([]int, len(headEntries))
	taken := make([]bool, len(baseEntries))
	pending := make([]int, 0, len(headEntries))
	for i := range headEntries {
		partner[i] = -1
		if j, ok := byVersion[versionKeyOf(&headEntries[i])]; ok {
			partner[i] = j
			taken[j] = true
			continue
		}
		pending = append(pending, i)
	}
	// A head entry with no twin at its own version takes the next entry of the
	// same name the base still has: that pair is the version bump.
	for _, i := range pending {
		j, ok := nextFree(byName[keyOf(&headEntries[i])], taken)
		if !ok {
			continue
		}
		partner[i] = j
		taken[j] = true
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
		if b.Ref.Version != h.Ref.Version || b.Source != h.Source || b.Integrity != h.Integrity {
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

// normalize copies the file's entries in order, fills in the ecosystem from the
// file for a format that states it once, and collapses entries repeating one
// exact version into the first of them.
func normalize(lf *lockfile.Lockfile) []lockfile.Entry {
	if lf == nil {
		return nil
	}
	seen := make(map[versionKey]int, len(lf.Entries))
	out := make([]lockfile.Entry, 0, len(lf.Entries))
	for i := range lf.Entries {
		e := lf.Entries[i]
		if e.Ref.Ecosystem == "" {
			e.Ref.Ecosystem = lf.Ecosystem
		}
		vk := versionKeyOf(&e)
		if j, ok := seen[vk]; ok {
			if e.Direct {
				out[j].Direct = true
			}
			continue
		}
		seen[vk] = len(out)
		out = append(out, e)
	}
	return out
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
