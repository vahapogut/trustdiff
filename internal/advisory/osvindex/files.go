package osvindex

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/vahapogut/trustdiff/internal/model"
)

// indexFileName matches every file this package writes into an ecosystem
// directory: the metadata, the shards, the archive a refresh streams to disk
// before reading it, and the temporary files os.CreateTemp creates for all of
// them before they are renamed into place (a decimal suffix, see os.CreateTemp).
// Clear removes nothing else, which is how a mistyped cache directory keeps its
// contents, and it removes the archive so an interrupted refresh does not leave
// a few hundred megabytes behind.
var indexFileName = regexp.MustCompile(`^((meta|[0-9a-f]{2})\.json|archive\.zip)(\.[0-9]+\.tmp)?$`)

// archiveTempName is the base name a downloaded archive is given while it is
// being read. It always carries a .tmp suffix on disk and never survives a
// refresh, successful or not.
const archiveTempName = "archive.zip"

// writeFileAtomic writes data to a temporary file in dir and renames it over
// name, so a reader sees either the old shard or the new one, never a partial
// file. The data is synced before the rename: the rename alone protects against
// a process crash, but after a power loss the file system may have made the
// rename durable before the data, leaving a truncated file under a valid name.
// It is the same discipline internal/httpcache uses for cache entries.
func writeFileAtomic(dir, name string, data []byte) error {
	tmp, err := os.CreateTemp(dir, name+".*.tmp")
	if err != nil {
		return fmt.Errorf("osvindex: creating a temporary file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	cleanup := func(cause error) error {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return cause
	}
	if _, err := tmp.Write(data); err != nil {
		return cleanup(fmt.Errorf("osvindex: writing %s: %w", tmpName, err))
	}
	if err := tmp.Sync(); err != nil {
		return cleanup(fmt.Errorf("osvindex: syncing %s: %w", tmpName, err))
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("osvindex: closing %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, filepath.Join(dir, name)); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("osvindex: renaming %s: %w", tmpName, err)
	}
	return nil
}

// removeIfPresent removes path and reports whether it was there. A file that
// disappeared in the meantime is not an error.
func removeIfPresent(path string) (bool, error) {
	err := os.Remove(path)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, os.ErrNotExist):
		return false, nil
	default:
		return false, fmt.Errorf("osvindex: removing %s: %w", path, err)
	}
}

// Clear removes the advisory index under a cache directory and leaves the cache
// directory itself alone. It never removes a file this package would not have
// written: anything else is kept, together with the directories that lead to it,
// and Clear returns ErrForeignFiles naming every one of them, so a cache
// directory the user mistyped never loses data.
//
// What it can remove, it removes even when it had to keep something else. A
// person who asks for the cache to be cleared and has one stray file under the
// index gets the index cleared and the stray file named, not a cache that is
// still entirely there:
// refusing the whole operation over one file leaves hundreds of megabytes behind
// and gives no way forward except deleting the directory by hand. Every file this
// package owns is one refresh away from coming back, which is what makes removing
// them the safe half of the answer.
//
// "trustdiff cache clear" calls this before internal/httpcache's Clear, which
// refuses any subdirectory it does not know by name and would otherwise report
// the index directory itself as a foreign file.
func Clear(cacheDir string) error {
	root := filepath.Join(cacheDir, Subdir)
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("osvindex: reading %s: %w", root, err)
	}
	var foreign []string
	for _, e := range entries {
		if !e.IsDir() || e.Name() != sourceDir {
			foreign = append(foreign, fmt.Sprintf("%s contains %q", root, e.Name()))
		}
	}
	source := filepath.Join(root, sourceDir)
	kept, err := clearSource(source)
	if err != nil {
		return err
	}
	foreign = append(foreign, kept...)
	if len(foreign) == 0 {
		// Both levels are ours and empty now, so the directories go too.
		if _, err := removeIfPresent(source); err != nil {
			return err
		}
		if _, err := removeIfPresent(root); err != nil {
			return err
		}
		return nil
	}
	return fmt.Errorf("%w: %s", ErrForeignFiles, strings.Join(foreign, "; "))
}

// clearSource empties the OSV level of the index, one ecosystem directory at a
// time, and returns a description of everything it kept because this package did
// not write it. A directory that is not an ecosystem is left untouched, contents
// and all: it is not ours to look inside, let alone to delete.
func clearSource(source string) ([]string, error) {
	ecosystems, err := os.ReadDir(source)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("osvindex: reading %s: %w", source, err)
	}
	var foreign []string
	for _, e := range ecosystems {
		if !e.IsDir() || !known(e.Name()) {
			foreign = append(foreign, fmt.Sprintf("%s contains %q", source, e.Name()))
			continue
		}
		dir := filepath.Join(source, e.Name())
		kept, err := clearEcosystem(dir)
		if err != nil {
			return nil, err
		}
		foreign = append(foreign, kept...)
	}
	return foreign, nil
}

// clearEcosystem removes the index files of one ecosystem directory and returns a
// description of every entry it kept. The directory itself survives when
// something was kept, since it is the only thing holding it.
func clearEcosystem(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("osvindex: reading %s: %w", dir, err)
	}
	var foreign []string
	for _, e := range entries {
		if e.IsDir() || !indexFileName.MatchString(e.Name()) {
			foreign = append(foreign, fmt.Sprintf("%s contains %q", dir, e.Name()))
			continue
		}
		if _, err := removeIfPresent(filepath.Join(dir, e.Name())); err != nil {
			return nil, err
		}
	}
	if len(foreign) > 0 {
		return foreign, nil
	}
	if _, err := removeIfPresent(dir); err != nil {
		return nil, err
	}
	return nil, nil
}

// known reports whether a directory name is one of the ecosystems this package
// indexes. It is deliberately narrow: a directory under the OSV index that is
// not an ecosystem is foreign, not ours to delete.
func known(name string) bool {
	for _, eco := range model.Ecosystems() {
		if string(eco) == name {
			return true
		}
	}
	return false
}

// dirBytes sums the size of every file this package owns under an ecosystem
// directory. A file that vanished between the listing and the stat is ignored.
func dirBytes(dir string) (int64, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("osvindex: reading %s: %w", dir, err)
	}
	var total int64
	for _, e := range entries {
		if e.IsDir() || !indexFileName.MatchString(e.Name()) || strings.HasSuffix(e.Name(), ".tmp") {
			continue
		}
		info, err := e.Info()
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return 0, fmt.Errorf("osvindex: reading %s: %w", filepath.Join(dir, e.Name()), err)
		}
		total += info.Size()
	}
	return total, nil
}
