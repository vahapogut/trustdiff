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

// Clear removes the whole advisory index under a cache directory and leaves the
// cache directory itself alone. It refuses, with ErrForeignFiles, when the index
// directory holds anything this package would not have written, so a cache
// directory the user mistyped never loses data.
//
// "trustdiff cache clear" calls this before internal/httpcache's Clear, which
// refuses any subdirectory it does not know by name. That ordering means the
// index is gone even if the httpcache pass then refuses over some other file,
// which is the right trade: the index is one download away, and the refusal is
// still reported.
func Clear(cacheDir string) error {
	root := filepath.Join(cacheDir, Subdir)
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("osvindex: reading %s: %w", root, err)
	}
	// Everything is checked before anything is removed, so a refusal leaves the
	// directory exactly as it was.
	for _, e := range entries {
		if !e.IsDir() || e.Name() != sourceDir {
			return fmt.Errorf("%w: %s contains %q", ErrForeignFiles, root, e.Name())
		}
	}
	source := filepath.Join(root, sourceDir)
	ecosystems, err := os.ReadDir(source)
	if err != nil {
		return fmt.Errorf("osvindex: reading %s: %w", source, err)
	}
	files := make(map[string][]string, len(ecosystems))
	for _, e := range ecosystems {
		if !e.IsDir() || !known(e.Name()) {
			return fmt.Errorf("%w: %s contains %q", ErrForeignFiles, source, e.Name())
		}
		dir := filepath.Join(source, e.Name())
		names, err := clearableFiles(dir)
		if err != nil {
			return err
		}
		files[dir] = names
	}
	for dir, names := range files {
		for _, name := range names {
			if _, err := removeIfPresent(filepath.Join(dir, name)); err != nil {
				return err
			}
		}
		if _, err := removeIfPresent(dir); err != nil {
			return err
		}
	}
	if _, err := removeIfPresent(source); err != nil {
		return err
	}
	_, err = removeIfPresent(root)
	return err
}

// clearableFiles lists one ecosystem directory, refusing with ErrForeignFiles
// when it holds anything this package would not have written there.
func clearableFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("osvindex: reading %s: %w", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !indexFileName.MatchString(e.Name()) {
			return nil, fmt.Errorf("%w: %s contains %q", ErrForeignFiles, dir, e.Name())
		}
		names = append(names, e.Name())
	}
	return names, nil
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
