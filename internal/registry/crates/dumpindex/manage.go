package dumpindex

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

var tempMetadata = regexp.MustCompile(`^current-[0-9]+\.tmp$`)

// Stats describes all installed generations as well as the current snapshot.
// Error reports corrupt metadata without hiding the occupied disk space.
type Stats struct {
	Dir   string `json:"dir"`
	Bytes int64  `json:"bytes"`
	Meta  *Meta  `json:"meta,omitempty"`
	Error string `json:"error,omitempty"`
}

// Stat counts recognized files without following symlinks.
func Stat(cacheDir string) (Stats, error) {
	s := Stats{Dir: Dir(cacheDir)}
	files, _, err := ownedFiles(s.Dir, false)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	for _, file := range files {
		info, err := os.Lstat(file)
		if err != nil {
			return s, err
		}
		s.Bytes += info.Size()
	}
	m, err := ReadMeta(cacheDir)
	if err == nil {
		s.Meta = m
	} else if !errors.Is(err, os.ErrNotExist) {
		s.Error = err.Error()
	}
	return s, nil
}

// Clear removes only recognized files after inspecting the entire tree. An
// active refresh, a symlink or an unfamiliar file refuses deletion altogether.
func Clear(cacheDir string) error {
	dir := Dir(cacheDir)
	if err := realDir(dir); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	lockPath := filepath.Join(dir, "refresh.lock")
	// #nosec G304 -- the lock has a fixed name inside the checked cache directory; O_EXCL rejects links.
	lock, err := os.OpenFile(lockPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("crates dump clear lock (a refresh may be running): %w", err)
	}
	_ = lock.Close()
	defer os.Remove(lockPath)
	files, dirs, err := ownedFiles(dir, true)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, file := range files {
		if err := os.Remove(file); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	for _, sub := range dirs {
		if err := os.Remove(sub); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	// Keep the empty reserved parent: removing it after releasing the lock
	// would race another refresh acquiring a new lock in that directory.
	return nil
}

func ownedFiles(dir string, locked bool) (files, dirs []string, err error) {
	if err := realDir(dir); err != nil {
		return nil, nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, err
	}
	for _, e := range entries {
		name := e.Name()
		if locked && name == "refresh.lock" {
			continue
		}
		full := filepath.Join(dir, name)
		if e.Type()&os.ModeSymlink != 0 {
			return nil, nil, fmt.Errorf("crates dump refuses symlink %s", full)
		}
		switch {
		case e.IsDir() && generationName.MatchString(name):
			children, err := os.ReadDir(full)
			if err != nil {
				return nil, nil, err
			}
			for _, child := range children {
				if !child.Type().IsRegular() || !shardName.MatchString(child.Name()) {
					return nil, nil, fmt.Errorf("crates dump refuses foreign file %s", filepath.Join(full, child.Name()))
				}
				files = append(files, filepath.Join(full, child.Name()))
			}
			dirs = append(dirs, full)
		case e.Type().IsRegular() && (name == "current.json" || tempMetadata.MatchString(name)):
			files = append(files, full)
		default:
			return nil, nil, fmt.Errorf("crates dump refuses foreign file or active refresh %s", full)
		}
	}
	return files, dirs, nil
}
