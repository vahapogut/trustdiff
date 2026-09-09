package baseline

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/vahapogut/trustdiff/internal/model"
)

// ErrWrongSchema is returned for a document whose schema field is not SchemaID.
// It is its own error because a file written by a later trustdiff is a reason to
// stop rather than a file to repair: overwriting it would throw away records the
// running binary cannot read.
var ErrWrongSchema = errors.New("not a trustdiff baseline of schema version 1")

// Path is where a project's baseline lives under dir.
func Path(dir string) string { return filepath.Join(dir, DirName, FileName) }

// Find looks for a baseline: DirName/FileName in startDir and then in each parent
// up to the root, the way the policy file is found, so that a command run in a
// package of a monorepo uses the baseline of the repository. found is false when
// there is none; err reports an I/O problem other than a missing file.
//
// There is no user-level fallback. A policy is a person's preference and may live
// in a home directory; a baseline is a record of this project's dependencies and
// belongs in this project, committed beside them.
func Find(startDir string) (path string, found bool, err error) {
	dir, err := filepath.Abs(startDir)
	if err != nil {
		return "", false, fmt.Errorf("resolve %q: %w", startDir, err)
	}
	for {
		candidate := Path(dir)
		info, err := os.Stat(candidate)
		switch {
		case err == nil && !info.IsDir():
			return candidate, true, nil
		case err != nil && !errors.Is(err, fs.ErrNotExist):
			return "", false, fmt.Errorf("stat %s: %w", candidate, err)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false, nil
		}
		dir = parent
	}
}

// Load reads and validates the baseline at path. A file that is not there is
// reported with fs.ErrNotExist, which the caller takes as a project that has no
// baseline yet rather than as a failure.
func Load(path string) (*File, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- the path is the project's own baseline, found upward from the working directory or named by the caller
	if err != nil {
		return nil, err
	}
	f, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.ToSlash(path), err)
	}
	return f, nil
}

// Parse decodes and validates a baseline document. It is what Load uses and what
// AtRevision uses for the bytes a git revision holds, so a baseline committed by
// another machine is validated exactly like one on this one.
//
// Unknown fields are refused rather than ignored: the schema says
// additionalProperties false, and a field this binary does not know is either a
// document from a later version or a typo in a hand edit, and reading past either
// would silently drop what someone meant to record.
func Parse(data []byte) (*File, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var f File
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("decode the baseline: %w", err)
	}
	if f.Schema != SchemaID {
		return nil, fmt.Errorf("%w: schema is %q, want %q", ErrWrongSchema, f.Schema, SchemaID)
	}
	seen := make(map[model.PackageRef]int, len(f.Packages))
	for i := range f.Packages {
		e := &f.Packages[i]
		if err := e.validate(i); err != nil {
			return nil, err
		}
		e.normalize()
		pkg := e.Package()
		if first, dup := seen[pkg]; dup {
			return nil, fmt.Errorf("packages[%d]: %s is already recorded at packages[%d]", i, pkg, first)
		}
		seen[pkg] = i
	}
	f.UpdatedAt = f.UpdatedAt.UTC().Truncate(time.Second)
	// The file on disk may have been sorted by a hand edit or by an older binary;
	// what this process serves and writes is always in the documented order.
	f.sort()
	return &f, nil
}

// Bytes renders the file the way Write stores it: two-space indentation, keys in
// field order, a trailing newline and no HTML escaping, which is what the report
// writer does too. Entries are sorted first, so the bytes depend on what the file
// holds and not on the order the caller put things in.
func Bytes(f *File) ([]byte, error) {
	if f.Schema == "" {
		f.Schema = SchemaID
	}
	if f.Packages == nil {
		// A project that locks nothing writes an empty list, never null: the schema
		// says packages is an array, and a consumer must not have to test for both.
		f.Packages = []Entry{}
	}
	f.UpdatedAt = f.UpdatedAt.UTC().Truncate(time.Second)
	f.sort()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(f); err != nil {
		return nil, fmt.Errorf("encode the baseline: %w", err)
	}
	return buf.Bytes(), nil
}

// Write stores the file at path, creating the directory when it is missing.
//
// The write is atomic: the bytes go to a temporary file in the same directory and
// are then renamed over the target, so a run that is interrupted leaves the
// previous record whole instead of half a document. The temporary file is removed
// when anything fails, and the rename is what makes the new content visible, on
// Windows as on Unix.
func Write(path string, f *File) error {
	data, err := Bytes(f)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create directory for %s: %w", filepath.ToSlash(path), err)
	}
	tmp, err := os.CreateTemp(dir, "."+FileName+".*")
	if err != nil {
		return fmt.Errorf("create a temporary file beside %s: %w", filepath.ToSlash(path), err)
	}
	name := tmp.Name()
	// The baseline is committed and read by everyone who reads the repository, so
	// it carries the mode of a source file rather than of a secret. CreateTemp
	// makes it 0600, which would leave a file nobody else can read behind.
	if err := chmodBaseline(tmp, name); err != nil {
		return cleanUp(tmp, name, err)
	}
	if _, err := tmp.Write(data); err != nil {
		return cleanUp(tmp, name, fmt.Errorf("write %s: %w", filepath.ToSlash(path), err))
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("write %s: %w", filepath.ToSlash(path), err)
	}
	if err := os.Rename(name, path); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("replace %s: %w", filepath.ToSlash(path), err)
	}
	return nil
}

// chmodBaseline gives the temporary file the mode a committed file has. On
// Windows the call is a no-op in practice, which is why its failure is not worth
// reporting on its own; everywhere else it is what keeps the file readable.
func chmodBaseline(tmp *os.File, name string) error {
	if err := tmp.Chmod(0o644); err != nil { // #nosec G302 -- a baseline is committed and read by everyone who reads the repository
		return fmt.Errorf("set the mode of %s: %w", filepath.ToSlash(name), err)
	}
	return nil
}

// cleanUp closes and removes the temporary file and returns the failure that led
// here, so a caller never has to remember both.
func cleanUp(tmp *os.File, name string, err error) error {
	_ = tmp.Close()
	_ = os.Remove(name)
	return err
}
