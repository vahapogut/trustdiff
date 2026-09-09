package baseline

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// sizeLimit is how much of a baseline is read. A project of five thousand
// packages writes about a megabyte and a half, so this leaves room for one many
// times larger while keeping a run from allocating whatever a repository
// committed under the name.
const sizeLimit = 8 << 20

// Load reads and validates the baseline at path. A file that is not there is
// reported with fs.ErrNotExist, which the caller takes as a project that has no
// baseline yet rather than as a failure.
//
// Only a plain file is read. A repository in a pull request decides what its
// files are and git records a symbolic link as a blob holding the link text, so a
// fork can commit .trustdiff/baseline.json as a link to any path on the runner;
// following it would put whatever that file holds into the comparison the gate
// rests on. internal/cli/lockfiles.go refuses a link for a lockfile and
// internal/doctor/read.go refuses one for a configuration file, both for this
// reason, and this is the same rule for the record itself.
func Load(path string) (*File, error) {
	name := filepath.ToSlash(path)
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file, so not a baseline trustdiff reads", name)
	}
	file, err := os.Open(path) // #nosec G304 -- the path is the project's own baseline, found upward from the working directory or named by the caller, and Lstat above has refused everything that is not a plain file
	if err != nil {
		return nil, err
	}
	// Nothing was written, so a close error says nothing a caller could act on.
	defer func() { _ = file.Close() }()

	data, err := io.ReadAll(io.LimitReader(file, sizeLimit+1))
	if err != nil {
		return nil, err
	}
	if len(data) > sizeLimit {
		return nil, fmt.Errorf("%s: larger than %d bytes, which no baseline is", name, sizeLimit)
	}
	f, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
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
	// Everything after the first value is refused rather than read past, the way
	// internal/policy refuses a second YAML document. A document with a second one
	// appended, or with anything at all after it, was written by something nobody
	// meant to run, and bytes no parser looked at are bytes no reviewer looked at.
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("decode the baseline: data follows the document")
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
// What it replaces must be a plain file. Following a symbolic link would write
// the project's record wherever the link points, which is a path a pull request
// gets to choose, and renaming over one would silently turn a link the project
// meant to keep into a regular file. Load refuses to read a link for the same
// reason.
//
// The bytes go to a temporary file in the same directory, are flushed to the
// disk, and the temporary file is then renamed over the target, on Windows as on
// Unix. What that guarantees is that no reader ever sees half a document and that
// a run which is interrupted or crashes leaves either the previous record or the
// new one, whole. What it does not guarantee is which of the two a crash leaves:
// the directory entry the rename changed is not flushed, so a machine that loses
// power in the moment after the rename may come back to the previous record. That
// is a run to repeat, not a file to repair. The temporary file is removed when
// anything fails.
func Write(path string, f *File) error {
	data, err := Bytes(f)
	if err != nil {
		return err
	}
	switch info, err := os.Lstat(path); {
	case err == nil && !info.Mode().IsRegular():
		return fmt.Errorf("replace %s: not a regular file, so not a baseline trustdiff writes", filepath.ToSlash(path))
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("stat %s: %w", filepath.ToSlash(path), err)
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
	// The bytes are flushed before the rename, because a rename that beats them to
	// the disk is what turns a crash into a file holding the right length and the
	// wrong content.
	if err := syncFile(tmp); err != nil {
		return cleanUp(tmp, name, fmt.Errorf("flush %s: %w", filepath.ToSlash(path), err))
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

// syncFile flushes what has been written to the disk. It is a variable so that a
// test can put a failure where no filesystem will produce one on demand, and so
// that a test can see that the flush happens at all: it is the step that decides
// whether the atomicity in Write's comment survives a crash and not only a killed
// process.
var syncFile = (*os.File).Sync

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
