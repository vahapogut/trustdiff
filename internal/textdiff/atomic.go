package textdiff

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// backupInfix separates the original name from the timestamp in a backup name.
// It names the tool so that a file left behind by an interrupted run is
// recognizable in a directory listing, and so that a repository can ignore
// "*.trustdiff-backup-*" with one pattern.
const backupInfix = ".trustdiff-backup-"

// backupTimeLayout stamps a backup with the run clock in UTC. It is ISO 8601
// basic format rather than the extended one because the extended one separates
// the time with colons, and a colon cannot appear in a Windows file name: it
// opens an alternate data stream instead, so "config.toml.backup-19:30:00" would
// silently write to a stream of "config.toml.backup-19" rather than to a file.
const backupTimeLayout = "20060102T150405Z"

// ErrNotRegular is returned by Write and Backup when the path names something
// that is not a plain file: a directory, a symbolic link, a device, a pipe. The
// files this package edits live in a repository whose contents a pull request may
// control, so a link planted in the tree must not turn an edit to a lockfile into
// an edit to whatever the link points at. Callers can test for it with
// errors.Is when they want to report the refusal differently from an I/O failure.
var ErrNotRegular = errors.New("not a regular file")

// ErrBackupExists is returned by Backup when the backup name it would use is
// already taken. A backup is only worth having if it holds the bytes from before
// the edit, so a second run within the same second of the clock has to fail
// rather than overwrite the first run's copy with already edited content.
var ErrBackupExists = errors.New("backup file already exists")

// Write replaces the file at path with data, atomically: the bytes go to a
// temporary file in the same directory and are renamed over the original, so an
// interrupted run leaves either the old file or the new one and never half of
// either. The temporary file is created in that same directory rather than in the
// system temporary directory because a rename is only atomic within one file
// system.
//
// An existing file keeps its own permissions and mode is used only when the file
// is being created, so writing to a file somebody made group readable does not
// quietly narrow it. The path is inspected with os.Lstat and anything that is not
// a regular file is refused with ErrNotRegular: Write never follows a symbolic
// link and never replaces one.
func Write(path string, data []byte, mode os.FileMode) error {
	mode, err := writeMode(path, mode)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("creating a temporary file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	if err := writeAll(tmp, data); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	// The mode is set on the temporary file rather than on path after the rename,
	// so that the file never exists under its final name with the wrong mode.
	if err := os.Chmod(tmpName, mode); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("setting the mode of %s: %w", tmpName, err)
	}
	// On Windows os.Rename replaces an existing file, as it does on Unix, but it
	// fails when another process holds the target open, which is common enough on
	// that platform that the failure has to name the file and say what went wrong
	// rather than surface as a bare "Access is denied".
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("replacing %s with %s: %w", path, tmpName, err)
	}
	return nil
}

// Backup copies path to "<path>.trustdiff-backup-<timestamp>" preserving its
// mode, and returns the backup's path. It exists so that a user who dislikes an
// edit trustdiff made can put the file back by hand without needing the file to
// have been committed first.
//
// now is the run clock rather than time.Now so that a test and the pinned demo
// clock produce the same name, which is what makes the recorded demo output and
// the golden files stable. It is used in UTC, so two machines in two time zones
// name the same backup the same way.
//
// An existing backup is never overwritten: that would replace the copy of the
// original with a copy of an already edited file. Backup refuses with
// ErrBackupExists instead. Like Write, it refuses anything that is not a regular
// file with ErrNotRegular.
func Backup(path string, now time.Time) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("inspecting %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("refusing to back up %s (%s): %w", path, kindOf(info.Mode()), ErrNotRegular)
	}
	backup := path + backupInfix + now.UTC().Format(backupTimeLayout)
	if _, err := os.Lstat(backup); err == nil {
		return "", fmt.Errorf("refusing to overwrite %s: %w", backup, ErrBackupExists)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("inspecting %s: %w", backup, err)
	}

	// #nosec G304 -- the path is the file the caller is about to edit, and the
	// os.Lstat above has refused everything that is not a plain file.
	src, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", path, err)
	}
	defer func() { _ = src.Close() }()

	// O_EXCL is the real guard against overwriting a backup; the os.Lstat above
	// only buys a message that names the file instead of an errno.
	// #nosec G304 -- the path is the one above with a fixed suffix appended.
	dst, err := os.OpenFile(backup, os.O_WRONLY|os.O_CREATE|os.O_EXCL, info.Mode().Perm())
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return "", fmt.Errorf("refusing to overwrite %s: %w", backup, ErrBackupExists)
		}
		return "", fmt.Errorf("creating %s: %w", backup, err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		_ = dst.Close()
		_ = os.Remove(backup)
		return "", fmt.Errorf("copying %s to %s: %w", path, backup, err)
	}
	if err := dst.Sync(); err != nil {
		_ = dst.Close()
		_ = os.Remove(backup)
		return "", fmt.Errorf("syncing %s: %w", backup, err)
	}
	if err := dst.Close(); err != nil {
		_ = os.Remove(backup)
		return "", fmt.Errorf("closing %s: %w", backup, err)
	}
	// The mode passed to os.OpenFile is masked by the umask on Unix, so it is set
	// again here to make "preserving its mode" true rather than approximate.
	if err := os.Chmod(backup, info.Mode().Perm()); err != nil {
		_ = os.Remove(backup)
		return "", fmt.Errorf("setting the mode of %s: %w", backup, err)
	}
	return backup, nil
}

// writeMode decides what mode the replacement file should carry and refuses the
// path when it is not something Write may replace. A file that already exists
// keeps its own permission bits; mode applies only to a file being created.
func writeMode(path string, mode os.FileMode) (os.FileMode, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return mode.Perm(), nil
	}
	if err != nil {
		return 0, fmt.Errorf("inspecting %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return 0, fmt.Errorf("refusing to write %s (%s): %w", path, kindOf(info.Mode()), ErrNotRegular)
	}
	return info.Mode().Perm(), nil
}

// writeAll puts data in f and gets it onto the disk, then closes f. The contents
// are synced before the rename that follows, because the rename alone only
// protects against a process dying: after a power loss the file system may have
// made the rename durable before the data, which would leave a truncated file
// under the name of a good one.
func writeAll(f *os.File, data []byte) error {
	name := f.Name()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("writing %s: %w", name, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("syncing %s: %w", name, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("closing %s: %w", name, err)
	}
	return nil
}

// kindOf names what a refused path turned out to be, so the error tells the user
// what to look at instead of only that the path was rejected.
func kindOf(mode os.FileMode) string {
	switch {
	case mode.IsDir():
		return "a directory"
	case mode&os.ModeSymlink != 0:
		return "a symbolic link"
	case mode&os.ModeNamedPipe != 0:
		return "a named pipe"
	case mode&os.ModeSocket != 0:
		return "a socket"
	case mode&os.ModeDevice != 0:
		return "a device"
	case mode&os.ModeIrregular != 0:
		return "an irregular file"
	default:
		return "not a plain file"
	}
}
