package doctor

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// configLimit is how much of a configuration file is read. These files are a few
// hundred bytes in every real project, and a scan must not be made to allocate
// whatever a repository committed under one of these names.
const configLimit = 4 << 20

// errNotRegular is what reading anything but a plain file returns, so a caller can
// tell it apart from a file that is simply not there.
var errNotRegular = errors.New("not a regular file")

// readConfig reads a configuration file, and only if it is a plain file.
//
// A repository in a pull request decides what its files are, and git records a
// symbolic link as a blob holding the link text, so a fork can commit .npmrc as a
// link to any path on the runner. Following it would put whatever that file holds
// into the scorecard, and a fix would write into it. The lockfile side of this tool
// refuses a link for the same reason; this is the doctor side of that rule.
//
// The file is also read through a limited reader rather than whole, because the
// name says nothing about the size.
func readConfig(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s", errNotRegular, describeMode(info.Mode()))
	}
	f, err := os.Open(path) // #nosec G304 -- the path is a configuration file under the directory the user named, and Lstat above has refused everything that is not a plain file
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // nothing was written, so a close error says nothing a caller could act on

	data, err := io.ReadAll(io.LimitReader(f, configLimit+1))
	if err != nil {
		return nil, err
	}
	if len(data) > configLimit {
		return nil, fmt.Errorf("larger than %d bytes, which no configuration file of these formats is", configLimit)
	}
	return data, nil
}

// describeMode words what a path turned out to be, so the reason names it.
func describeMode(mode os.FileMode) string {
	switch {
	case mode.IsDir():
		return "a directory"
	case mode&os.ModeSymlink != 0:
		return "a symbolic link"
	case mode&os.ModeNamedPipe != 0:
		return "a named pipe"
	case mode&os.ModeDevice != 0:
		return "a device"
	}
	return "not a plain file"
}
