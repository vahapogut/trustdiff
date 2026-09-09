package policy

import (
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// defaultYAML is the commented policy file that "policy init" writes. Parsing it
// yields exactly Default(); a test enforces that.
//
//go:embed default.yaml
var defaultYAML []byte

// DefaultYAML returns a copy of the commented default policy file.
func DefaultYAML() []byte {
	out := make([]byte, len(defaultYAML))
	copy(out, defaultYAML)
	return out
}

// ErrExists is returned by WriteDefault when the target already exists.
var ErrExists = errors.New("policy file already exists")

// WriteDefault writes the commented default policy to path. It never overwrites: an
// existing file yields ErrExists so a reviewed policy cannot be replaced by accident.
func WriteDefault(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("create directory for %s: %w", path, err)
	}
	// #nosec G304 G302 -- the target is chosen by the user, O_EXCL refuses to overwrite, and a
	// policy file is meant to be committed and read by everyone, so 0644 is the right mode.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%w: %s", ErrExists, path)
		}
		return fmt.Errorf("create %s: %w", path, err)
	}
	if _, err := f.Write(defaultYAML); err != nil {
		_ = f.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
