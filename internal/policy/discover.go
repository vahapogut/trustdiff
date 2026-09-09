package policy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// FileName is the policy file name looked for in the working directory and its parents.
const FileName = ".trustdiff.yaml"

// userConfigPath returns the user-level fallback, $XDG_CONFIG_HOME/trustdiff/policy.yaml.
// XDG_CONFIG_HOME is honored on every platform, not only where os.UserConfigDir reads
// it, so a user who sets it gets the same location everywhere; as the XDG spec says,
// a relative value is ignored. Without it the platform directory from os.UserConfigDir
// is used (~/.config on Linux, Library/Application Support on macOS, AppData/Roaming
// on Windows).
func userConfigPath(getenv func(string) string, userConfigDir func() (string, error)) (string, error) {
	if dir := getenv("XDG_CONFIG_HOME"); dir != "" && filepath.IsAbs(dir) {
		return filepath.Join(dir, "trustdiff", "policy.yaml"), nil
	}
	dir, err := userConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "trustdiff", "policy.yaml"), nil
}

// Find looks for a policy file: FileName in startDir and each parent up to the root,
// then the user-level fallback. found is false when neither exists; err reports an
// I/O problem other than a missing file.
func Find(startDir string) (path string, found bool, err error) {
	return find(startDir, os.Getenv, os.UserConfigDir)
}

func find(startDir string, getenv func(string) string, userConfigDir func() (string, error)) (string, bool, error) {
	dir, err := filepath.Abs(startDir)
	if err != nil {
		return "", false, fmt.Errorf("resolve %q: %w", startDir, err)
	}
	for {
		candidate := filepath.Join(dir, FileName)
		exists, err := fileExists(candidate)
		if err != nil {
			return "", false, err
		}
		if exists {
			return candidate, true, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	fallback, err := userConfigPath(getenv, userConfigDir)
	if err != nil {
		return "", false, nil //nolint:nilerr // no user config dir means no fallback, not a failure
	}
	exists, err := fileExists(fallback)
	if err != nil {
		return "", false, err
	}
	if exists {
		return fallback, true, nil
	}
	return "", false, nil
}

func fileExists(path string) (bool, error) {
	info, err := os.Stat(path)
	switch {
	case err == nil:
		return !info.IsDir(), nil
	case errors.Is(err, os.ErrNotExist):
		return false, nil
	default:
		return false, fmt.Errorf("stat %s: %w", path, err)
	}
}
