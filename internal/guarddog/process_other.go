//go:build !linux && !darwin

package guarddog

import "os/exec"

func supportedHost() bool { return false }

// New refuses these hosts before process creation; these functions only keep
// report types and validation available to all trustdiff build targets.
func configureProcess(_ *exec.Cmd) {}
func stopProcessGroup(_ *exec.Cmd) {}
