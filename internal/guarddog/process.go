package guarddog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"
)

const (
	maxStdout = 4 << 20
	maxStderr = 64 << 10
)

var errOutputLimit = errors.New("GuardDog process output exceeded its limit")

type boundedOutput struct {
	buf      bytes.Buffer
	limit    int
	exceeded bool
	cancel   context.CancelFunc
}

func (w *boundedOutput) Write(p []byte) (int, error) {
	if len(p) > w.limit-w.buf.Len() {
		w.exceeded = true
		w.cancel()
		return 0, errOutputLimit
	}
	return w.buf.Write(p)
}

func (c *Client) run(ctx context.Context, args ...string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp("", "trustdiff-guarddog-")
	if err != nil {
		return nil, fmt.Errorf("create GuardDog working directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	work, scratch := filepath.Join(dir, "work"), filepath.Join(dir, "scratch")
	for _, path := range []string{work, scratch} {
		if err := os.Mkdir(path, 0o700); err != nil {
			return nil, fmt.Errorf("create GuardDog directory: %w", err)
		}
	}
	processCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stdout := &boundedOutput{limit: maxStdout, cancel: cancel}
	stderr := &boundedOutput{limit: maxStderr, cancel: cancel}
	// The executable is explicitly configured and resolved by New. Every argument
	// is a fixed flag or a validated registry identity; no shell is involved.
	cmd := exec.CommandContext(processCtx, c.binary, args...) // #nosec G204 -- explicit external scanner, validated argv
	cmd.Dir = work
	cmd.Env = append(os.Environ(), "TMPDIR="+scratch, "TMP="+scratch, "TEMP="+scratch)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.WaitDelay = time.Second
	configureProcess(cmd)
	err = cmd.Run()
	// Include helpers still running after the scanner exits, not just its parent.
	stopProcessGroup(cmd)
	if stdout.exceeded || stderr.exceeded {
		return nil, errOutputLimit
	}
	if ctx.Err() != nil {
		return nil, fmt.Errorf("GuardDog process interrupted: %w", ctx.Err())
	}
	if err != nil {
		diagnostic := safeDiagnostic(normalizeTempPaths(stderr.buf.String(), dir))
		if diagnostic != "" {
			return nil, fmt.Errorf("GuardDog process failed: %w: %s", err, diagnostic)
		}
		return nil, fmt.Errorf("GuardDog process failed: %w", err)
	}
	return []byte(normalizeTempPaths(stdout.buf.String(), dir)), nil
}

// GuardDog creates another tempfile directory beneath the supplied private temp
// root. Normalize both owned paths before cleanup so repeated watch scans retain
// stable diagnostics, including download errors without a top-level report.path.
// Do not touch arbitrary user paths or package code unrelated to these roots.
func normalizeTempPaths(value, root string) string {
	encoded, _ := json.Marshal(root)
	for _, prefix := range []string{root, string(encoded[1 : len(encoded)-1])} {
		temporary := regexp.MustCompile(regexp.QuoteMeta(prefix) + `/scratch/tmp[A-Za-z0-9_-]+`)
		value = temporary.ReplaceAllString(value, "<guarddog-temp>/scratch/<scan>")
		value = strings.ReplaceAll(value, prefix, "<guarddog-temp>")
	}
	return value
}

func safeDiagnostic(value string) string {
	if len(value) > 4096 {
		value = value[:4096] + " (truncated)"
	}
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, value))
}
