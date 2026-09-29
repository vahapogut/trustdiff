// Package guarddog runs an explicitly enabled, separately installed GuardDog
// scanner for exact registry releases and returns attributed supplemental results.
// It never installs a tool or package, invokes a shell, or weakens trust findings.
package guarddog

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/model/version"
)

const (
	// SourceURL identifies the external scanner, separately from trustdiff checks.
	SourceURL = "https://github.com/DataDog/guarddog"
	// SupportedVersion pins the reviewed sandbox and JSON contract. Verified
	// 2026-09-29 at upstream commit 3da172679cb58b1c9a780f9f5d640f855be016dc.
	SupportedVersion = "3.2.0"
	// DefaultTimeout includes the version probe and scan for one package.
	DefaultTimeout = 2 * time.Minute
	// MaxPackages caps external scans per client, including failed attempts.
	MaxPackages = 20
)

// Options enables the external executable without downloading or installing it.
type Options struct {
	Binary  string
	Timeout time.Duration
	Offline bool
}

// Result is an attributed supplement, not a trustdiff finding.
type Result = model.Analysis

// Risk retains an upstream risk description without duplicating source snippets.
type Risk = model.AnalysisRisk

// Client serializes scans, checks the executable version once, and enforces a
// total package limit. Its public methods are safe for concurrent callers.
type Client struct {
	binary  string
	timeout time.Duration
	gate    chan struct{}
	version string
	scans   int
}

// New validates configuration without starting a process. Offline and unsupported
// platforms fail before executable lookup. Binary defaults to guarddog on PATH.
func New(opts Options) (*Client, error) {
	if opts.Offline {
		return nil, errors.New("GuardDog requires network access and cannot run in offline mode")
	}
	if opts.Timeout < 0 || opts.Timeout > 30*time.Minute {
		return nil, errors.New("GuardDog timeout must be positive and at most 30 minutes")
	}
	if !supportedHost() {
		return nil, errors.New("GuardDog handoff requires Linux or macOS with sandbox support; on Windows run trustdiff and GuardDog inside a supported Linux environment")
	}
	if opts.Timeout == 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.Binary == "" {
		opts.Binary = "guarddog"
	}
	binary, err := exec.LookPath(opts.Binary)
	if err != nil {
		return nil, fmt.Errorf("find GuardDog executable: install GuardDog %s separately or set --guarddog-bin: %w", SupportedVersion, err)
	}
	binary, err = filepath.Abs(binary)
	if err != nil {
		return nil, fmt.Errorf("resolve GuardDog executable: %w", err)
	}
	return &Client{binary: binary, timeout: opts.Timeout, gate: make(chan struct{}, 1)}, nil
}

// Scan checks one exact npm, PyPI or Cargo registry release. The caller selects
// releases already carrying trust findings and excludes local/git/URL sources.
// Any incomplete scan returns a non-nil error together with its attributed result.
func (c *Client) Scan(ctx context.Context, ref model.PackageRef) (Result, error) {
	result := Result{Ref: ref, Source: SourceURL, Status: "unavailable"}
	fail := func(err error) (Result, error) {
		result.Message = err.Error()
		return result, err
	}
	if err := validateRef(ref); err != nil {
		return fail(err)
	}
	select {
	case c.gate <- struct{}{}:
		defer func() { <-c.gate }()
	case <-ctx.Done():
		return fail(ctx.Err())
	}
	result.ToolVersion = c.version
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	if c.scans >= MaxPackages {
		return fail(fmt.Errorf("GuardDog scan limit reached (%d packages)", MaxPackages))
	}
	c.scans++
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	if c.version == "" {
		probeCtx, stopProbe := context.WithTimeout(ctx, 10*time.Second)
		output, err := c.run(probeCtx, "--version")
		stopProbe()
		if err != nil {
			return fail(fmt.Errorf("GuardDog version probe: %w", err))
		}
		if strings.TrimSpace(string(output)) != SupportedVersion {
			return fail(fmt.Errorf("GuardDog version must be %s; install the reviewed version separately", SupportedVersion))
		}
		c.version = SupportedVersion
		result.ToolVersion = c.version
	}
	ecosystem := string(ref.Ecosystem)
	if ref.Ecosystem == model.Cargo {
		ecosystem = "crates"
	}
	// Fixed argv follows the pinned CLI above. --sandbox is explicit: a missing
	// kernel sandbox is an error, never permission to retry without isolation.
	args := []string{ecosystem, "scan", "--version", ref.Version, "--output-format", "json", "--sandbox"}
	if ref.Ecosystem == model.NPM {
		// This upstream metadata rule resolves ranges and starts additional scans.
		// Keep this handoff scoped to the exact releases selected by trustdiff.
		args = append(args, "--exclude-rules", "risky_new_dependency")
	}
	args = append(args, "--", ref.Name)
	output, err := c.run(ctx, args...)
	if err != nil {
		return fail(fmt.Errorf("GuardDog scan %s: %w", ref, err))
	}
	result, err = parseReport(ref, output)
	if ref.Ecosystem == model.NPM {
		if result.Message != "" {
			result.Message += "; "
		}
		result.Message += "risky_new_dependency excluded: the handoff scans only the selected exact release"
	}
	return result, err
}

var (
	pypiName    = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$`)
	crateName   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,63}$`)
	exactSemver = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)
)

func validateRef(ref model.PackageRef) error {
	validName := false
	switch ref.Ecosystem {
	case model.NPM:
		validName = model.NPMNameProblem(ref.Name) == ""
	case model.PyPI:
		validName = len(ref.Name) <= 214 && pypiName.MatchString(ref.Name)
	case model.Cargo:
		validName = crateName.MatchString(ref.Name)
	default:
		return fmt.Errorf("GuardDog handoff does not support ecosystem %q", ref.Ecosystem)
	}
	if !validName {
		return errors.New("GuardDog requires a valid registry package name; paths, URLs and options are not accepted")
	}
	if len(ref.Version) > 256 || strings.TrimSpace(ref.Version) != ref.Version {
		return errors.New("GuardDog requires an exact registry release version")
	}
	if ref.Ecosystem != model.PyPI && !exactSemver.MatchString(ref.Version) {
		return errors.New("GuardDog requires a complete exact semantic version, not a tag or range")
	}
	if _, err := version.Parse(ref.Ecosystem, ref.Version); err != nil {
		return fmt.Errorf("GuardDog requires an exact registry release version: %w", err)
	}
	return nil
}
