package attestation

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// Options selects an installed verifier and, optionally, an explicit trust root.
type Options struct {
	Binary, TrustedRoot string
	Offline             bool
}

// Verifier uses the reviewed Cosign release with bounded execution and output.
type Verifier struct {
	binary, root string
	gate         chan struct{}
}

// New resolves and validates explicit local configuration before a registry run.
func New(ctx context.Context, opts Options) (*Verifier, error) {
	if opts.Binary == "" {
		opts.Binary = "cosign"
	}
	binary, err := exec.LookPath(opts.Binary)
	if err != nil {
		return nil, fmt.Errorf("install cosign v3.1.3 or set --cosign-bin: %w", err)
	}
	binary, err = filepath.Abs(binary)
	if err != nil {
		return nil, err
	}
	if opts.Offline && opts.TrustedRoot == "" {
		return nil, fmt.Errorf("offline local verification requires --sigstore-root")
	}
	if opts.TrustedRoot != "" {
		opts.TrustedRoot, err = filepath.Abs(opts.TrustedRoot)
		if err != nil {
			return nil, err
		}
		st, err := os.Stat(opts.TrustedRoot)
		if err != nil || !st.Mode().IsRegular() || st.Size() > maxBundleBytes {
			return nil, fmt.Errorf("trusted root must be a readable regular file at most 2 MiB")
		}
	}
	v := &Verifier{binary: binary, root: opts.TrustedRoot, gate: make(chan struct{}, 1)}
	output, err := v.run(ctx, "version", "--json")
	if err != nil {
		return nil, fmt.Errorf("cosign version: %w", err)
	}
	var version struct{ GitVersion string }
	if err := json.Unmarshal(output, &version); err != nil || version.GitVersion != "v3.1.3" {
		return nil, fmt.Errorf("local verification requires the reviewed cosign v3.1.3")
	}
	return v, nil
}

// Verify authenticates the complete bundle; no insecure skip flags are accepted.
func (v *Verifier) Verify(ctx context.Context, c *Claim) error {
	// Serialize invocations so concurrent subjects cannot race Cosign's TUF cache.
	select {
	case v.gate <- struct{}{}:
		defer func() { <-v.gate }()
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "trustdiff-sigstore-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(path, c.Bundle, 0600); err != nil {
		return err
	}
	args := []string{"verify-blob-attestation", "--bundle", path, "--certificate-identity", c.Identity, "--certificate-oidc-issuer", c.Issuer, "--type", c.Predicate, "--digest", c.Digest, "--digestAlg", "sha512", "--timeout", "45s"}
	if v.root != "" {
		args = append(args, "--trusted-root", v.root)
	}
	_, err = v.run(ctx, args...)
	return err
}

type cappedOutput struct {
	data     []byte
	exceeded bool
}

func (b *cappedOutput) Write(p []byte) (int, error) {
	if len(b.data)+len(p) > 64<<10 {
		b.exceeded = true
		return 0, fmt.Errorf("verifier output exceeds 64 KiB")
	}
	b.data = append(b.data, p...)
	return len(p), nil
}

func (v *Verifier) run(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, v.binary, args...) // #nosec G204 -- explicit user-selected verifier, fixed argument vector and no shell
	cmd.WaitDelay = time.Second
	var out, diagnostic cappedOutput
	cmd.Stdout = &out
	cmd.Stderr = &diagnostic
	err := cmd.Run()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if out.exceeded || diagnostic.exceeded {
		return nil, fmt.Errorf("cosign output limit exceeded")
	}
	if err != nil {
		return nil, fmt.Errorf("cosign verification failed: %w", err)
	}
	return out.data, nil
}
