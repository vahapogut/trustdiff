package crates

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/vahapogut/trustdiff/internal/httpcache"
)

const (
	// MaxArchiveBytes is the largest .crate archive that is downloaded and
	// inspected. crates.io accepts uploads of 10 MiB by default and raises the
	// limit per crate on request; 32 MiB leaves room for those while keeping one
	// inspection bounded in memory, since httpcache holds the body whole.
	MaxArchiveBytes = 32 << 20
	// maxUnpackedBytes bounds what the tar walk reads out of the gzip stream, so
	// an archive that expands far beyond its size stops the walk instead of
	// costing unbounded time.
	maxUnpackedBytes = 256 << 20
	// maxManifestBytes bounds Cargo.toml; a real one is a few kilobytes.
	maxManifestBytes = 1 << 20

	// ScriptBuild is the Scripts key for a build script, as the model documents for crates.io.
	ScriptBuild = "build.rs"
	// ScriptProcMacro is the Scripts key for a procedural macro crate.
	ScriptProcMacro = "proc-macro"

	manifestName    = "Cargo.toml"
	buildScriptName = "build.rs"
)

// ErrNotInspected is wrapped by VersionInfo when the archive was not inspected
// and Scripts is therefore unknown, not empty. The cause is wrapped as well:
// ErrArchiveTooLarge, ErrChecksumMismatch, httpcache.ErrOffline, a missing
// archive or a corrupt one.
var ErrNotInspected = errors.New("crate archive not inspected")

// ErrArchiveTooLarge means the archive exceeds MaxArchiveBytes and was skipped;
// the registry's crate_size is checked before any download.
var ErrArchiveTooLarge = errors.New("crate archive exceeds the inspection size cap")

// ErrChecksumMismatch means the downloaded archive's SHA-256 is not the checksum
// the registry lists for the version. The archive is never opened in that case.
var ErrChecksumMismatch = errors.New("crate archive checksum does not match the registry")

// errUnpackedLimit is returned by the capped reader when the tar stream expands
// beyond maxUnpackedBytes.
var errUnpackedLimit = errors.New("archive expands beyond the unpacked size limit")

// archiveLimits are the size bounds of one inspection; tests lower them.
type archiveLimits struct {
	unpacked int64
	manifest int64
}

// inspect downloads the archive through the cache (forever: the file is
// immutable), verifies its checksum and walks it for the build script and the
// procedural macro flag. Every failure is wrapped in ErrNotInspected. A missing
// archive answers 403 on static.crates.io (S3), 404 elsewhere (verified
// 2026-09-09); both count as unavailable.
func (c *Client) inspect(ctx context.Context, crateName, ver, checksum string, size int64) (map[string]string, error) {
	if size > c.maxArchive {
		return nil, fmt.Errorf("%w: %w: %d bytes, cap %d", ErrNotInspected, ErrArchiveTooLarge, size, c.maxArchive)
	}
	file := crateName + "-" + ver + ".crate"
	u := c.static + "/" + url.PathEscape(crateName) + "/" + url.PathEscape(file)
	resp, err := c.http.Get(ctx, u, httpcache.Request{TTL: httpcache.Forever})
	if err != nil {
		if isStatus(err, http.StatusForbidden, http.StatusNotFound) {
			return nil, fmt.Errorf("%w: archive not available: %w", ErrNotInspected, err)
		}
		return nil, fmt.Errorf("%w: %w", ErrNotInspected, err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%w: archive not available: %s answered 404", ErrNotInspected, u)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: unexpected status %d from %s", ErrNotInspected, resp.StatusCode, u)
	}
	if int64(len(resp.Body)) > c.maxArchive {
		return nil, fmt.Errorf("%w: %w: %d bytes, cap %d", ErrNotInspected, ErrArchiveTooLarge, len(resp.Body), c.maxArchive)
	}
	if checksum == "" {
		return nil, fmt.Errorf("%w: the registry lists no checksum for %s", ErrNotInspected, file)
	}
	sum := sha256.Sum256(resp.Body)
	if got := hex.EncodeToString(sum[:]); !strings.EqualFold(got, checksum) {
		return nil, fmt.Errorf("%w: %w: %s has sha256 %s, registry lists %s", ErrNotInspected, ErrChecksumMismatch, file, got, checksum)
	}
	facts, err := inspectArchive(bytes.NewReader(resp.Body), crateName+"-"+ver, archiveLimits{unpacked: maxUnpackedBytes, manifest: maxManifestBytes})
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrNotInspected, file, err)
	}
	c.log.Debug("crate archive inspected", "file", file, "build_script", facts.buildScript(), "proc_macro", facts.procMacro)
	return facts.scripts(), nil
}

// archiveFacts is what the walk learns about an archive.
type archiveFacts struct {
	manifestSeen bool
	// procMacro is [lib] proc-macro = true from Cargo.toml.
	procMacro bool
	// buildPath is [package] build from Cargo.toml when it names a file, and
	// buildDisabled is true for build = false. Both empty means the manifest
	// did not say; cargo only started writing the auto-detected build.rs into
	// published manifests in 2024, so memoffset 0.9.1 (2024-03) has the file
	// but no key.
	buildPath     string
	buildDisabled bool
	// buildFileSeen is true when <name>-<version>/build.rs is in the archive.
	buildFileSeen bool
}

// settled reports whether the walk can stop: the manifest has been read and the
// build script question is answered, by the manifest or by the file itself.
// Without an answer the walk continues to the end, since absence of build.rs
// can only be proven by seeing every entry.
func (f *archiveFacts) settled() bool {
	return f.manifestSeen && (f.buildFileSeen || f.buildPath != "" || f.buildDisabled)
}

// buildScript returns the build script path, or "" when the crate has none.
// A manifest that disables the build script wins over a build.rs file, as it
// does for cargo.
func (f *archiveFacts) buildScript() string {
	switch {
	case f.buildDisabled:
		return ""
	case f.buildPath != "":
		return f.buildPath
	case f.buildFileSeen:
		return buildScriptName
	default:
		return ""
	}
}

// scripts renders the facts as VersionInfo.Scripts, nil when nothing runs at
// compile time.
func (f *archiveFacts) scripts() map[string]string {
	out := map[string]string{}
	if path := f.buildScript(); path != "" {
		if path == buildScriptName {
			out[ScriptBuild] = "build script runs at compile time"
		} else {
			out[ScriptBuild] = "build script " + path + " runs at compile time"
		}
	}
	if f.procMacro {
		out[ScriptProcMacro] = "procedural macro runs at compile time"
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// inspectArchive streams the gzip tar and stops as soon as the facts are
// settled. Entries live under <prefix>/ (cargo writes <name>-<version>/); files
// outside that directory are ignored.
func inspectArchive(r io.Reader, prefix string, lim archiveLimits) (*archiveFacts, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("not a gzip stream: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(&cappedReader{r: gz, left: lim.unpacked})
	facts := &archiveFacts{}
	dir := prefix + "/"
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading tar: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		rel, ok := strings.CutPrefix(hdr.Name, dir)
		if !ok {
			continue
		}
		switch rel {
		case manifestName:
			data, err := readManifest(tr, hdr.Size, lim.manifest)
			if err != nil {
				return nil, err
			}
			m := scanManifest(data)
			facts.manifestSeen = true
			facts.procMacro = m.procMacro
			facts.buildPath = m.build
			facts.buildDisabled = m.buildDisabled
		case buildScriptName:
			facts.buildFileSeen = true
		}
		if facts.settled() {
			break
		}
	}
	if !facts.manifestSeen {
		return nil, fmt.Errorf("no %s under %s", manifestName, dir)
	}
	return facts, nil
}

// readManifest reads the Cargo.toml entry, refusing one beyond the limit.
func readManifest(r io.Reader, size, limit int64) ([]byte, error) {
	if size > limit {
		return nil, fmt.Errorf("%s is %d bytes, limit %d", manifestName, size, limit)
	}
	data, err := io.ReadAll(io.LimitReader(r, limit+1)) // #nosec G110 -- bounded by the limit above and the LimitReader
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", manifestName, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s exceeds %d bytes", manifestName, limit)
	}
	return data, nil
}

// cappedReader fails once more than left bytes were read through it.
type cappedReader struct {
	r    io.Reader
	left int64
}

func (c *cappedReader) Read(p []byte) (int, error) {
	if c.left <= 0 {
		return 0, errUnpackedLimit
	}
	if int64(len(p)) > c.left {
		p = p[:c.left]
	}
	n, err := c.r.Read(p)
	c.left -= int64(n)
	return n, err
}

// isStatus reports whether err is an httpcache.StatusError with one of the codes.
func isStatus(err error, codes ...int) bool {
	var se *httpcache.StatusError
	if !errors.As(err, &se) {
		return false
	}
	for _, code := range codes {
		if se.StatusCode == code {
			return true
		}
	}
	return false
}
