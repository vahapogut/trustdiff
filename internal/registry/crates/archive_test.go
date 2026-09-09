package crates

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"maps"
	"strings"
	"testing"
)

// entry is one file of a synthetic archive.
type entry struct {
	name string
	body []byte
	dir  bool
}

// buildArchive writes entries into a gzip tar the way cargo lays one out.
func buildArchive(t *testing.T, entries []entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Mode: 0o644, Size: int64(len(e.body)), Typeflag: tar.TypeReg}
		if e.dir {
			hdr.Typeflag = tar.TypeDir
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar header: %v", err)
		}
		if !e.dir {
			if _, err := tw.Write(e.body); err != nil {
				t.Fatalf("tar body: %v", err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

// fixtureManifest extracts <prefix>/Cargo.toml from a recorded archive.
func fixtureManifest(t *testing.T, file, prefix string) []byte {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(fixture(t, file)))
	if err != nil {
		t.Fatalf("gzip: %v", err)
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err != nil {
			t.Fatalf("no Cargo.toml in %s: %v", file, err)
		}
		if hdr.Name != prefix+"/Cargo.toml" {
			continue
		}
		data, err := readManifest(tr, hdr.Size, maxManifestBytes)
		if err != nil {
			t.Fatalf("reading Cargo.toml: %v", err)
		}
		return data
	}
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// incompressible returns n bytes gzip cannot shrink, so a truncated compressed
// stream really cuts the entry short.
func incompressible(n int) []byte {
	out := make([]byte, n)
	var x uint32 = 2463534242
	for i := range out {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		out[i] = byte(x)
	}
	return out
}

const (
	manifestPlain     = "[package]\nname = \"demo\"\nversion = \"1.0.0\"\n"
	manifestBuild     = "[package]\nname = \"demo\"\nversion = \"1.0.0\"\nbuild = \"build.rs\"\n"
	manifestCustom    = "[package]\nname = \"demo\"\nversion = \"1.0.0\"\nbuild = \"build/main.rs\"\n\n[lib]\nproc-macro = true\n"
	manifestNoBuild   = "[package]\nname = \"demo\"\nversion = \"1.0.0\"\nbuild = false\n"
	manifestProcMacro = "[package]\nname = \"demo\"\n\n[lib]\nproc-macro = true\n"
)

var defaultLimits = archiveLimits{unpacked: maxUnpackedBytes, manifest: maxManifestBytes}

func TestInspectArchiveRecordedCrates(t *testing.T) {
	tests := []struct {
		file, prefix string
		want         map[string]string
	}{
		{
			// build.rs exists but the 2024-03 manifest carries no build key.
			file: "memoffset-0.9.1.crate", prefix: "memoffset-0.9.1",
			want: map[string]string{ScriptBuild: "build script runs at compile time"},
		},
		{
			file: "async-recursion-1.1.1.crate", prefix: "async-recursion-1.1.1",
			want: map[string]string{ScriptProcMacro: "procedural macro runs at compile time"},
		},
		{
			file: "paste-1.0.15.crate", prefix: "paste-1.0.15",
			want: map[string]string{
				ScriptBuild:     "build script runs at compile time",
				ScriptProcMacro: "procedural macro runs at compile time",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			facts, err := inspectArchive(bytes.NewReader(fixture(t, tt.file)), tt.prefix, defaultLimits)
			if err != nil {
				t.Fatalf("inspectArchive: %v", err)
			}
			if got := facts.scripts(); !maps.Equal(got, tt.want) {
				t.Errorf("scripts = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestInspectArchiveSynthetic(t *testing.T) {
	tests := []struct {
		name    string
		entries []entry
		limits  archiveLimits
		want    map[string]string
		wantErr string
	}{
		{
			name: "build.rs found by walking to the end",
			entries: []entry{
				{name: "demo-1.0.0/Cargo.toml", body: []byte(manifestPlain)},
				{name: "demo-1.0.0/src/lib.rs", body: []byte("pub fn f() {}")},
				{name: "demo-1.0.0/build.rs", body: []byte("fn main() {}")},
			},
			want: map[string]string{ScriptBuild: "build script runs at compile time"},
		},
		{
			name: "nothing runs at compile time",
			entries: []entry{
				{name: "demo-1.0.0/Cargo.toml", body: []byte(manifestPlain)},
				{name: "demo-1.0.0/src/lib.rs", body: []byte("pub fn f() {}")},
			},
			want: nil,
		},
		{
			name: "custom build path and proc-macro from the manifest",
			entries: []entry{
				{name: "demo-1.0.0/Cargo.toml", body: []byte(manifestCustom)},
				{name: "demo-1.0.0/build/main.rs", body: []byte("fn main() {}")},
			},
			want: map[string]string{
				ScriptBuild:     "build script build/main.rs runs at compile time",
				ScriptProcMacro: "procedural macro runs at compile time",
			},
		},
		{
			name: "build = false wins over a build.rs file",
			entries: []entry{
				{name: "demo-1.0.0/Cargo.toml", body: []byte(manifestNoBuild)},
				{name: "demo-1.0.0/build.rs", body: []byte("fn main() {}")},
			},
			want: nil,
		},
		{
			name: "build.rs before Cargo.toml in an unsorted archive",
			entries: []entry{
				{name: "demo-1.0.0/build.rs", body: []byte("fn main() {}")},
				{name: "demo-1.0.0/Cargo.toml", body: []byte(manifestProcMacro)},
			},
			want: map[string]string{
				ScriptBuild:     "build script runs at compile time",
				ScriptProcMacro: "procedural macro runs at compile time",
			},
		},
		{
			name: "files outside the crate directory are ignored",
			entries: []entry{
				{name: "demo-1.0.0/", dir: true},
				{name: "demo-1.0.0/Cargo.toml", body: []byte(manifestPlain)},
				{name: "other-1.0.0/build.rs", body: []byte("fn main() {}")},
				{name: "build.rs", body: []byte("fn main() {}")},
				{name: "demo-1.0.0/src/build.rs", body: []byte("fn main() {}")},
			},
			want: nil,
		},
		{
			name: "no Cargo.toml",
			entries: []entry{
				{name: "demo-1.0.0/build.rs", body: []byte("fn main() {}")},
				{name: "other-1.0.0/Cargo.toml", body: []byte(manifestBuild)},
			},
			wantErr: "no Cargo.toml under demo-1.0.0/",
		},
		{
			name: "manifest over the limit",
			entries: []entry{
				{name: "demo-1.0.0/Cargo.toml", body: []byte(manifestBuild + strings.Repeat("# padding\n", 20))},
			},
			limits:  archiveLimits{unpacked: maxUnpackedBytes, manifest: 64},
			wantErr: "Cargo.toml is",
		},
		{
			name: "expansion beyond the unpacked limit",
			entries: []entry{
				{name: "demo-1.0.0/.padding", body: make([]byte, 1<<20)},
				{name: "demo-1.0.0/Cargo.toml", body: []byte(manifestBuild)},
			},
			limits:  archiveLimits{unpacked: 64 << 10, manifest: maxManifestBytes},
			wantErr: errUnpackedLimit.Error(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limits := tt.limits
			if limits == (archiveLimits{}) {
				limits = defaultLimits
			}
			facts, err := inspectArchive(bytes.NewReader(buildArchive(t, tt.entries)), "demo-1.0.0", limits)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want one containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("inspectArchive: %v", err)
			}
			if got := facts.scripts(); !maps.Equal(got, tt.want) {
				t.Errorf("scripts = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestInspectArchiveNotGzip(t *testing.T) {
	_, err := inspectArchive(strings.NewReader("plain text"), "demo-1.0.0", defaultLimits)
	if err == nil || !strings.Contains(err.Error(), "not a gzip stream") {
		t.Fatalf("error = %v, want a gzip error", err)
	}
	if _, err := inspectArchive(bytes.NewReader(buildArchive(t, nil)[:10]), "demo-1.0.0", defaultLimits); err == nil {
		t.Fatal("truncated header accepted")
	}
}

// TestInspectArchiveStopsEarly cuts the compressed stream in the middle of the
// entry that follows Cargo.toml. When the manifest settles both facts the walk
// never reaches the cut; when it leaves the build script open the walk must go
// on and runs into the truncation.
func TestInspectArchiveStopsEarly(t *testing.T) {
	tail := incompressible(256 << 10)
	tests := []struct {
		name     string
		manifest string
		wantStop bool
	}{
		{name: "manifest declares the build script", manifest: manifestBuild, wantStop: true},
		{name: "manifest disables the build script", manifest: manifestNoBuild, wantStop: true},
		{name: "manifest says nothing, walk continues", manifest: manifestProcMacro, wantStop: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			full := buildArchive(t, []entry{
				{name: "demo-1.0.0/Cargo.toml", body: []byte(tt.manifest)},
				{name: "demo-1.0.0/src/lib.rs", body: tail},
				{name: "demo-1.0.0/build.rs", body: []byte("fn main() {}")},
			})
			cut := full[:len(full)/2]
			facts, err := inspectArchive(bytes.NewReader(cut), "demo-1.0.0", defaultLimits)
			if !tt.wantStop {
				if err == nil {
					t.Fatal("walk did not reach the truncated entry")
				}
				return
			}
			if err != nil {
				t.Fatalf("inspectArchive on the truncated stream: %v", err)
			}
			if !facts.settled() {
				t.Errorf("facts not settled: %+v", facts)
			}
		})
	}
}

func TestCappedReader(t *testing.T) {
	r := &cappedReader{r: strings.NewReader("0123456789"), left: 4}
	buf := make([]byte, 8)
	n, err := r.Read(buf)
	if n != 4 || err != nil {
		t.Fatalf("first read = %d, %v; want 4, nil", n, err)
	}
	if _, err := r.Read(buf); !errors.Is(err, errUnpackedLimit) {
		t.Fatalf("second read error = %v, want errUnpackedLimit", err)
	}
}
