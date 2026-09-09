package version

import (
	"runtime"
	"strings"
	"testing"
)

func TestGetUsesLinkTimeValuesAndRuntime(t *testing.T) {
	t.Cleanup(func() { Version, Commit, Date = "dev", "none", "unknown" })
	Version, Commit, Date = "v9.9.9", "abc1234", "2026-09-09T00:00:00Z"

	got := Get()
	if got.Version != "v9.9.9" || got.Commit != "abc1234" || got.Date != "2026-09-09T00:00:00Z" {
		t.Fatalf("Get() = %+v, want link-time values", got)
	}
	if got.GoVersion != runtime.Version() || got.OS != runtime.GOOS || got.Arch != runtime.GOARCH {
		t.Fatalf("Get() runtime fields = %+v", got)
	}
}

func TestInfoString(t *testing.T) {
	tests := []struct {
		name string
		info Info
		want string
	}{
		{
			name: "release build",
			info: Info{Version: "v0.1.0", Commit: "abc1234", Date: "2026-09-09T10:00:00Z", GoVersion: "go1.26.8", OS: "linux", Arch: "amd64"},
			want: "trustdiff v0.1.0 (commit abc1234, built 2026-09-09T10:00:00Z, go1.26.8 linux/amd64)",
		},
		{
			name: "dev build",
			info: Info{Version: "dev", Commit: "none", Date: "unknown", GoVersion: "go1.26.8", OS: "windows", Arch: "arm64"},
			want: "trustdiff dev (commit none, built unknown, go1.26.8 windows/arm64)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.info.String(); got != tt.want {
				t.Fatalf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestUserAgentIdentifiesProject(t *testing.T) {
	ua := UserAgent()
	if !strings.HasPrefix(ua, "trustdiff/") || !strings.Contains(ua, "github.com/vahapogut/trustdiff") {
		t.Fatalf("UserAgent() = %q", ua)
	}
}
