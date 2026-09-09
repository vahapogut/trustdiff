// Package version exposes the build identity of the trustdiff binary.
//
// Version, Commit and Date are set at link time by goreleaser or the Makefile:
//
//	-ldflags "-X github.com/vahapogut/trustdiff/internal/version.Version=v0.1.0 ..."
//
// Without them the binary reports itself as a development build.
package version

import (
	"fmt"
	"runtime"
)

// Set at link time. Keep the zero values meaningful for `go run` and `go install`.
var (
	// Version is the release tag, for example v0.1.0, or "dev".
	Version = "dev"
	// Commit is the short git commit the binary was built from, or "none".
	Commit = "none"
	// Date is the commit or build timestamp in RFC 3339, or "unknown".
	Date = "unknown"
)

// Info is the complete build identity, including the runtime the binary was compiled with.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	Date      string `json:"date"`
	GoVersion string `json:"go_version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

// Get returns the build identity of the running binary.
func Get() Info {
	return Info{
		Version:   Version,
		Commit:    Commit,
		Date:      Date,
		GoVersion: runtime.Version(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
	}
}

// String renders the identity on one line, suitable for `trustdiff version`.
func (i Info) String() string {
	return fmt.Sprintf("trustdiff %s (commit %s, built %s, %s %s/%s)",
		i.Version, i.Commit, i.Date, i.GoVersion, i.OS, i.Arch)
}

// UserAgent is the value sent in the User-Agent header of every outbound request.
// crates.io requires an identifying agent with a contact URL.
func UserAgent() string {
	return "trustdiff/" + Version + " (+https://github.com/vahapogut/trustdiff)"
}
