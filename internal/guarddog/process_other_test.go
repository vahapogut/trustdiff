//go:build !linux && !darwin

package guarddog

import (
	"strings"
	"testing"
)

func TestUnsupportedHostRefusesBeforeExecutableLookup(t *testing.T) {
	_, err := New(Options{Binary: "does-not-exist"})
	if err == nil || !strings.Contains(err.Error(), "requires Linux or macOS") {
		t.Fatalf("unsupported platform: %v", err)
	}
}
