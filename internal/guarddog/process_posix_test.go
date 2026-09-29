//go:build linux || darwin

package guarddog

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/vahapogut/trustdiff/internal/model"
)

// Helpers are inert executable fixtures. Their interpreter is selected by the
// kernel's shebang handling; production always executes its configured binary
// directly, with no shell command string. No helper downloads or installs data.
func helperBinary(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "guarddog fixture")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nset -eu\n"+body+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func helperClient(t *testing.T, body string, timeout time.Duration) *Client {
	t.Helper()
	binary := helperBinary(t, `if [ "$1" = "--version" ]; then printf '3.2.0\n'; exit 0; fi`+"\n"+body)
	client, err := New(Options{Binary: binary, Timeout: timeout})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestExecutableArgumentsIdentityAndIsolation(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "calls")
	t.Setenv("GUARDDOG_TEST_LOG", logPath)
	for _, tt := range []struct {
		ecosystem model.Ecosystem
		command   string
		name      string
	}{
		{model.NPM, "npm", "@scope/example"},
		{model.PyPI, "pypi", "example"},
		{model.Cargo, "crates", "example_crate"},
	} {
		t.Run(string(tt.ecosystem), func(t *testing.T) {
			body := `printf '%s\n' "$PWD" "$TMPDIR" "$TMP" "$TEMP" "$@" >> "$GUARDDOG_TEST_LOG"
if [ "$1" = "--version" ]; then printf '3.2.0\n'; exit 0; fi
[ "$(find . -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')" = '0' ]
for arg in "$@"; do target="$arg"; done
printf '{"package":"%s","package_version":"%s","issues":0,"errors":{},"results":{},"risks":[]}' "$target" "$4"`
			binary := helperBinary(t, body)
			client, err := New(Options{Binary: binary})
			if err != nil {
				t.Fatal(err)
			}
			ref := model.PackageRef{Ecosystem: tt.ecosystem, Name: tt.name, Version: "1.2.3"}
			for range 2 {
				got, scanErr := client.Scan(t.Context(), ref)
				if scanErr != nil || got.Status != "completed" {
					t.Fatalf("scan: %+v, %v", got, scanErr)
				}
			}
			data, err := os.ReadFile(logPath)
			if err != nil {
				t.Fatal(err)
			}
			lines := strings.Split(strings.TrimSpace(string(data)), "\n")
			want := []string{tt.command, "scan", "--version", "1.2.3", "--output-format", "json", "--sandbox"}
			if tt.ecosystem == model.NPM {
				want = append(want, "--exclude-rules", "risky_new_dependency")
			}
			want = append(want, "--", tt.name)
			if len(lines) != 5+2*(4+len(want)) {
				t.Fatalf("want one probe and two scans; got %d lines: %q", len(lines), lines)
			}
			for _, offset := range []int{0, 5, 9 + len(want)} {
				work, scratch := lines[offset], lines[offset+1]
				if filepath.Dir(work) != filepath.Dir(scratch) || filepath.Base(work) != "work" || filepath.Base(scratch) != "scratch" || lines[offset+2] != scratch || lines[offset+3] != scratch {
					t.Fatalf("temporary isolation missing: %q", lines[offset:offset+4])
				}
				if _, statErr := os.Stat(filepath.Dir(work)); !errors.Is(statErr, os.ErrNotExist) {
					t.Fatalf("temporary directory not removed: %v", statErr)
				}
			}
			if !reflect.DeepEqual(lines[9:9+len(want)], want) || !reflect.DeepEqual(lines[13+len(want):], want) {
				t.Fatalf("unexpected scan argv: %q", lines)
			}
			if err := os.Remove(logPath); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestWrongVersionNeverScans(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "unexpected-scan")
	t.Setenv("GUARDDOG_TEST_MARKER", marker)
	binary := helperBinary(t, `if [ "$1" = "--version" ]; then printf '3.1.0\n'; exit 0; fi
touch "$GUARDDOG_TEST_MARKER"`)
	client, err := New(Options{Binary: binary})
	if err != nil {
		t.Fatal(err)
	}
	got, err := client.Scan(t.Context(), model.MustParseRef("npm:example@1.2.3"))
	if err == nil || got.Status != "unavailable" || !strings.Contains(err.Error(), SupportedVersion) {
		t.Fatalf("wrong-version scan: %+v, %v", got, err)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("scan executed for unreviewed tool: %v", err)
	}
}

func TestProcessFailuresAreNotCleanScans(t *testing.T) {
	for _, tt := range []struct{ name, body, want string }{
		{"exit", `printf 'sandbox unavailable\n' >&2; exit 1`, "sandbox unavailable"},
		{"malformed", `printf 'not json'`, "invalid JSON"},
		{"download", `printf '%s' '{"package":"example","issues":0,"errors":{"download-package":"unavailable"}}'`, "did not confirm"},
		{"stdout limit", `dd if=/dev/zero bs=65536 count=65 2>/dev/null`, "output exceeded"},
		{"stderr limit", `dd if=/dev/zero bs=65536 count=2 >&2 2>/dev/null`, "output exceeded"},
		{"timeout", `exec sleep 30`, "deadline exceeded"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			client := helperClient(t, tt.body, 300*time.Millisecond)
			start := time.Now()
			got, err := client.Scan(t.Context(), model.MustParseRef("npm:example@1.2.3"))
			if err == nil || got.Status != "unavailable" || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("scan failure: %+v, %v; want %s", got, err, tt.want)
			}
			if time.Since(start) > 3*time.Second {
				t.Fatal("scan exceeded its timeout and pipe drain allowance")
			}
		})
	}
}

func TestCancelTerminatesChildProcess(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	t.Setenv("GUARDDOG_TEST_PID", pidFile)
	client := helperClient(t, `sleep 30 &
printf '%s' "$!" > "$GUARDDOG_TEST_PID"
wait`, 5*time.Second)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := client.Scan(ctx, model.MustParseRef("npm:example@1.2.3"))
		done <- err
	}()
	var pid int
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(pidFile)
		if err == nil {
			pid, err = strconv.Atoi(string(data))
			if err == nil {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if pid <= 0 {
		t.Fatal("helper child did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancel error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancellation did not terminate process group")
	}
	// A killed child can remain a zombie until init reaps it in a container.
	// ESRCH or Linux's zombie state both prove it cannot continue running.
	deadline = time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
			return
		}
		if status, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)); err == nil && strings.Contains(string(status), ") Z ") {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("child %d still exists after cancellation", pid)
}

func TestPackageLimitAndCanceledContext(t *testing.T) {
	client := helperClient(t, `printf '%s' '`+cleanReport+`'`, time.Second)
	ref := model.MustParseRef("npm:example@1.2.3")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := client.Scan(ctx, ref); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled context: %v", err)
	}
	for range MaxPackages {
		if _, err := client.Scan(t.Context(), ref); err != nil {
			t.Fatal(err)
		}
	}
	got, err := client.Scan(t.Context(), ref)
	if err == nil || got.Status != "unavailable" || !strings.Contains(err.Error(), "scan limit") {
		t.Fatalf("scan limit ignored: %+v, %v", got, err)
	}
}

func TestMissingBinary(t *testing.T) {
	_, err := New(Options{Binary: filepath.Join(t.TempDir(), "missing")})
	if err == nil || !strings.Contains(err.Error(), "install GuardDog "+SupportedVersion+" separately") {
		t.Fatalf("missing executable error: %v", err)
	}
}
