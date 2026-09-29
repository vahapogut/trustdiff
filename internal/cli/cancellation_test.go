package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vahapogut/trustdiff/internal/registry/crates/dumpindex"
)

func TestMainContextAlreadyCanceled(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		var ctx context.Context
		var cancel context.CancelFunc
		want := "context canceled"
		if deadline {
			ctx, cancel = context.WithDeadline(context.Background(), time.Unix(0, 0))
			want = "context deadline exceeded"
		} else {
			ctx, cancel = context.WithCancel(context.Background())
			cancel()
		}
		var stdout, stderr bytes.Buffer
		code := MainContext(ctx, []string{"version"}, &stdout, &stderr)
		cancel()
		if code != ExitUnavailable || stdout.Len() != 0 || !strings.Contains(stderr.String(), want) {
			t.Fatalf("canceled command: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
	}
}

type cancellationWriter struct {
	buffer bytes.Buffer
	cancel context.CancelFunc
}

func (w *cancellationWriter) Write(data []byte) (int, error) {
	n, err := w.buffer.Write(data)
	w.cancel()
	return n, err
}

func TestMainContextCancellationOverridesSuccessfulCommand(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stdout := &cancellationWriter{cancel: cancel}
	var stderr bytes.Buffer
	code := MainContext(ctx, []string{"version"}, stdout, &stderr)
	if code != ExitUnavailable || stdout.buffer.Len() == 0 || !strings.Contains(stderr.String(), "context canceled") {
		t.Fatalf("cancellation after output: code=%d stdout=%q stderr=%q", code, stdout.buffer.String(), stderr.String())
	}
}

// A slow refresh must unwind through the same entry point used by the process.
// Cancellation happens only after HTTP response bytes have reached the staging
// file, so this covers cleanup of an interrupted download, not just a precheck.
func TestMainContextCanceledCratesDownloadPreservesIndex(t *testing.T) {
	dir, _ := installCLIDump(t, time.Now().UTC().Add(-time.Hour))
	indexDir := dumpindex.Dir(dir)
	before := indexFileHashes(t, indexDir)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write([]byte("partial archive bytes"))
		w.(http.Flusher).Flush()
		close(started)
		<-r.Context().Done()
	}))
	defer srv.Close()
	previous := cratesRefreshOptions
	cratesRefreshOptions = func() dumpindex.Options { return dumpindex.Options{URL: srv.URL} }
	t.Cleanup(func() { cratesRefreshOptions = previous })
	var stdout, stderr bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- MainContext(ctx, []string{"cache", "refresh", "--crates-dump"}, &stdout, &stderr)
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("refresh never reached the loopback server")
	}
	// Wait for the partial response to be written before canceling. The bound
	// protects the test from a regression while keeping cancellation deterministic.
	deadline := time.Now().Add(5 * time.Second)
	for {
		staging, err := filepath.Glob(filepath.Join(indexDir, "build-*", "archive.tar.gz"))
		if err != nil {
			t.Fatal(err)
		}
		if len(staging) == 1 {
			if info, err := os.Stat(staging[0]); err == nil && info.Size() > 0 {
				break
			}
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("partial download never reached staging")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case code := <-done:
		if code != ExitUnavailable || stdout.Len() != 0 || !strings.Contains(stderr.String(), "context canceled") {
			t.Fatalf("canceled refresh: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("canceled refresh did not stop")
	}
	if after := indexFileHashes(t, indexDir); !reflect.DeepEqual(before, after) {
		t.Fatalf("cancellation changed the index or left staging/lock files: before=%v after=%v", before, after)
	}
	entries, err := os.ReadDir(indexDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() == "refresh.lock" || strings.HasPrefix(entry.Name(), "build-") {
			t.Fatalf("cancellation left %s behind", entry.Name())
		}
	}
	if _, err := dumpindex.Open(dir, time.Now()); err != nil {
		t.Fatalf("previous index is no longer usable: %v", err)
	}
}

func indexFileHashes(t *testing.T, dir string) map[string][sha256.Size]byte {
	t.Helper()
	hashes := map[string][sha256.Size]byte{}
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		hashes[rel] = sha256.Sum256(data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return hashes
}
