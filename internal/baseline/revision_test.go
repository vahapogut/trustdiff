package baseline

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// revision is a fake RevisionReader: one path per revision, or an error.
type revision struct {
	files map[string][]byte
	err   error
	asked []string
}

func (r *revision) FileAt(_ context.Context, sha, path string) ([]byte, error) {
	r.asked = append(r.asked, sha+":"+path)
	if r.err != nil {
		return nil, r.err
	}
	if data, ok := r.files[path]; ok {
		return data, nil
	}
	return nil, errNotAtRev
}

// errNotAtRev stands in for gitdiff.ErrNotAtRev, which this package must not
// import; what matters is that AtRevision leaves it recognizable to the caller.
var errNotAtRev = errors.New("path does not exist at revision")

const sha = "0123456789abcdef0123456789abcdef01234567"

func TestAtRevisionReadsAndParses(t *testing.T) {
	data, err := Bytes(file(entry("npm:example-lib@1.0.0", day, "alice")))
	if err != nil {
		t.Fatal(err)
	}
	r := &revision{files: map[string][]byte{".trustdiff/baseline.json": data}}
	f, err := AtRevision(context.Background(), r, sha, ".trustdiff\\baseline.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Packages) != 1 || f.Packages[0].Name != "example-lib" {
		t.Fatalf("packages = %+v", f.Packages)
	}
	// git speaks in forward slashes whatever the platform, so a Windows path is
	// translated before it is asked for.
	if len(r.asked) != 1 || r.asked[0] != sha+":.trustdiff/baseline.json" {
		t.Errorf("asked = %v, want a slash separated path", r.asked)
	}
}

// A revision without a baseline is what a change that adds the file looks like,
// and the caller has to be able to tell that from a git failure.
func TestAtRevisionKeepsTheReaderError(t *testing.T) {
	r := &revision{err: errNotAtRev}
	_, err := AtRevision(context.Background(), r, sha, ".trustdiff/baseline.json")
	if !errors.Is(err, errNotAtRev) {
		t.Fatalf("err = %v, want the reader's error to stay recognizable", err)
	}
	if !strings.Contains(err.Error(), "0123456789ab") || strings.Contains(err.Error(), sha) {
		t.Errorf("err = %v, want the revision abbreviated", err)
	}
}

// A baseline committed by another machine is validated exactly like one on this
// one, and the message says which revision it came from.
func TestAtRevisionValidates(t *testing.T) {
	r := &revision{files: map[string][]byte{".trustdiff/baseline.json": []byte(`{"schema":"trustdiff.baseline/2"}`)}}
	_, err := AtRevision(context.Background(), r, sha, ".trustdiff/baseline.json")
	if !errors.Is(err, ErrWrongSchema) {
		t.Fatalf("err = %v, want ErrWrongSchema", err)
	}
	if !strings.Contains(err.Error(), ".trustdiff/baseline.json at 0123456789ab") {
		t.Errorf("err = %v, want the path and the revision named", err)
	}
}
