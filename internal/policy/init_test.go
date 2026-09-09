package policy

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The commented file "policy init" writes must parse to exactly the built-in default.
func TestDefaultYAMLParsesToDefault(t *testing.T) {
	got, err := Parse(DefaultYAML())
	if err != nil {
		t.Fatalf("Parse(default.yaml): %v", err)
	}
	if !reflect.DeepEqual(got, Default()) {
		t.Fatalf("default.yaml differs from Default()\n got: %+v\nwant: %+v", got, Default())
	}
}

func TestDefaultYAMLExplainsEveryKey(t *testing.T) {
	text := string(DefaultYAML())
	for _, key := range []string{"version", "cooldown", "cooldown_exclude", "previous_versions_window", "checks", "allow", "on_data_unavailable", "ecosystems"} {
		if !strings.Contains(text, "\n"+key+":") {
			t.Errorf("default.yaml lacks the key %q", key)
		}
	}
	for _, name := range CheckNames() {
		if !strings.Contains(text, "  "+name+":") {
			t.Errorf("default.yaml lacks the check %q", name)
		}
	}
	if strings.ContainsAny(text, "\u2014\u2013") {
		t.Error("default.yaml contains an em or en dash, which the project style forbids")
	}
	if !strings.HasPrefix(text, "# ") {
		t.Error("default.yaml should start with a comment explaining the file")
	}
}

func TestDefaultYAMLReturnsACopy(t *testing.T) {
	a := DefaultYAML()
	a[0] = 'X'
	if b := DefaultYAML(); b[0] == 'X' {
		t.Fatal("DefaultYAML shares its buffer with the caller")
	}
}

func TestWriteDefault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", FileName)
	if err := WriteDefault(path); err != nil {
		t.Fatalf("WriteDefault: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, DefaultYAML()) {
		t.Fatal("written file differs from DefaultYAML()")
	}
	p, err := Load(path)
	if err != nil {
		t.Fatalf("Load(written): %v", err)
	}
	if !reflect.DeepEqual(p, Default()) {
		t.Fatal("Load(written) differs from Default()")
	}

	if err := os.WriteFile(path, []byte("version: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	err = WriteDefault(path)
	if !errors.Is(err, ErrExists) {
		t.Fatalf("WriteDefault over an existing file = %v, want ErrExists", err)
	}
	if data, _ := os.ReadFile(path); string(data) != "version: 1\n" {
		t.Fatal("WriteDefault overwrote an existing file")
	}
}
