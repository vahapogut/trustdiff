package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestParseTrimmedMappings(t *testing.T) {
	data := []byte("# recorded synthetic Unicode-format fixture, no network\n0441 ; 0063 ; MA # Cyrillic c\n006D ; 0072 006E ; MA\n039C ; 004D ; MA\n0301 ; 0300 ; MA\n1D41C ; 0063 ; MA\n")
	want := map[rune]string{'\u0441': "c", 'm': "rn", '\u039c': "rn", '\U0001d41c': "c"}
	for range 20 {
		got, err := parse(data)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("parse() = %v, %v; want %v", got, err, want)
		}
	}
}

func TestChangedUpstreamNeverOverwritesOutput(t *testing.T) {
	dir := t.TempDir()
	in, out := filepath.Join(dir, "confusables.txt"), filepath.Join(dir, "generated.go")
	if err := os.WriteFile(in, []byte("0441 ; 0063 ; MA\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, []byte("preserve generated table\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(in, out); err == nil {
		t.Fatal("accepted unreviewed upstream bytes")
	}
	got, err := os.ReadFile(out)
	if err != nil || string(got) != "preserve generated table\n" {
		t.Fatalf("existing generated file changed: %q, %v", got, err)
	}
}

func TestParseRejectsMalformedAndCycles(t *testing.T) {
	for _, data := range []string{"no fields", "zz ; 0061 ; MA", "D800 ; 0061 ; MA", "0041 ; zz ; MA", "0041 ; 110000 ; MA", "0041 ; 0061 ; SL", "0061 ; 0062 ; MA\n0062 ; 0061 ; MA", "0061 ; 0061 0061 ; MA"} {
		if _, err := parse([]byte(data)); err == nil {
			t.Errorf("accepted %q", data)
		}
	}
}
