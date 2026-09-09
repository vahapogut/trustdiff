package typosquat

import (
	"math/rand/v2"
	"testing"
)

func TestDistance(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"", "", 0},
		{"abc", "", 3},
		{"", "abc", 3},
		{"requests", "requests", 0},
		{"kitten", "sitting", 3},
		{"requests", "requets", 1},
		{"requests", "reqeusts", 1},
		{"abcd", "acbd", 1},
		{"lodash", "1odash", 1},
		{"lodash", "lodashh", 1},
		{"beautifulsoup4", "beatifulsop4", 2},
		// Optimal string alignment: a transposed pair is never edited again, so
		// ca -> abc costs 3, not the 2 of the unrestricted distance.
		{"ca", "abc", 3},
		// Runes, not bytes.
		{"café", "cafe", 1},
	}
	for _, tt := range tests {
		t.Run(tt.a+"/"+tt.b, func(t *testing.T) {
			if got := Distance(tt.a, tt.b); got != tt.want {
				t.Errorf("Distance(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

// TestDistanceProperties checks the metric properties over random names: the
// distance is symmetric, zero exactly for equal strings, and never more than
// the longer length.
func TestDistanceProperties(t *testing.T) {
	const alphabet = "abcde-_.10"
	rng := rand.New(rand.NewPCG(1, 2))
	random := func() string {
		n := rng.IntN(12)
		b := make([]byte, n)
		for i := range b {
			b[i] = alphabet[rng.IntN(len(alphabet))]
		}
		return string(b)
	}
	for range 5000 {
		a, b := random(), random()
		ab, ba := Distance(a, b), Distance(b, a)
		if ab != ba {
			t.Fatalf("Distance(%q, %q) = %d but Distance(%q, %q) = %d", a, b, ab, b, a, ba)
		}
		if (ab == 0) != (a == b) {
			t.Fatalf("Distance(%q, %q) = %d, zero must mean equal", a, b, ab)
		}
		if longest := max(len(a), len(b)); ab > longest {
			t.Fatalf("Distance(%q, %q) = %d exceeds the longer length %d", a, b, ab, longest)
		}
		if d := Distance(a, a); d != 0 {
			t.Fatalf("Distance(%q, %q) = %d, want 0", a, a, d)
		}
	}
}

func TestThreshold(t *testing.T) {
	tests := []struct {
		name string
		want int
	}{
		{"", 1},
		{"ms", 1},
		{"requests", 1},
		{"colorama1", 1},
		{"typescript", 2},
		{"beautifulsoup4", 2},
		{"cafécaféc", 1}, // 9 runes, 11 bytes
	}
	for _, tt := range tests {
		if got := Threshold(tt.name); got != tt.want {
			t.Errorf("Threshold(%q) = %d, want %d", tt.name, got, tt.want)
		}
	}
}
