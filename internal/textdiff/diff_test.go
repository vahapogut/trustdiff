package textdiff

import (
	"strings"
	"testing"
)

// The golden diffs below were compared against GNU diff -u on the same inputs and
// match it byte for byte, which is the point of the port: a reviewer who reads
// one of these hunks reads what every other diff tool would have shown.
func TestUnified(t *testing.T) {
	cases := []struct {
		name string
		old  string
		new  string
		want string
	}{
		{
			name: "identical files produce no diff at all",
			old:  "alpha\nbeta\ngamma\n",
			new:  "alpha\nbeta\ngamma\n",
			want: "",
		},
		{
			name: "identical empty files produce no diff at all",
			old:  "",
			new:  "",
			want: "",
		},
		{
			name: "one changed line carries three lines of context on each side",
			old:  "a\nb\nc\nd\ne\nf\ng\nh\ni\n",
			new:  "a\nb\nc\nd\nE\nf\ng\nh\ni\n",
			want: "--- old.txt\n" +
				"+++ new.txt\n" +
				"@@ -2,7 +2,7 @@\n" +
				" b\n c\n d\n" +
				"-e\n+E\n" +
				" f\n g\n h\n",
		},
		{
			name: "a change near the top takes the context the file has",
			old:  "a\nb\nc\n",
			new:  "a\nB\nc\n",
			want: "--- old.txt\n" +
				"+++ new.txt\n" +
				"@@ -1,3 +1,3 @@\n" +
				" a\n" +
				"-b\n+B\n" +
				" c\n",
		},
		{
			name: "a line gained at the end is one addition after the context",
			old:  "a\nb\nc\nd\ne\n",
			new:  "a\nb\nc\nd\ne\nf\n",
			want: "--- old.txt\n" +
				"+++ new.txt\n" +
				"@@ -3,3 +3,4 @@\n" +
				" c\n d\n e\n" +
				"+f\n",
		},
		{
			name: "a lost last line is one removal after the context",
			old:  "a\nb\nc\nd\ne\nf\n",
			new:  "a\nb\nc\nd\ne\n",
			want: "--- old.txt\n" +
				"+++ new.txt\n" +
				"@@ -3,4 +3,3 @@\n" +
				" c\n d\n e\n" +
				"-f\n",
		},
		{
			name: "a file that loses its final newline says so the way diff does",
			old:  "a\nb\nc\n",
			new:  "a\nb\nc",
			want: "--- old.txt\n" +
				"+++ new.txt\n" +
				"@@ -1,3 +1,3 @@\n" +
				" a\n b\n" +
				"-c\n" +
				"+c\n\\ No newline at end of file\n",
		},
		{
			name: "a file created from nothing is all additions at line 0",
			old:  "",
			new:  "a\nb\n",
			want: "--- old.txt\n" +
				"+++ new.txt\n" +
				"@@ -0,0 +1,2 @@\n" +
				"+a\n+b\n",
		},
		{
			name: "two far apart changes are two hunks",
			old:  "a\nb\nc\nd\ne\nf\ng\nh\ni\nj\nk\nl\nm\nn\no\np\n",
			new:  "a\nb\nC\nd\ne\nf\ng\nh\ni\nj\nk\nl\nm\nN\no\np\n",
			want: "--- old.txt\n" +
				"+++ new.txt\n" +
				"@@ -1,6 +1,6 @@\n" +
				" a\n b\n" +
				"-c\n+C\n" +
				" d\n e\n f\n" +
				"@@ -11,6 +11,6 @@\n" +
				" k\n l\n m\n" +
				"-n\n+N\n" +
				" o\n p\n",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Unified("old.txt", "new.txt", []byte(c.old), []byte(c.new))
			if string(got) != c.want {
				t.Errorf("Unified() produced\n%s\nwant\n%s", got, c.want)
			}
			if c.want == "" && got != nil {
				t.Errorf("Unified() returned %q for identical input, want a nil slice", got)
			}
		})
	}
}

// TestUnifiedNamesAppearInHeader pins the one thing a caller has to be able to
// rely on beyond the hunks: the header says which file each side came from.
func TestUnifiedNamesAppearInHeader(t *testing.T) {
	got := string(Unified("a/go.sum", "b/go.sum", []byte("one\n"), []byte("two\n")))
	if !strings.HasPrefix(got, "--- a/go.sum\n+++ b/go.sum\n@@ ") {
		t.Errorf("Unified() began with %q, want the ---/+++ header with both names", got)
	}
	if strings.Contains(got, "diff a/go.sum b/go.sum") {
		t.Error("Unified() printed upstream's \"diff <old> <new>\" line, which this port drops")
	}
}

// TestUnifiedDoesNotMistakeCarriageReturns keeps the port honest about line
// endings: it splits on \n only, so a CRLF file diffs as CRLF lines rather than
// having the \r quietly eaten, and a file whose line endings changed shows every
// line as changed instead of showing nothing.
func TestUnifiedDoesNotMistakeCarriageReturns(t *testing.T) {
	got := Unified("old.txt", "new.txt", []byte("a\nb\n"), []byte("a\r\nb\r\n"))
	if len(got) == 0 {
		t.Fatal("Unified() called a LF file and a CRLF file identical")
	}
	if !strings.Contains(string(got), "-a\n") || !strings.Contains(string(got), "+a\r\n") {
		t.Errorf("Unified() produced %q, want the carriage returns kept on the new side", got)
	}
}
