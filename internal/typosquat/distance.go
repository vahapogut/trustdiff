package typosquat

// Threshold is the edit distance below which a name is a suspect of a popular
// name: 1 for popular names shorter than 10 characters, 2 otherwise. The popular
// name decides, since it is the one being imitated, and for a scoped name only its
// bare half counts.
//
// The scope is left out because it is shared by every package inside it, so it
// costs a squatter nothing to copy and must not buy one a looser budget.
// "@loaders.gl/" is twelve runes on its own: while the whole spelling decided, the
// pair cleared ten runes on the scope alone, every package in that scope was
// within two edits of every other, and @loaders.gl/wms was reported as a suspect
// of @loaders.gl/gis.
func Threshold(popular string) int {
	return thresholdRunes(len(bareName([]rune(popular))))
}

// thresholdRunes is Threshold for a bare name already counted, so the scan over
// the popular names counts each one once.
func thresholdRunes(bare int) int {
	if bare < 10 {
		return 1
	}
	return 2
}

// Distance is the Damerau-Levenshtein distance between a and b in its optimal
// string alignment form: the number of single-character insertions, deletions,
// substitutions and adjacent transpositions that turn one into the other, with
// no substring edited twice. It is symmetric and counts runes, not bytes.
func Distance(a, b string) int {
	var d distancer
	return d.distance([]rune(a), []rune(b))
}

// distancer keeps the three rows of the dynamic program so that a scan over
// thousands of names allocates once.
type distancer struct {
	rows [3][]int
}

func (d *distancer) distance(a, b []rune) int {
	n, m := len(a), len(b)
	if n == 0 {
		return m
	}
	if m == 0 {
		return n
	}
	for i := range d.rows {
		if cap(d.rows[i]) < m+1 {
			d.rows[i] = make([]int, m+1)
		}
		d.rows[i] = d.rows[i][:m+1]
	}
	prev2, prev, cur := d.rows[0], d.rows[1], d.rows[2]
	for j := 0; j <= m; j++ {
		prev[j] = j
	}
	for i := 1; i <= n; i++ {
		cur[0] = i
		for j := 1; j <= m; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			best := min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
			if i > 1 && j > 1 && a[i-1] == b[j-2] && a[i-2] == b[j-1] {
				best = min(best, prev2[j-2]+1)
			}
			cur[j] = best
		}
		prev2, prev, cur = prev, cur, prev2
	}
	return prev[m]
}

// absDiff is |a - b| for lengths.
func absDiff(a, b int) int {
	if a > b {
		return a - b
	}
	return b - a
}
