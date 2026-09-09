package crates

import (
	"strings"
)

// manifest is what the scan reads out of a published Cargo.toml.
type manifest struct {
	// procMacro is [lib] proc-macro = true (cargo also accepts proc_macro).
	procMacro bool
	// build is [package] build when it names a file; buildDisabled is build = false.
	build         string
	buildDisabled bool
}

// scanManifest reads the two facts trustdiff needs from a Cargo.toml without a
// TOML parser: the [lib] proc-macro flag and the [package] build entry. Published
// manifests are normalized by cargo, one key per line with multi-line arrays and
// strings only where a value needs them, so a line scan that tracks the current
// table, skips comments, multi-line strings and multi-line arrays, and reads
// bare, quoted and dotted keys is enough. Anything it does not understand is
// ignored rather than guessed.
func scanManifest(data []byte) manifest {
	var (
		m       manifest
		table   string // current table, "" at the top level
		inArray int    // bracket depth of a multi-line array
		inStr   string // delimiter of an open multi-line string
	)
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if inStr != "" {
			if strings.Contains(line, inStr) {
				inStr = ""
			}
			continue
		}
		if inArray > 0 {
			inArray += bracketDepth(line)
			continue
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			table = tableName(line)
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = unquoteKey(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if delim, open := openMultilineString(value); open {
			inStr = delim
			continue
		}
		if strings.HasPrefix(value, "[") {
			if depth := bracketDepth(value); depth > 0 {
				inArray = depth
			}
			continue
		}
		value = stripComment(value)
		switch fullKey(table, key) {
		case "lib.proc-macro", "lib.proc_macro":
			m.procMacro = value == "true"
		case "package.build":
			switch {
			case value == "false":
				m.buildDisabled = true
				m.build = ""
			case len(value) >= 2 && (value[0] == '"' || value[0] == '\''):
				m.buildDisabled = false
				m.build = value[1 : len(value)-1]
			}
		}
	}
	return m
}

// tableName parses a [table] or [[array.table]] header. An array table gets a
// marker so [[lib]] never counts as [lib].
func tableName(line string) string {
	end := strings.Index(line, "]")
	if end < 0 {
		return ""
	}
	if strings.HasPrefix(line, "[[") {
		return "[[" + strings.TrimSpace(line[2:end])
	}
	return unquoteKey(strings.TrimSpace(line[1:end]))
}

// fullKey joins the table and the key the way TOML addresses them, so a dotted
// key at the top level (lib.proc-macro = true) reads like a key in its table.
func fullKey(table, key string) string {
	if table == "" {
		return key
	}
	return table + "." + key
}

// unquoteKey strips one layer of quotes from a bare or quoted key.
func unquoteKey(key string) string {
	if len(key) >= 2 && (key[0] == '"' || key[0] == '\'') && key[len(key)-1] == key[0] {
		return key[1 : len(key)-1]
	}
	return key
}

// openMultilineString reports whether value opens a triple-quoted string (three
// double quotes or three single quotes) that does not close on the same line,
// and returns the delimiter to wait for.
func openMultilineString(value string) (string, bool) {
	for _, delim := range []string{`"""`, `'''`} {
		if !strings.HasPrefix(value, delim) {
			continue
		}
		return delim, !strings.Contains(value[len(delim):], delim)
	}
	return "", false
}

// bracketDepth counts unbalanced square brackets outside quoted strings.
func bracketDepth(line string) int {
	depth := 0
	var quote byte
	for i := 0; i < len(line); i++ {
		ch := line[i]
		switch {
		case quote != 0:
			if ch == quote {
				quote = 0
			}
		case ch == '"' || ch == '\'':
			quote = ch
		case ch == '#':
			return depth
		case ch == '[':
			depth++
		case ch == ']':
			depth--
		}
	}
	return depth
}

// stripComment removes a trailing comment from a value, leaving quoted strings
// alone, and trims the result.
func stripComment(value string) string {
	var quote byte
	for i := 0; i < len(value); i++ {
		ch := value[i]
		switch {
		case quote != 0:
			if ch == quote {
				quote = 0
			}
		case ch == '"' || ch == '\'':
			quote = ch
		case ch == '#':
			return strings.TrimSpace(value[:i])
		}
	}
	return strings.TrimSpace(value)
}
