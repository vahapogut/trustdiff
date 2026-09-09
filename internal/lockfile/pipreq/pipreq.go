// Package pipreq reads the hash pinned requirements files a Python project hands to
// pip, the ones pip-compile and pip-tools write and the ones people write by hand:
// requirements.txt, requirements-dev.txt, requirements_dev.txt and the files inside
// a requirements directory.
//
// A requirements file is not a lockfile the way the other formats are. It has no
// version, no schema and no graph; it is a list of arguments to pip, one per logical
// line, and only one shape of line pins a version somebody can evaluate:
//
//	cryptography==46.0.3 \
//	    --hash=sha256:15ee7dbdc0f01f8e70b6c30fdc7e4c5c9e4b1a2e0a3f4e7d9c1b2a3f4e5d6c7b \
//	    --hash=sha256:2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f80912
//
// That is a name, one exact version and at least one hash, and it is the only thing
// this parser turns into an entry. Extras on the name and an environment marker
// after a semicolon are read and set aside: they say when the requirement applies,
// not which version is pinned, so a pinned requirement keeps its entry either way.
//
// Every other line is either dropped with a reason, because it pins something this
// parser cannot evaluate and a silent parse would look complete, or ignored quietly,
// because it is not a requirement at all:
//
//	name==1.2.3 with no --hash    dropped   a pin nothing guards. pip refuses to
//	                                        install any unhashed requirement once one
//	                                        requirement in the file carries a hash, so
//	                                        in a hash pinned file this is an anomaly
//	                                        worth showing rather than an entry.
//	name>=1.0, name~=1.0, name    dropped   a range or a bare name resolves to
//	                                        whatever the index serves on the day, so
//	                                        there is no version to evaluate.
//	name===1.0                    dropped   arbitrary equality compares the version as
//	                                        a string and is not the "==" pin this
//	                                        parser reads.
//	name; python_version < "3.9"  dropped   a marker with no pin is still no pin.
//	https://host/pkg-1.0.whl      dropped   a URL requirement names an artifact and no
//	name @ https://host/pkg.whl             version, and Entry.Ref needs a name a
//	                                        lookup could use.
//	-e ., -e git+https://...      dropped   an editable install has no version in the
//	                                        file at all.
//	-r other.txt, -c other.txt    dropped   an include names another file. This parser
//	                                        reads one file and does not follow it, and
//	                                        everything that file pins is missing from
//	                                        this parse, which is exactly what a reason
//	                                        on the entry set is for.
//	a blank line                  ignored   nothing is there.
//	# a comment, # via pip-compile ignored  a comment installs nothing. pip-compile
//	                                        writes "# via <package>" under every
//	                                        requirement it added itself, which is the
//	                                        only hint in the format about which
//	                                        requirements a person asked for; it is a
//	                                        comment, and Direct below says what this
//	                                        parser does about it.
//	--index-url, --find-links,    ignored   an option on a line of its own configures
//	--require-hashes, -f, -i, ...           pip for the whole file and installs
//	                                        nothing.
//	a file that ends on a "\"     dropped   the last requirement is cut in half. pip
//	                                        warns and installs what it has; a file
//	                                        that was truncated in transit is worth
//	                                        saying so about, and half a requirement is
//	                                        not something to evaluate.
//
// Line continuations, comments and options are read the way pip reads them. A line
// ending in a backslash joins with the next one, and the entry's line number is the
// physical line the requirement started on, which is where a SARIF finding points. A
// comment runs from a "#" at the start of a line or after whitespace to the end of
// the line, and a whole line comment ends a continuation rather than joining it,
// which is what pip does so that a comment can never swallow a requirement. Within a
// requirement, everything from the first argument beginning with a dash is options,
// which is where the hashes are.
//
// Fields the format does not carry. Source is the registry on every entry, because a
// bare "name==version" is fetched from an index; Resolved stays empty, because the
// file names no location for an entry and an "--index-url" configures the whole
// install rather than one requirement. Integrity is the first hash the requirement
// lists, as written, "sha256:<hex>": a requirement carries one hash per artifact it
// may be satisfied by, wheels for a dozen platforms and the sdist, and Entry.Integrity
// holds one hash with nothing in the file saying which artifact an install will pick.
// Dev stays false: requirements-dev.txt says so in its name, and Parser.Parse is
// documented to use the path for messages only. Optional and Bundled have no meaning
// here.
//
// Direct stays false on every entry, which Entry.Direct documents as what a parser
// that cannot tell does. A requirements file is one flat list with no field
// separating a requirement a person wrote from one pip-compile appended below it,
// and a hash pinned file is nearly always pip-compile output, where most lines are
// transitive. Marking everything direct would over-report on exactly the files this
// parser exists to read.
//
// PyPI names are recorded PEP 503 normalized, as model.NormalizeName defines it,
// because a requirements file spells a name however its author typed it.
//
// Format verified against pip's requirements file reference on 2026-09-09:
// https://pip.pypa.io/en/stable/reference/requirements-file-format/
package pipreq

import (
	"fmt"
	"io"
	"strings"

	"github.com/vahapogut/trustdiff/internal/lockfile"
	"github.com/vahapogut/trustdiff/internal/model"
)

// Format is the name the parser registers under. A requirements file has no single
// name, so this is the one it is called by far the most often, and Detect is what
// really decides.
const Format = "requirements.txt"

// The pieces of a name Detect accepts: a file called requirements with an optional
// suffix, or any .txt file inside a directory called requirements.
const (
	requirementsStem = "requirements"
	txtSuffix        = ".txt"
	stemSeparators   = "-_."
)

// hashOption is how a requirement names the hash of an artifact it may be installed
// from. pip accepts it glued to its value and separated by a space, and both are
// read.
const hashOption = "--hash"

// includeOptions name another requirements file. They are dropped rather than
// ignored, because everything the named file pins is missing from this parse.
var includeOptions = []string{"-r", "--requirement", "-c", "--constraint"}

// editableOptions install a project from a directory or a repository, with no
// version anywhere in the file.
var editableOptions = []string{"-e", "--editable"}

// versionOperators are the characters a version specifier is built from. A pinned
// version contains none of them, so finding one means the "==" was part of a wider
// range.
const versionOperators = "<>=!~*, \t"

func init() { lockfile.Register(Parser{}) }

// Parser reads hash pinned requirements files. The zero value is ready to use.
type Parser struct{}

// Name returns the format name, "requirements.txt".
func (Parser) Name() string { return Format }

// Detect reports whether a file with this name is a requirements file.
//
// lockfile.For passes the base name alone, which is enough for the names built on
// the word requirements: requirements.txt, requirements-dev.txt, requirements_dev.txt
// and requirements.prod.txt. It is not enough for the other common layout, a
// requirements directory holding main.txt, dev.txt and deploy.txt, because those base
// names say nothing and accepting every .txt file would swallow unrelated text. So
// Detect also accepts a name that carries its parent directory, "requirements/dev.txt",
// and a caller that has the whole path can pass it to have those recognized.
func (Parser) Detect(base string) bool {
	name := strings.ToLower(strings.ReplaceAll(base, `\`, "/"))
	if i := strings.LastIndex(name, "/"); i >= 0 {
		dir, file := name[:i], name[i+1:]
		if parentDirectory(dir) == requirementsStem && strings.HasSuffix(file, txtSuffix) {
			return true
		}
		name = file
	}
	stem, ok := strings.CutSuffix(name, txtSuffix)
	if !ok {
		return false
	}
	rest, ok := strings.CutPrefix(stem, requirementsStem)
	if !ok {
		return false
	}
	// "requirements.txt" itself, or a suffix the name is joined to by one of the
	// separators people spell it with.
	return rest == "" || strings.ContainsRune(stemSeparators, rune(rest[0]))
}

// parentDirectory is the last segment of a directory path.
func parentDirectory(dir string) string {
	if i := strings.LastIndex(dir, "/"); i >= 0 {
		return dir[i+1:]
	}
	return dir
}

// Parse reads a requirements file. It fails only when the file cannot be read at
// all: a line it cannot make sense of is dropped with a reason and the rest is
// kept, because a requirements file with one unreadable line still pins everything
// else.
func (Parser) Parse(path string, r io.Reader) (*lockfile.Lockfile, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", Format, err)
	}
	lf := &lockfile.Lockfile{Path: path, Format: Format, Ecosystem: model.PyPI}
	for _, ll := range logicalLines(data) {
		readLine(lf, &ll)
	}
	return lf, nil
}

// logicalLine is one requirement as pip sees it: the physical lines a backslash
// joined, and the number of the first of them.
type logicalLine struct {
	text string
	line int
	// unterminated is true for a file that ends on a backslash, which leaves its
	// last requirement half written.
	unterminated bool
}

// logicalLines joins the physical lines of the file the way pip does. A line ending
// in a backslash continues into the next one, except a line that is only a comment,
// which ends the continuation instead so that a comment can never swallow the
// requirement below it. The final newline is trimmed before the split, so that a
// file whose last line ends in a backslash is seen for what it is rather than being
// closed by the empty string after it.
func logicalLines(data []byte) []logicalLine {
	text := strings.TrimSuffix(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	physical := strings.Split(text, "\n")
	lines := make([]logicalLine, 0, len(physical))
	var joined strings.Builder
	start := 0
	for i, raw := range physical {
		line := strings.TrimRight(raw, " \t\r")
		if joined.Len() == 0 {
			start = i + 1
		} else if wholeLineComment(line) {
			// pip separates a comment from what it is joined to, so that a comment
			// glued to the end of a requirement still ends where it should.
			joined.WriteString(" ")
		}
		if continued, ok := strings.CutSuffix(line, `\`); ok && !wholeLineComment(line) {
			joined.WriteString(continued)
			continue
		}
		joined.WriteString(line)
		lines = append(lines, logicalLine{text: joined.String(), line: start})
		joined.Reset()
	}
	if joined.Len() > 0 {
		lines = append(lines, logicalLine{text: joined.String(), line: start, unterminated: true})
	}
	return lines
}

// wholeLineComment reports whether the line holds nothing but a comment.
func wholeLineComment(text string) bool {
	return strings.HasPrefix(strings.TrimLeft(text, " \t"), "#")
}

// readLine turns one logical line into an entry, drops it with a reason, or ignores
// it. The package comment says which of the three each shape of line gets and why.
func readLine(lf *lockfile.Lockfile, ll *logicalLine) {
	text := strings.TrimSpace(stripComment(ll.text))
	if text == "" {
		// A blank line, or a line that was only a comment.
		return
	}
	if ll.unterminated {
		lf.Drop("line %d: the file ends on a line continuation, so %q is only half a requirement", ll.line, text)
		return
	}
	if strings.HasPrefix(text, "-") {
		readOption(lf, ll, text)
		return
	}
	spec, options := splitOptions(text)
	// The environment marker says when the requirement applies, not what it pins, so
	// it is cut away and the requirement in front of it is read as usual.
	requirement, _, _ := strings.Cut(spec, ";")
	name, version, ok := splitPin(requirement)
	if !ok {
		lf.Drop("line %d: %q is not a name and one pinned version, so there is nothing to evaluate", ll.line, strings.TrimSpace(requirement))
		return
	}
	hashes := hashesOf(options)
	if len(hashes) == 0 {
		lf.Drop("line %d: %s==%s carries no --hash, so nothing guards the bytes it installs", ll.line, name, version)
		return
	}
	lf.Add(lockfile.Entry{
		Ref: model.PackageRef{Ecosystem: model.PyPI, Name: model.NormalizeName(model.PyPI, name), Version: version},
		// A bare name and version is fetched from an index, and the file names no
		// location of its own for it.
		Source:    lockfile.SourceRegistry,
		Integrity: hashes[0],
		Line:      ll.line,
	})
}

// readOption handles a line that begins with a dash. The two kinds that install
// something are dropped with a reason; everything else configures pip for the whole
// file and is ignored.
func readOption(lf *lockfile.Lockfile, ll *logicalLine, text string) {
	switch {
	case hasOption(text, includeOptions):
		lf.Drop("line %d: %q names another requirements file, which this parser does not follow, so nothing that file pins is in these entries", ll.line, text)
	case hasOption(text, editableOptions):
		lf.Drop("line %d: %q is an editable install, which pins no version in this file", ll.line, text)
	}
}

// hasOption reports whether the line starts with one of the options, as its own
// argument rather than as the beginning of a longer one.
func hasOption(text string, options []string) bool {
	for _, option := range options {
		if text == option {
			return true
		}
		for _, separator := range []string{" ", "=", "\t"} {
			if strings.HasPrefix(text, option+separator) {
				return true
			}
		}
	}
	return false
}

// splitOptions cuts a requirement into the requirement itself and the options that
// follow it. pip writes a requirement as a specifier and then its options, so
// everything from the first argument beginning with a dash is options; a marker
// holds no such argument, which is why it stays with the specifier.
func splitOptions(text string) (spec string, options []string) {
	fields := strings.Fields(text)
	for i, field := range fields {
		if strings.HasPrefix(field, "-") {
			return strings.Join(fields[:i], " "), fields[i:]
		}
	}
	return strings.Join(fields, " "), nil
}

// hashesOf reads the hashes out of a requirement's options, as written. pip accepts
// "--hash=sha256:..." and "--hash sha256:...", and a hash without an algorithm is
// not one pip would accept either.
func hashesOf(options []string) []string {
	var hashes []string
	for i := 0; i < len(options); i++ {
		var value string
		switch {
		case options[i] == hashOption && i+1 < len(options):
			value = options[i+1]
			i++
		case strings.HasPrefix(options[i], hashOption+"="):
			value = strings.TrimPrefix(options[i], hashOption+"=")
		default:
			continue
		}
		if algorithm, digest, ok := strings.Cut(value, ":"); ok && algorithm != "" && digest != "" {
			hashes = append(hashes, value)
		}
	}
	return hashes
}

// splitPin reads "name==version" out of a requirement, with the extras the name may
// carry cut away. It reports false for everything else: a range, a bare name, a URL,
// an arbitrary equality "===", a compound specifier and a wildcard all fail here,
// and the caller drops the line with a reason.
func splitPin(requirement string) (name, version string, ok bool) {
	requirement = strings.TrimSpace(requirement)
	name, version, ok = strings.Cut(requirement, "==")
	if !ok {
		return "", "", false
	}
	// Extras name the parts of a distribution to install, not the distribution, so
	// "requests[socks]" is an entry for requests.
	if i := strings.Index(name, "["); i >= 0 {
		if !strings.HasSuffix(strings.TrimSpace(name), "]") {
			return "", "", false
		}
		name = name[:i]
	}
	name = strings.TrimSpace(name)
	version = strings.TrimSpace(version)
	if name == "" || version == "" || !validName(name) || strings.ContainsAny(version, versionOperators) {
		return "", "", false
	}
	return name, version, true
}

// validName reports whether the text is a PEP 508 distribution name, which is what
// separates a requirement from a URL or from anything else on the line.
func validName(name string) bool {
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-' || c == '_' || c == '.':
		default:
			return false
		}
	}
	return true
}

// stripComment cuts a comment off a line. pip starts one at a "#" that begins the
// line or follows whitespace, so a "#" inside a value is left alone.
func stripComment(text string) string {
	for i := 0; i < len(text); i++ {
		if text[i] != '#' {
			continue
		}
		if i == 0 || text[i-1] == ' ' || text[i-1] == '\t' {
			return text[:i]
		}
	}
	return text
}
