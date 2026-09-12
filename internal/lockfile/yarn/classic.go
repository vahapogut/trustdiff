package yarn

import (
	"fmt"
	"strings"

	"github.com/vahapogut/trustdiff/internal/lockfile"
	"github.com/vahapogut/trustdiff/internal/model"
)

// The yarn.lock Yarn 1 writes is a different file from the one Yarn 2 writes, and
// both are called yarn.lock. Yarn 1 is still what a great many repositories carry,
// React's among them, and this file reads it.
//
// The format is line oriented rather than yaml. An entry is a key line of comma
// separated descriptors, each quoted only where it has to be, and a block of two
// space indented fields whose values are quoted:
//
//	"@babel/code-frame@^7.0.0", "@babel/code-frame@^7.24.2":
//	  version "7.24.2"
//	  resolved "https://registry.yarnpkg.com/@babel/code-frame/-/code-frame-7.24.2.tgz#718b4b19"
//	  integrity sha512-y5+tLQyV8pg3fsiln67BVLD1P13Eg4lh5RW9mF0zUuvLrv9uIQ4MCL+CRT+FTsBlBjcIan6PGsLcBN0m3ClUyQ==
//	  dependencies:
//	    "@babel/highlight" "^7.24.2"
//
// What each field becomes:
//
//   - The name comes from the first descriptor, and from the alias it names where
//     the range is an "npm:" one: "@typescript-eslint/parser-v2@npm:@typescript-eslint/parser@^2.26.0"
//     installs @typescript-eslint/parser, which is the name every lookup wants.
//   - The version is the "version" field. An entry without one is dropped with a
//     reason, the way the Berry parser drops it.
//   - The integrity is the "integrity" field. Where there is none, which is every
//     entry Yarn wrote before that field existed, the sha1 in the fragment of the
//     resolved URL is the hash the file states, and it is recorded as "sha1-<hex>"
//     so that what a check compares is what the file says.
//   - The source comes from the descriptor's range first, because that is what the
//     manifest asked for, and from the resolved URL otherwise. "file:", "link:" and
//     "portal:" are a directory of the repository; a git remote, a github shorthand
//     and a codeload tarball are a repository; registry.yarnpkg.com and
//     registry.npmjs.org are the registry; any other http URL is a download.
//
// Two things Yarn 1 does not record, and this parser does not invent. There is no
// workspace entry, so no entry is marked direct: Yarn 1 wrote the same file for a
// dependency of the project and for a dependency of a dependency. There is no dev
// or optional marker either. A check that reads those fields sees the zero value
// and says so, which is what it does for every other parser that cannot tell.
const classicVersion = "1"

// classicHeader is the comment Yarn 1 writes at the top of every file it generates.
const classicHeader = "# yarn lockfile v1"

// parseClassic reads a Yarn 1 lockfile. It is called when the file carries no
// __metadata block, which is what tells the two formats apart.
func parseClassic(path string, data []byte) (*lockfile.Lockfile, error) {
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	lines := strings.Split(text, "\n")
	lf := &lockfile.Lockfile{Path: path, Format: formatName, Ecosystem: model.NPM, Version: classicVersion}

	for i := 0; i < len(lines); i++ {
		key, ok := classicKey(lines[i])
		if !ok {
			continue
		}
		line := i + 1
		fields, next := classicFields(lines, i+1)
		classicEntry(lf, key, fields, line)
		i = next - 1
	}
	// A file that yielded nothing and does not even carry Yarn 1's header is not
	// this format either, and saying so is more use than an empty lockfile.
	if len(lf.Entries) == 0 && !strings.Contains(text, classicHeader) {
		return nil, unreadable(data, nil)
	}
	return lf, nil
}

// classicKey returns the descriptors of an entry's key line. A key line starts at
// column zero, is not a comment, and ends with a colon.
func classicKey(line string) (string, bool) {
	if line == "" || strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") || strings.HasPrefix(line, "#") {
		return "", false
	}
	trimmed := strings.TrimRight(line, " \t")
	if !strings.HasSuffix(trimmed, ":") {
		return "", false
	}
	return strings.TrimSuffix(trimmed, ":"), true
}

// classicFields reads the two space indented fields of one entry and returns the
// index of the line that ended it. A nested block, which is what "dependencies:"
// opens, is skipped: what it holds is a range the project did not lock.
func classicFields(lines []string, from int) (map[string]string, int) {
	fields := map[string]string{}
	i := from
	for ; i < len(lines); i++ {
		line := lines[i]
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			break
		}
		if strings.HasPrefix(line, "    ") || strings.HasPrefix(line, "\t\t") {
			continue
		}
		text := strings.TrimSpace(line)
		if strings.HasSuffix(text, ":") {
			continue
		}
		key, value, ok := strings.Cut(text, " ")
		if !ok {
			continue
		}
		fields[key] = strings.Trim(strings.TrimSpace(value), `"`)
	}
	return fields, i
}

// classicEntry turns one key and its fields into an entry, or into a line of the
// dropped list saying why it is not one.
func classicEntry(lf *lockfile.Lockfile, key string, fields map[string]string, line int) {
	list := classicDescriptors(key)
	if len(list) == 0 {
		lf.Dropped = append(lf.Dropped, fmt.Sprintf("line %d: an entry whose key is empty", line))
		return
	}
	name, rang := splitDescriptor(list[0])
	if alias, ok := strings.CutPrefix(rang, "npm:"); ok {
		if aliased, _ := splitDescriptor(alias); aliased != "" {
			name = aliased
		}
	}
	if name == "" {
		lf.Dropped = append(lf.Dropped, fmt.Sprintf("line %d: %q names no package", line, list[0]))
		return
	}
	version := fields["version"]
	if version == "" {
		lf.Dropped = append(lf.Dropped, fmt.Sprintf("line %d: %s states no version, so there is nothing to evaluate", line, name))
		return
	}
	resolved := fields["resolved"]
	integrity := fields["integrity"]
	if integrity == "" {
		integrity = classicSHA1(resolved)
	}
	lf.Entries = append(lf.Entries, lockfile.Entry{
		Ref:       model.PackageRef{Ecosystem: model.NPM, Name: model.NormalizeName(model.NPM, name), Version: version},
		Source:    classicSource(rang, resolved),
		Resolved:  resolved,
		Integrity: integrity,
		Line:      line,
	})
}

// classicDescriptors splits a key into its descriptors. Yarn separates them with
// ", " and quotes the ones that need it, so a comma inside a quoted range, which a
// range like ">=1, <2" has, does not split anything.
func classicDescriptors(key string) []string {
	var out []string
	var current strings.Builder
	quoted := false
	for i := 0; i < len(key); i++ {
		c := key[i]
		switch {
		case c == '"':
			quoted = !quoted
		case c == ',' && !quoted:
			out = appendDescriptor(out, current.String())
			current.Reset()
		default:
			current.WriteByte(c)
		}
	}
	return appendDescriptor(out, current.String())
}

func appendDescriptor(out []string, s string) []string {
	if s = strings.TrimSpace(s); s != "" {
		out = append(out, s)
	}
	return out
}

// classicSHA1 reads the hash Yarn 1 wrote into the fragment of a resolved URL,
// which is what a file written before the integrity field carries. It is spelled
// the way an integrity is spelled, so a check reads one thing whichever field it
// came from.
func classicSHA1(resolved string) string {
	_, fragment, ok := strings.Cut(resolved, "#")
	if !ok || fragment == "" {
		return ""
	}
	for i := 0; i < len(fragment); i++ {
		c := fragment[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return ""
		}
	}
	if len(fragment) != 40 {
		return ""
	}
	return "sha1-" + fragment
}

// classicSource says where a version comes from. The range the descriptor carries
// decides it wherever it names a protocol, because that is what the manifest asked
// for; the resolved URL decides the rest.
func classicSource(rang, resolved string) lockfile.Source {
	switch {
	case hasAnyPrefix(rang, "file:", "link:", "portal:"):
		return lockfile.SourcePath
	case hasAnyPrefix(rang, "git:", "git+", "github:", "gitlab:", "bitbucket:"):
		return lockfile.SourceGit
	case gitShorthand(rang):
		return lockfile.SourceGit
	}
	switch {
	case resolved == "":
		return lockfile.SourceUnknown
	case hasAnyPrefix(resolved, "file:", "link:"):
		return lockfile.SourcePath
	case hasAnyPrefix(resolved, "git:", "git+", "ssh:"), strings.Contains(resolved, "codeload.github.com"):
		return lockfile.SourceGit
	case strings.Contains(resolved, "://registry.yarnpkg.com/"), strings.Contains(resolved, "://registry.npmjs.org/"):
		return lockfile.SourceRegistry
	case hasAnyPrefix(resolved, "http://", "https://"):
		return lockfile.SourceURL
	}
	return lockfile.SourceUnknown
}

// gitShorthand reports whether a range is the "owner/repository#ref" form Yarn
// takes for a GitHub repository. A range with a slash and no protocol is that, and
// a version range never carries a slash.
func gitShorthand(rang string) bool {
	if rang == "" || strings.Contains(rang, "://") || strings.HasPrefix(rang, "npm:") {
		return false
	}
	owner, rest, ok := strings.Cut(rang, "/")
	return ok && owner != "" && rest != "" && !strings.ContainsAny(owner, " ><=^~|")
}

func hasAnyPrefix(s string, prefixes ...string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}
