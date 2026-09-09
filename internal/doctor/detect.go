// The detection half of doctor: which package managers a repository uses, in
// which directories, at which version, and which files each one is configured
// through. The package comment is in doctor.go.
//
// Detection is a walk and a table. A file name means something to one or more
// managers, and some of those names prove the manager is used while others only
// say the manager would read the file if it were: a pnpm-lock.yaml exists because
// somebody ran pnpm, a package.json exists in every Node repository whatever
// installs it. A manager counts as present in a directory when something in that
// directory proves it, which is what makes a monorepo report one manager per
// directory instead of one for the whole tree.
//
// Versions come from the repository's own files first and from the machine last.
// The order is deliberate: a packageManager pin is what corepack will actually
// run, a Yarn release checked into .yarn/releases is what Yarn will actually be,
// and a lockfile marker is a floor rather than a number, so it is used as a floor
// and said to be one. Running a package manager is the last resort, is off unless
// the caller asks for it, and is done with a fixed argument list outside the
// repository, because the version of a package manager is not worth handing a
// repository the ability to choose what runs.

package doctor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"go.yaml.in/yaml/v3"
)

// DetectOptions are the choices a scan makes before it starts. It is separate
// from the Options one evaluation run works under because detection happens
// first and answers a different question: a caller can detect a repository's
// managers and report them without ever evaluating a rule.
type DetectOptions struct {
	// RunBinaries allows Detect to ask a package manager installed on this machine
	// for its version, and only when the repository's own files could not answer.
	// It is off by default because running a program is a different kind of act
	// from reading a file, and the caller, not this package, decides whether a scan
	// is allowed to do it.
	RunBinaries bool
}

// prunedDirs are the directory names the walk never descends into. They hold
// installed copies of other people's packages, build output or git's own storage,
// and a lockfile or a manifest inside one of them belongs to a dependency rather
// than to the repository being examined. internal/cli prunes the same names for
// the same reason.
var prunedDirs = map[string]bool{
	".git":         true,
	".venv":        true,
	"dist":         true,
	"node_modules": true,
	"target":       true,
	"vendor":       true,
	// testdata holds fixtures: a lockfile a parser is tested against, a workflow
	// written to be wrong on purpose. The Go tool ignores the name for the same
	// reason, and a scorecard that reported a fixture as a finding would teach
	// people that the scorecard is noise.
	"testdata": true,
}

// manifestLimit is how much of a manifest is read. A package.json or a
// pyproject.toml that is larger than this is not one this reads two fields out
// of, and a scan must not be made to allocate whatever a repository committed.
const manifestLimit = 4 << 20

// markerLimit is how much of a lockfile's head is read to find its version
// marker. Every one of these formats writes the marker in its first few lines,
// while the file itself can be tens of megabytes, so nothing reads further.
const markerLimit = 64 << 10

// binaryTimeout is how long a version command is given. A package manager that
// cannot say its own version in three seconds is one that is doing something
// else, and a scan waits for no such thing.
const binaryTimeout = 3 * time.Second

// Detect walks root and reports the package managers the repository uses, one
// Manager per manager per directory that has its own lockfile, manifest or
// configuration for it.
//
// The second return value is the notes: everything the walk was refused, could
// not parse or could not ask. They are not errors, because a directory whose
// permissions differ or a package.json somebody left half-written must not stop a
// scan of the rest of the tree, and because a caller that reports nothing about
// what it skipped is claiming a completeness it does not have. An error is
// returned only when the walk itself could not happen: root is missing, root is
// not a directory, or the context was canceled.
//
// Paths in Manager.Files are relative to root with forward slashes on every
// platform, so a report says the same thing on Windows as on Linux.
func Detect(ctx context.Context, root string, opts DetectOptions) ([]Manager, []string, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, nil, fmt.Errorf("scan %s: %w", root, err)
	}
	if !info.IsDir() {
		return nil, nil, fmt.Errorf("scan %s: not a directory", root)
	}

	d := &detector{
		root:   root,
		opts:   opts,
		found:  make(map[managerKey]*instance),
		pins:   make(map[string]managerPin),
		probed: make(map[ManagerID]probe),
	}
	if err := d.walk(ctx); err != nil {
		return nil, d.notes, err
	}
	d.readManifests()

	managers := d.managers()
	for i := range managers {
		d.resolveVersion(ctx, &managers[i])
	}
	return managers, d.notes, nil
}

// managerKey identifies one manager instance: which manager, and the directory it
// manages relative to the scan root.
type managerKey struct {
	id   ManagerID
	root string
}

// instance is one manager instance while it is being built. The sets dedupe:
// several files can prove the same manager, and one file can be claimed by a
// manager twice through two different rules.
type instance struct {
	key      managerKey
	files    map[string]bool
	evidence map[string]bool
	// proven is true once something in the directory showed the manager is
	// actually used, rather than only that it would read a file that is there.
	proven bool
}

// managerPin is a packageManager field as package.json wrote it: which manager it
// names and which version it pins, the version empty when the field named a
// manager without one.
type managerPin struct {
	id      ManagerID
	version string
}

// probe is the answer a version command gave, remembered so that a monorepo with
// five npm directories runs npm once rather than five times.
type probe struct {
	version string
	err     error
}

// detector carries one scan.
type detector struct {
	root string
	opts DetectOptions

	notes  []string
	found  map[managerKey]*instance
	pins   map[string]managerPin
	probed map[ManagerID]probe

	// manifests are the package.json and pyproject.toml paths the walk saw,
	// relative to the scan root. They are read after the walk rather than during
	// it, so the walk stays a walk and the reading order is the lexical one.
	manifests []string
}

// note records something the scan could not do, in the words the report prints.
func (d *detector) note(format string, args ...any) {
	d.notes = append(d.notes, fmt.Sprintf(format, args...))
}

// walk visits every file under the scan root and records what each one claims.
//
// A directory that cannot be read is a note and not a failure: a scan of a large
// tree must not stop at the one directory whose permissions differ, and a subtree
// nobody looked at is not a pass, so it has to be said out loud instead.
func (d *detector) walk(ctx context.Context) error {
	err := filepath.WalkDir(d.root, func(p string, entry fs.DirEntry, walkErr error) error {
		// Cancellation stops the walk rather than being reported as a note: an
		// answer assembled from half a tree is not the answer that was asked for.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		rel := d.relative(p)
		if walkErr != nil {
			if entry != nil && entry.IsDir() {
				d.note("%s could not be read (%s), so the package managers inside it were not detected", rel, reason(walkErr))
				return fs.SkipDir
			}
			d.note("%s could not be read (%s)", rel, reason(walkErr))
			return nil
		}
		if entry.IsDir() {
			if p != d.root && prunedDirs[entry.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		// Only plain files are read. git records a symbolic link as a blob holding
		// the link text, so a pull request can commit package-lock.json as a link to
		// any path on the runner, and following it would report a manager, and later
		// read settings, from outside the tree being examined.
		claims := claimsFor(rel)
		if !entry.Type().IsRegular() {
			if len(claims) > 0 {
				d.note("%s is not a plain file, so it was not read", rel)
			}
			return nil
		}
		for _, c := range claims {
			d.add(c, rel)
		}
		switch path.Base(rel) {
		case "package.json", "pyproject.toml":
			d.manifests = append(d.manifests, rel)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("walk %s: %w", d.root, err)
	}
	return nil
}

// relative names a path the way a report should: relative to the scan root and
// separated by forward slashes. A path that cannot be made relative, which on
// Windows means a different volume, is reported whole rather than dropped, since
// a note that names no file is worse than one that names an absolute one.
func (d *detector) relative(p string) string {
	rel, err := filepath.Rel(d.root, p)
	if err != nil {
		return filepath.ToSlash(p)
	}
	return filepath.ToSlash(rel)
}

// real turns a path this package reports into the path this machine opens.
func (d *detector) real(rel string) string {
	return filepath.Join(d.root, filepath.FromSlash(rel))
}

// claim is what one file says: which manager it belongs to, which directory that
// manager manages, and whether its presence alone proves the manager is used.
type claim struct {
	id   ManagerID
	root string
	// proves separates a file that exists because the manager is used from one the
	// manager merely reads. A pnpm-lock.yaml is written by pnpm and by nothing
	// else; a package.json is in every Node repository whatever installs it, so it
	// is listed among a manager's files without ever being the reason it counted.
	proves bool
}

// claimsFor says what one file name means, given as a path relative to the scan
// root. It is the whole of the detection table: adding a manager or a file name
// is an entry here and a case in the test.
func claimsFor(rel string) []claim {
	dir := path.Dir(rel)
	base := path.Base(rel)

	// Three managers are configured somewhere other than the directory they act
	// on, so their root is the repository the .github or .yarn directory belongs
	// to rather than the directory the file sits in.
	switch {
	case path.Base(dir) == ".github" && (base == "dependabot.yml" || base == "dependabot.yaml"):
		return []claim{{Dependabot, path.Dir(dir), true}}
	case path.Base(dir) == "workflows" && path.Base(path.Dir(dir)) == ".github" && isYAMLName(base):
		return []claim{{Actions, path.Dir(path.Dir(dir)), true}}
	case path.Base(dir) == "releases" && path.Base(path.Dir(dir)) == ".yarn":
		// A Yarn release committed into the repository is the Yarn that runs, which
		// is both the strongest evidence Yarn is used and the exact version of it.
		return []claim{{Yarn, path.Dir(path.Dir(dir)), true}}
	}

	switch base {
	case "package.json":
		// The manifest of every Node manager, and where Renovate's configuration
		// lives when the repository keeps it there. None of that is evidence by
		// itself; the fields inside are, and readManifests reads them.
		return []claim{{NPM, dir, false}, {PNPM, dir, false}, {Yarn, dir, false}, {Bun, dir, false}, {Renovate, dir, false}}
	case "package-lock.json":
		return []claim{{NPM, dir, true}}
	case ".npmrc":
		// pnpm reads .npmrc too, and several of its hardening settings can live
		// there, so the file is listed among pnpm's files. It only proves npm.
		return []claim{{NPM, dir, true}, {PNPM, dir, false}}
	case "pnpm-lock.yaml", "pnpm-workspace.yaml":
		return []claim{{PNPM, dir, true}}
	case "yarn.lock", ".yarnrc.yml":
		return []claim{{Yarn, dir, true}}
	case "bun.lock", "bun.lockb", "bunfig.toml":
		return []claim{{Bun, dir, true}}
	case "deno.json", "deno.jsonc", "deno.lock":
		return []claim{{Deno, dir, true}}
	case "uv.lock", "uv.toml":
		return []claim{{UV, dir, true}}
	case "pyproject.toml":
		// Shared by uv and Poetry and used by neither unless it holds their table.
		return []claim{{UV, dir, false}, {Poetry, dir, false}}
	case "poetry.lock", "poetry.toml":
		return []claim{{Poetry, dir, true}}
	case "pip.conf", "pip.ini":
		return []claim{{Pip, dir, true}}
	case "Cargo.toml", "Cargo.lock":
		return []claim{{Cargo, dir, true}}
	case "renovate.json", "renovate.json5", ".renovaterc", ".renovaterc.json":
		return []claim{{Renovate, dir, true}}
	}

	// requirements.txt, requirements-dev.txt, requirements.prod.txt: pip's file has
	// no fixed name beyond the prefix, and every one of them is a file pip installs
	// from.
	if strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt") {
		return []claim{{Pip, dir, true}}
	}
	return nil
}

// isYAMLName reports whether a file name is one a workflow can be written in.
func isYAMLName(base string) bool {
	return strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml")
}

// add records one file against one manager instance.
func (d *detector) add(c claim, file string) {
	key := managerKey{c.id, c.root}
	inst := d.found[key]
	if inst == nil {
		inst = &instance{key: key, files: make(map[string]bool), evidence: make(map[string]bool)}
		d.found[key] = inst
	}
	inst.files[file] = true
	if !c.proves {
		return
	}
	inst.proven = true
	// Evidence is written the way a person reading about this manager would say
	// it, relative to the directory the manager manages, so a monorepo's lines are
	// short and the same whichever directory they came from. The exception is the
	// workflows, which are one line however many files there are: a repository
	// with forty of them has one reason, not forty.
	if c.id == Actions {
		inst.evidence["the workflows in .github/workflows"] = true
		return
	}
	inst.evidence[relativeToManager(c.root, file)] = true
}

// prove records a manager that a field inside a manifest showed is used, with the
// sentence that says which field it was.
func (d *detector) prove(id ManagerID, root, file, evidence string) {
	d.add(claim{id: id, root: root}, file)
	inst := d.found[managerKey{id, root}]
	inst.proven = true
	inst.evidence[evidence] = true
}

// relativeToManager names a file the way the manager whose root it is under would
// name it.
func relativeToManager(root, file string) string {
	if root == "." {
		return file
	}
	return strings.TrimPrefix(file, root+"/")
}

// readManifests reads the two files whose contents, rather than whose existence,
// decide whether a manager is used: package.json, which pins a Node manager
// through packageManager and can carry Renovate's configuration, and
// pyproject.toml, whose [tool.uv] and [tool.poetry] tables say which of the two
// Python managers owns the project.
func (d *detector) readManifests() {
	for _, rel := range d.manifests {
		dir := path.Dir(rel)
		data, err := readLimited(d.real(rel), manifestLimit)
		if err != nil {
			d.note("%s could not be read (%s)", rel, reason(err))
			continue
		}
		if path.Base(rel) == "package.json" {
			d.readPackageJSON(rel, dir, data)
			continue
		}
		d.readPyproject(rel, dir, data)
	}
}

// packageJSON is the part of a package.json this reads. The Renovate
// configuration is kept raw because only its presence matters here.
type packageJSON struct {
	PackageManager string          `json:"packageManager"`
	Renovate       json.RawMessage `json:"renovate"`
}

// readPackageJSON records the packageManager pin and the Renovate configuration
// of one package.json.
func (d *detector) readPackageJSON(rel, dir string, data []byte) {
	var doc packageJSON
	if err := json.Unmarshal(data, &doc); err != nil {
		d.note("%s could not be read (%s), so any packageManager pin in it was not used", rel, err)
		return
	}
	if len(doc.Renovate) > 0 && string(doc.Renovate) != "null" {
		d.prove(Renovate, dir, rel, "the renovate key of package.json")
	}
	if doc.PackageManager == "" {
		return
	}
	id, version, ok := parsePackageManager(doc.PackageManager)
	if !ok {
		d.note("%s states packageManager %q, which names no manager doctor knows", rel, doc.PackageManager)
		return
	}
	d.prove(id, dir, rel, "the packageManager field of package.json")
	d.pins[dir] = managerPin{id: id, version: version}
}

// parsePackageManager reads corepack's spelling of a pin: "pnpm@11.2.0", or
// "pnpm@11.2.0+sha512-..." once corepack has recorded the hash of the release it
// downloaded. The hash is not a part of the version and is dropped. A field that
// names a manager without a version is still a manager, so the version comes back
// empty rather than the whole field being refused.
func parsePackageManager(field string) (ManagerID, string, bool) {
	name, version, _ := strings.Cut(strings.TrimSpace(field), "@")
	if hash := strings.IndexByte(version, '+'); hash >= 0 {
		version = version[:hash]
	}
	switch ManagerID(strings.ToLower(name)) {
	case NPM:
		return NPM, version, true
	case PNPM:
		return PNPM, version, true
	case Yarn:
		return Yarn, version, true
	case Bun:
		return Bun, version, true
	}
	return "", "", false
}

// readPyproject records which Python manager owns a pyproject.toml. Both tables
// can be there at once, which is what a project halfway through a migration looks
// like, and both are reported.
func (d *detector) readPyproject(rel, dir string, data []byte) {
	var doc struct {
		Tool map[string]any `toml:"tool"`
	}
	if err := toml.Unmarshal(data, &doc); err != nil {
		d.note("%s could not be read (%s), so its [tool] tables were not used", rel, err)
		return
	}
	if _, ok := doc.Tool["uv"]; ok {
		d.prove(UV, dir, rel, "the [tool.uv] table of pyproject.toml")
	}
	if _, ok := doc.Tool["poetry"]; ok {
		d.prove(Poetry, dir, rel, "the [tool.poetry] table of pyproject.toml")
	}
}

// managers turns what the walk found into the answer: the instances something
// proved, each with its files and its evidence sorted, ordered by manager and
// then by directory so that two runs over one tree report the same list in the
// same order.
func (d *detector) managers() []Manager {
	out := make([]Manager, 0, len(d.found))
	for _, inst := range d.found {
		if !inst.proven {
			continue
		}
		out = append(out, Manager{
			ID:       inst.key.id,
			Root:     inst.key.root,
			Evidence: sortedKeys(inst.evidence),
			Files:    sortedKeys(inst.files),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ID != out[j].ID {
			return out[i].ID < out[j].ID
		}
		return out[i].Root < out[j].Root
	})
	return out
}

// sortedKeys is the set turned back into the list a report prints.
func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// resolveVersion fills in Version and VersionSource, in the order the answers
// deserve: what the repository pinned, what it committed, what its lockfile
// implies, and only then what this machine happens to have installed. The first
// one that answers wins, and the source says which it was, because a version that
// came from a lockfile marker is a floor and a version that came from the machine
// may be nothing like the one CI will run.
func (d *detector) resolveVersion(ctx context.Context, m *Manager) {
	if version, source, ok := d.pinnedVersion(m); ok {
		m.Version, m.VersionSource = version, source
		return
	}
	if version, source, ok := d.yarnVersion(m); ok {
		m.Version, m.VersionSource = version, source
		return
	}
	if version, source, ok := d.markerVersion(m); ok {
		m.Version, m.VersionSource = version, source
		return
	}
	if !d.opts.RunBinaries {
		return
	}
	if version, source, ok := d.binaryVersion(ctx, m); ok {
		m.Version, m.VersionSource = version, source
	}
}

// pinnedVersion returns the packageManager pin that governs this manager. The
// search runs from the manager's own directory upward, because that is what
// corepack does: a package.json in a workspace member without a pin is run by the
// pin at the root above it. A pin naming a different manager is not this
// manager's answer and the search continues past it, since a repository whose
// root pins pnpm can still have a directory that npm installs.
func (d *detector) pinnedVersion(m *Manager) (version, source string, ok bool) {
	for dir := m.Root; ; dir = path.Dir(dir) {
		if pin, found := d.pins[dir]; found && pin.id == m.ID && pin.version != "" {
			return pin.version, "the packageManager field of " + path.Join(dir, "package.json"), true
		}
		if dir == "." {
			return "", "", false
		}
	}
}

// yarnReleaseVersion matches the name Yarn gives a release it writes into
// .yarn/releases, which is where the version of a repository that has vendored
// its own Yarn is written down exactly.
var yarnReleaseVersion = regexp.MustCompile(`yarn-(\d+\.\d+\.\d+[0-9A-Za-z.\-]*)\.cjs$`)

// yarnVersion reads the Yarn a repository committed. yarnPath in .yarnrc.yml is
// authoritative when it is set, because it names the file Yarn will run whatever
// else is installed; a release sitting in .yarn/releases without a yarnPath is
// the same answer written down once instead of twice.
func (d *detector) yarnVersion(m *Manager) (version, source string, ok bool) {
	if m.ID != Yarn {
		return "", "", false
	}
	rc := path.Join(m.Root, ".yarnrc.yml")
	if data, err := readLimited(d.real(rc), manifestLimit); err == nil {
		var doc struct {
			YarnPath string `yaml:"yarnPath"`
		}
		if err := yaml.Unmarshal(data, &doc); err != nil {
			d.note("%s could not be read (%s), so its yarnPath was not used", rc, err)
		} else if match := yarnReleaseVersion.FindStringSubmatch(doc.YarnPath); match != nil {
			return match[1], "the yarnPath of " + rc, true
		}
	}
	// Files are sorted, so a directory holding two releases answers with the same
	// one on every run rather than with whichever the filesystem listed first.
	for _, file := range m.Files {
		if !strings.Contains(file, ".yarn/releases/") {
			continue
		}
		if match := yarnReleaseVersion.FindStringSubmatch(file); match != nil {
			return match[1], "the release committed at " + file, true
		}
	}
	return "", "", false
}

// lockfileMarker is the version marker one lockfile format writes, and what the
// value found means.
type lockfileMarker struct {
	// file is the lockfile's name inside the manager's root.
	file string
	// key is what the format calls the marker, for the sentence VersionSource
	// prints.
	key string
	// read pulls the marker's value out of the head of the file.
	read func(head []byte) string
	// floor maps a marker value to the lowest manager version that writes it. A
	// marker is a range and not a number: every npm from 7 onward can write
	// lockfileVersion 3, so a repository whose lockfile says 3 is running npm 7 or
	// anything after it. The floor is what gets recorded, and VersionSource says
	// so, which is the only honest thing to do with a range. A value that is not in
	// the map leaves the version empty on purpose: a mapping nobody checked is
	// worse than no mapping, because the rules already know what to do with a
	// version they do not have.
	floor map[string]string
}

// lockfileMarkers are the markers doctor reads and the mappings it is sure of.
//
// Deliberately absent, and left to the binary or to nothing: pnpm's 5.x
// lockfileVersions, which belong to pnpm 6 and 7 and are older than every setting
// doctor checks; uv.lock's version, which has been 1 for every uv that has ever
// written a lockfile and therefore identifies nothing; every bun.lock
// lockfileVersion but 0; and Cargo.lock versions 1 and 2.
var lockfileMarkers = map[ManagerID]lockfileMarker{
	NPM: {
		file: "package-lock.json",
		key:  "lockfileVersion",
		read: jsonMarker,
		floor: map[string]string{
			// npm 5 introduced package-lock.json at version 1, npm 7 introduced
			// version 2, and version 3 is what npm 7 and later write, by default from
			// npm 9 onward.
			"1": "5.0.0",
			"2": "7.0.0",
			"3": "7.0.0",
		},
	},
	PNPM: {
		file: "pnpm-lock.yaml",
		key:  "lockfileVersion",
		read: yamlMarker,
		floor: map[string]string{
			// pnpm 8 introduced lockfile 6.0 and pnpm 9 introduced 9.0, which pnpm 10
			// and 11 still write.
			"6.0": "8.0.0",
			"9.0": "9.0.0",
		},
	},
	Bun: {
		file: "bun.lock",
		key:  "lockfileVersion",
		read: jsonMarker,
		floor: map[string]string{
			// The text lockfile arrived in Bun 1.1.39, so a bun.lock at all means at
			// least that, whatever the binary lockfile beside it says.
			"0": "1.1.39",
		},
	},
	UV: {
		file:  "uv.lock",
		key:   "version",
		read:  tomlMarker,
		floor: map[string]string{},
	},
	Cargo: {
		file: "Cargo.lock",
		key:  "version",
		read: tomlMarker,
		floor: map[string]string{
			// Cargo 1.53 made lockfile version 3 the default and Cargo 1.78
			// stabilized version 4.
			"3": "1.53.0",
			"4": "1.78.0",
		},
	},
}

// markerVersion reads a lockfile's version marker and turns it into the lowest
// manager version that writes it.
func (d *detector) markerVersion(m *Manager) (version, source string, ok bool) {
	marker, known := lockfileMarkers[m.ID]
	if !known {
		return "", "", false
	}
	rel := path.Join(m.Root, marker.file)
	head, err := readLimited(d.real(rel), markerLimit)
	if err != nil {
		// The lockfile not being there is the ordinary case for a manager detected
		// through a manifest or a configuration file, and is not worth a note.
		if !errors.Is(err, fs.ErrNotExist) {
			d.note("%s could not be read (%s), so its %s was not used", rel, reason(err), marker.key)
		}
		return "", "", false
	}
	value := marker.read(head)
	if value == "" {
		return "", "", false
	}
	floor, mapped := marker.floor[value]
	if !mapped {
		return "", "", false
	}
	return floor, fmt.Sprintf("%s %s of %s, which no %s older than %s writes", marker.key, value, rel, m.ID, floor), true
}

// The markers themselves. The two line oriented ones are anchored to the start
// of a line so that a key of the same name deeper in the document cannot answer
// for the file: pnpm writes its lockfileVersion against the margin, and the two
// TOML lockfiles write their version above the first table. Their ends allow a
// carriage return, because a lockfile checked out on Windows without the eol
// setting this repository uses has CRLF endings and is still that lockfile.
//
// The JSON one is not anchored, because a package-lock.json or a bun.lock can be
// written on one line and then the key follows an opening brace rather than a
// newline. It is safe unanchored: neither format has a lockfileVersion anywhere
// but at the top level, and the pattern only matches a bare number, so a package
// whose install path happened to end in that name would be an object and would
// not match.
var (
	jsonMarkerKey = regexp.MustCompile(`"lockfileVersion"[ \t]*:[ \t]*(\d+)`)
	yamlMarkerKey = regexp.MustCompile(`(?m)^lockfileVersion:[ \t]*['"]?([0-9][0-9.]*)['"]?[ \t\r]*$`)
	tomlMarkerKey = regexp.MustCompile(`(?m)^version[ \t]*=[ \t]*(\d+)[ \t\r]*$`)
)

// jsonMarker reads package-lock.json's and bun.lock's lockfileVersion.
func jsonMarker(head []byte) string { return firstGroup(jsonMarkerKey, head) }

// yamlMarker reads pnpm-lock.yaml's lockfileVersion, which is quoted in the
// versions that matter and bare in the older ones.
func yamlMarker(head []byte) string { return firstGroup(yamlMarkerKey, head) }

// tomlMarker reads uv.lock's and Cargo.lock's version, which is the format's
// version and sits above the first table. Everything from the first table onward
// is cut away first, because a [[package]] entry has a version of its own; that
// one is a quoted string and this pattern only matches a bare number, so the cut
// is a second lock on a door that is already shut.
func tomlMarker(head []byte) string {
	if i := tableStart(head); i >= 0 {
		head = head[:i]
	}
	return firstGroup(tomlMarkerKey, head)
}

// tableStart is the offset of the first line that opens a TOML table, or -1.
func tableStart(head []byte) int {
	for i := 0; i < len(head); i++ {
		if head[i] != '[' {
			continue
		}
		if i == 0 || head[i-1] == '\n' {
			return i
		}
	}
	return -1
}

// firstGroup returns the first capture of the first match, or the empty string.
func firstGroup(re *regexp.Regexp, data []byte) string {
	match := re.FindSubmatch(data)
	if match == nil {
		return ""
	}
	return string(match[1])
}

// versionArgv is every command Detect will ever run, written out here and built
// nowhere else. There is one per manager, the arguments are constants, and
// nothing a repository contains reaches this table, which is what makes running
// any of them safe to do at all.
var versionArgv = map[ManagerID][]string{
	NPM:    {"npm", "-v"},
	PNPM:   {"pnpm", "-v"},
	Yarn:   {"yarn", "-v"},
	Bun:    {"bun", "-v"},
	Deno:   {"deno", "-v"},
	UV:     {"uv", "--version"},
	Pip:    {"pip", "--version"},
	Poetry: {"poetry", "--version"},
	Cargo:  {"cargo", "--version"},
}

// dottedVersion matches a version in the first line a version command prints. The
// outputs differ: npm prints the number alone, cargo prints "cargo 1.78.0
// (54d8815d0 2024-03-26)", pip prints "pip 25.2 from ..." and Poetry prints
// "Poetry (version 2.1.3)". A dotted number is the one thing all of them have,
// and a line that has none means the version is unknown rather than guessed at.
var dottedVersion = regexp.MustCompile(`\d+\.\d+(?:\.\d+)*(?:[-+][0-9A-Za-z.\-]+)?`)

// binaryVersion asks the manager installed on this machine, which is the last
// resort and the only part of detection that runs anything. The answer is
// remembered per manager, so a monorepo with five npm directories runs npm once.
//
// A manager that is not installed, is too slow or answers with something that is
// not a version is not an error: the repository is still what it is, the version
// stays empty, and the note says the question could not be answered so that a
// scorecard reporting a rule as not applicable can say why.
func (d *detector) binaryVersion(ctx context.Context, m *Manager) (version, source string, ok bool) {
	argv, runnable := versionArgv[m.ID]
	if !runnable {
		return "", "", false
	}
	spelled := strings.Join(argv, " ")
	result, asked := d.probed[m.ID]
	if !asked {
		printed, err := runVersionCommand(ctx, argv)
		result = probe{version: printed, err: err}
		d.probed[m.ID] = result
		switch {
		case err != nil:
			d.note("%s could not be run (%s), so the %s version is unknown", spelled, reason(err), m.ID)
		case printed == "":
			d.note("%s printed no version, so the %s version is unknown", spelled, m.ID)
		}
	}
	if result.err != nil || result.version == "" {
		return "", "", false
	}
	return result.version, spelled + ", the binary on this machine", true
}

// runVersionCommand runs one of the fixed commands in versionArgv and returns the
// version out of its first line.
func runVersionCommand(ctx context.Context, argv []string) (string, error) {
	exe, err := exec.LookPath(argv[0])
	if err != nil {
		return "", fmt.Errorf("%s is not on PATH", argv[0])
	}
	ctx, cancel := context.WithTimeout(ctx, binaryTimeout)
	defer cancel()

	// #nosec G204 -- the argument list is one of the constant lists in versionArgv
	// and no part of it is built from anything the repository holds, the executable
	// is what exec.LookPath resolved from the inherited PATH rather than a name
	// resolved at spawn time, no shell is involved so nothing in it is interpreted,
	// and the working directory below is the system temporary directory rather than
	// the repository, so neither a node_modules/.bin inside the tree being scanned
	// nor Windows looking in the current directory first can decide what runs.
	cmd := exec.CommandContext(ctx, exe, argv[1:]...)
	cmd.Dir = os.TempDir()
	cmd.Env = versionEnv()
	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			return "", fmt.Errorf("it did not answer within %s", binaryTimeout)
		}
		return "", err
	}
	first, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
	return dottedVersion.FindString(first), nil
}

// forcedEnv are the variables a version command is run with whatever this process
// inherited. The two corepack ones matter most: without them, asking a package
// manager for its version can make corepack download a package manager or prompt
// for permission to, which is a network fetch and a hang in a command that was
// supposed to read a number. NO_UPDATE_NOTIFIER stops the same kind of surprise
// from the npm side. Everything else, PATH included, is inherited unchanged.
var forcedEnv = []struct{ name, value string }{
	{"COREPACK_ENABLE_AUTO_PIN", "0"},
	{"COREPACK_ENABLE_DOWNLOAD_PROMPT", "0"},
	{"NO_UPDATE_NOTIFIER", "1"},
}

// versionEnv is this process's environment with those three forced. The inherited
// copies are dropped rather than left to be overridden later in the list, because
// which of two entries with one name wins is a detail of os/exec and this has to
// be true on both platforms.
func versionEnv() []string {
	forced := make(map[string]bool, len(forcedEnv))
	for _, e := range forcedEnv {
		forced[e.name] = true
	}
	inherited := os.Environ()
	env := make([]string, 0, len(inherited)+len(forcedEnv))
	for _, entry := range inherited {
		name, _, ok := strings.Cut(entry, "=")
		if ok && forced[strings.ToUpper(name)] {
			continue
		}
		env = append(env, entry)
	}
	for _, e := range forcedEnv {
		env = append(env, e.name+"="+e.value)
	}
	return env
}

// readLimited reads at most limit bytes of a file, and only if it is a plain
// file. The link check is the same one internal/cli applies to a lockfile: a name
// in a repository is text somebody chose, and a link is not a file this reads
// through.
func readLimited(realPath string, limit int64) ([]byte, error) {
	info, err := os.Lstat(realPath)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("not a plain file")
	}
	f, err := os.Open(realPath) // #nosec G304 -- the path is one the walk found under the directory the caller named, and Lstat above has refused everything that is not a plain file
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(io.LimitReader(f, limit))
}

// reason is the part of an error worth printing beside a path the note already
// names: the operating system's own message, without the absolute path it was
// tried on, which would say where this machine keeps the repository and is not
// what the reader needs.
func reason(err error) string {
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		return pathErr.Err.Error()
	}
	return err.Error()
}
