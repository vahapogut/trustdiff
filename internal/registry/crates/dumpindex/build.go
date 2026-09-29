package dumpindex

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/model/version"
)

// The selected columns were verified against crates.io's dump-db.toml and
// export.sql snapshot at 0498d51e0f06f379c8e570db1628763ad4be7927 on 2026-09-29.
// Columns are addressed by header, not by an unstable positional order.
func build(ctx context.Context, stage string, o *Options) (*Meta, error) {
	b, err := readRegular(filepath.Join(stage, "metadata.json"), maxMeta)
	if err != nil {
		return nil, err
	}
	var upstream struct {
		Timestamp time.Time `json:"timestamp"`
		Commit    string    `json:"crates_io_commit"`
	}
	if err := json.Unmarshal(b, &upstream); err != nil {
		return nil, err
	}
	if upstream.Timestamp.IsZero() || upstream.Commit == "" {
		return nil, errors.New("dump metadata lacks timestamp or crates_io_commit")
	}
	meta := &Meta{SnapshotAt: upstream.Timestamp, UpstreamCommit: upstream.Commit, Shards: map[string]Shard{}}
	crates := map[string]*Record{}
	names := map[string]bool{}
	err = readCSV(ctx, stage, "crates.csv", []string{"id", "name", "created_at", "updated_at"}, o, func(row row) error {
		id, name := row.get("id"), row.get("name")
		if !numericID(id) || !validName(name) {
			return errors.New("invalid crate id or name")
		}
		if crates[id] != nil || names[canonical(name)] {
			return errors.New("duplicate crate id or canonical name")
		}
		created, err := parseTime(row.get("created_at"))
		if err != nil {
			return err
		}
		modified, err := parseTime(row.get("updated_at"))
		if err != nil {
			return err
		}
		if len(crates) >= 2_000_000 {
			return errors.New("too many crates")
		}
		crates[id] = &Record{Name: name, Created: created, Modified: modified, Versions: []Version{}}
		names[canonical(name)] = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	meta.Crates = len(crates)
	users := map[string]string{}
	err = readCSV(ctx, stage, "users.csv", []string{"id", "gh_login"}, o, func(row row) error {
		id := row.get("id")
		if !numericID(id) {
			return errors.New("invalid user id")
		}
		if _, ok := users[id]; ok {
			return errors.New("duplicate user id")
		}
		// EncodablePublicUser maps API login from users.username (upstream
		// crates_io_api_types/src/lib.rs, verified 2026-09-29). Older dumps
		// predate that column and use gh_login for the same API identity.
		login := row.get("username")
		if login == "" {
			login = row.get("gh_login")
		}
		if len(login) > 256 || len(users) >= 2_000_000 {
			return errors.New("user identity limit exceeded")
		}
		users[id] = login
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := loadOwners(ctx, stage, o, crates, users); err != nil {
		return nil, err
	}
	spools := map[string]*spool{}
	defer func() {
		for _, s := range spools {
			_ = s.file.Close()
		}
	}()
	var spoolBytes int64
	err = readCSV(ctx, stage, "versions.csv", []string{"crate_id", "num", "created_at", "published_by", "yanked", "tar_sha256"}, o, func(row row) error {
		r := crates[row.get("crate_id")]
		if r == nil {
			return errors.New("version references an unknown crate")
		}
		v := Version{Num: row.get("num"), Checksum: strings.TrimPrefix(row.get("tar_sha256"), `\x`)}
		if len(v.Num) > 256 {
			return errors.New("version exceeds size limit")
		}
		if _, err := version.Parse(model.Cargo, v.Num); err != nil {
			return err
		}
		var err error
		v.Published, err = parseTime(row.get("created_at"))
		if err != nil {
			return err
		}
		v.Yanked, err = strconv.ParseBool(row.get("yanked"))
		if err != nil {
			return err
		}
		if !validHash(v.Checksum) {
			return errors.New("version has an invalid SHA-256 checksum")
		}
		if id := row.get("published_by"); id != "" {
			var ok bool
			v.Publisher, ok = users[id]
			if !ok {
				return errors.New("version references an unknown publishing user")
			}
		}
		name := shardFor(r.Name)
		s := spools[name]
		if s == nil {
			// #nosec G304 -- name is two SHA-256 hex digits and stage is a private MkdirTemp directory.
			f, err := os.OpenFile(filepath.Join(stage, name+".rows"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
			if err != nil {
				return err
			}
			s = &spool{file: f, writer: bufio.NewWriterSize(f, 64<<10)}
			spools[name] = s
		}
		line, err := json.Marshal(versionRow{Name: canonical(r.Name), Version: v})
		if err != nil {
			return err
		}
		line = append(line, '\n')
		s.bytes += int64(len(line))
		spoolBytes += int64(len(line))
		if s.bytes > maxShard || spoolBytes > o.MaxIndexBytes {
			return errors.New("partitioned versions exceed index byte limit")
		}
		if _, err := s.writer.Write(line); err != nil {
			return err
		}
		meta.Versions++
		return nil
	})
	if err != nil {
		return nil, err
	}
	for _, s := range spools {
		if err := errors.Join(s.writer.Flush(), s.file.Close()); err != nil {
			return nil, err
		}
	}
	if meta.Crates == 0 || meta.Versions == 0 {
		return nil, errors.New("empty crates or versions table")
	}
	if err := os.Mkdir(filepath.Join(stage, "index"), 0o700); err != nil {
		return nil, err
	}
	// Only one shard is assembled at a time. The maps retained across shards
	// hold small crate/user identities, never the full version database.
	groups := map[string]map[string]*Record{}
	for _, r := range crates {
		shard := shardFor(r.Name)
		if groups[shard] == nil {
			groups[shard] = map[string]*Record{}
		}
		groups[shard][canonical(r.Name)] = r
	}
	for name, group := range groups {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if spools[name] != nil {
			if err := assemble(ctx, filepath.Join(stage, name+".rows"), group); err != nil {
				return nil, err
			}
		}
		b, err := json.Marshal(group)
		if err != nil {
			return nil, err
		}
		meta.IndexBytes += int64(len(b))
		if len(b) > maxShard || meta.IndexBytes > o.MaxIndexBytes {
			return nil, errors.New("encoded index exceeds byte limit")
		}
		h := sha256.Sum256(b)
		meta.Shards[name] = Shard{Bytes: int64(len(b)), SHA256: hex.EncodeToString(h[:])}
		if err := os.WriteFile(filepath.Join(stage, "index", name), b, 0o600); err != nil {
			return nil, err
		}
		for _, r := range group {
			r.Versions = nil
		}
	}
	return meta, nil
}

type spool struct {
	file   *os.File
	writer *bufio.Writer
	bytes  int64
}
type versionRow struct {
	Name    string
	Version Version
}

func assemble(ctx context.Context, file string, records map[string]*Record) error {
	// #nosec G304 -- the caller constructs this path from its private stage and a hash shard name.
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	dec := json.NewDecoder(&contextReader{ctx: ctx, reader: f})
	seen := map[string]bool{}
	for {
		var row versionRow
		if err := dec.Decode(&row); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return err
		}
		key := row.Name + "@" + row.Version.Num
		if seen[key] {
			return errors.New("duplicate crate version")
		}
		seen[key] = true
		r := records[row.Name]
		if r == nil {
			return errors.New("partitioned version has an unknown crate")
		}
		r.Versions = append(r.Versions, row.Version)
	}
	return nil
}

func loadOwners(ctx context.Context, stage string, o *Options, crates map[string]*Record, users map[string]string) error {
	if _, err := os.Stat(filepath.Join(stage, "crate_owners.csv")); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	teams := map[string]string{}
	if _, err := os.Stat(filepath.Join(stage, "teams.csv")); err == nil {
		if err := readCSV(ctx, stage, "teams.csv", []string{"id", "login"}, o, func(row row) error {
			id, login := row.get("id"), row.get("login")
			if !numericID(id) || login == "" || len(login) > 256 || len(teams) >= 2_000_000 {
				return errors.New("invalid team identity")
			}
			if _, ok := teams[id]; ok {
				return errors.New("duplicate team")
			}
			teams[id] = login
			return nil
		}); err != nil {
			return err
		}
	}
	for _, r := range crates {
		r.OwnersKnown = true
	}
	return readCSV(ctx, stage, "crate_owners.csv", []string{"crate_id", "owner_id", "owner_kind"}, o, func(row row) error {
		r := crates[row.get("crate_id")]
		if r == nil {
			return errors.New("owner references unknown crate")
		}
		var login string
		switch row.get("owner_kind") {
		case "0":
			login = users[row.get("owner_id")]
		case "1":
			login = teams[row.get("owner_id")]
		default:
			return errors.New("unknown owner kind")
		}
		if login == "" {
			r.OwnersKnown = false
			return nil
		}
		if len(r.Owners) >= 10000 {
			return errors.New("crate owner count exceeds limit")
		}
		r.Owners = append(r.Owners, model.Publisher{Name: login})
		return nil
	})
}

type row struct {
	values  []string
	columns map[string]int
}

func (r row) get(name string) string {
	if n, ok := r.columns[name]; ok {
		return r.values[n]
	}
	return ""
}

// A CSV reader buffers at most one 4 KiB lookahead block beyond this budget.
// Resetting the budget between logical records also bounds quoted multiline rows.
type rowReader struct {
	reader    io.Reader
	remaining int64
}

func (r *rowReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, errors.New("CSV record exceeds byte limit")
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	n, err := r.reader.Read(p)
	r.remaining -= int64(n)
	return n, err
}

func readCSV(ctx context.Context, stage, name string, required []string, o *Options, consume func(row) error) error {
	// #nosec G304 -- name is a fixed selected table name; stage is a private MkdirTemp directory.
	f, err := os.Open(filepath.Join(stage, name))
	if err != nil {
		return err
	}
	defer f.Close()
	bounded := &rowReader{reader: &contextReader{ctx: ctx, reader: f}, remaining: o.MaxRowBytes}
	r := csv.NewReader(bounded)
	header, err := r.Read()
	if err != nil {
		return fmt.Errorf("%s header: %w", name, err)
	}
	columns := make(map[string]int, len(header))
	for n, col := range header {
		if _, ok := columns[col]; ok {
			return fmt.Errorf("%s has duplicate header %s", name, col)
		}
		columns[col] = n
	}
	for _, col := range required {
		if _, ok := columns[col]; !ok {
			return fmt.Errorf("%s lacks required column %s", name, col)
		}
	}
	for n := 0; ; n++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		bounded.remaining = o.MaxRowBytes
		values, err := r.Read()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%s row %d: %w", name, n+2, err)
		}
		if n >= o.MaxRecords {
			return fmt.Errorf("%s exceeds row count limit", name)
		}
		if err := consume(row{values: values, columns: columns}); err != nil {
			return fmt.Errorf("%s row %d: %w", name, n+2, err)
		}
	}
}

func numericID(s string) bool { n, err := strconv.ParseUint(s, 10, 64); return err == nil && n > 0 }
func validName(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for n, c := range []byte(s) {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || (n > 0 && (c == '_' || c == '-')) {
			continue
		}
		return false
	}
	return true
}

func parseTime(s string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05.999999999Z07:00", "2006-01-02 15:04:05.999999999Z07", "2006-01-02 15:04:05.999999999"} {
		if t, err := time.Parse(layout, s); err == nil && !t.IsZero() {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid dump timestamp %q", s)
}
