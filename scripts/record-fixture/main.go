// Command record-fixture downloads one registry or advisory response into a
// testdata directory, together with a line in that directory's README that records
// the source URL and the date, so a test can serve it with net/http/httptest instead
// of touching the network.
//
// Usage:
//
//	go run ./scripts/record-fixture [-accept <media type>] [-post <json file>] <url> <testdata path>
//
// Example:
//
//	go run ./scripts/record-fixture https://registry.npmjs.org/express internal/registry/npm/testdata/express.json
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vahapogut/trustdiff/internal/version"
)

func main() {
	accept := flag.String("accept", "", "Accept header to send (for example application/vnd.npm.install-v1+json)")
	post := flag.String("post", "", "send a POST with this JSON file as the body instead of a GET")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: record-fixture [-accept <media type>] [-post <json file>] <url> <testdata path>\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 2 {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(context.Background(), flag.Arg(0), flag.Arg(1), *accept, *post); err != nil {
		fmt.Fprintf(os.Stderr, "record-fixture: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, url, dest, accept, postFile string) error {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	method, body := http.MethodGet, io.Reader(nil)
	if postFile != "" {
		data, err := os.ReadFile(postFile) // #nosec G304 -- the body file is named on the command line by the developer
		if err != nil {
			return fmt.Errorf("read post body: %w", err)
		}
		method, body = http.MethodPost, bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", version.UserAgent())
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return fmt.Errorf("read %s: %w", url, err)
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("fetch %s: HTTP %d", url, resp.StatusCode)
	}

	if err := os.MkdirAll(filepath.Dir(dest), 0o750); err != nil {
		return err
	}
	if err := os.WriteFile(dest, data, 0o600); err != nil {
		return err
	}
	readme := filepath.Join(filepath.Dir(dest), "README.md")
	line := fmt.Sprintf("- `%s`: %s %s (HTTP %d, %d bytes, recorded %s)\n",
		filepath.Base(dest), method, url, resp.StatusCode, len(data), time.Now().UTC().Format("2006-01-02"))
	if accept != "" {
		line = strings.TrimSuffix(line, "\n") + fmt.Sprintf(" with Accept: %s\n", accept)
	}
	if err := appendReadme(readme, line); err != nil {
		return err
	}
	fmt.Printf("wrote %s (%d bytes, HTTP %d) and noted it in %s\n", dest, len(data), resp.StatusCode, readme)
	return nil
}

// appendReadme creates the README with a header if needed and appends the line,
// replacing an earlier line for the same file so re-recording updates the date.
func appendReadme(path, line string) error {
	existing, err := os.ReadFile(path) // #nosec G304 -- path is derived from the destination the developer named
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	name := line[:strings.Index(line, "`:")+1]
	var out []string
	if len(existing) == 0 {
		out = append(out, "# Recorded fixtures", "", "Real responses recorded once with `go run ./scripts/record-fixture`; tests serve them with httptest. Do not edit by hand.", "")
	} else {
		for _, l := range strings.Split(strings.TrimRight(string(existing), "\n"), "\n") {
			if strings.HasPrefix(l, name) {
				continue
			}
			out = append(out, l)
		}
	}
	out = append(out, strings.TrimSuffix(line, "\n"))
	return os.WriteFile(path, []byte(strings.Join(out, "\n")+"\n"), 0o600) // #nosec G703 -- the README sits next to the destination the developer named
}
