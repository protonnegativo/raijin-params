// Package arjun runs arjun, the HTTP parameter discovery tool, and parses its JSON export.
package arjun

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
)

// ErrNotFound is returned when the arjun binary is not on PATH.
var ErrNotFound = errors.New("arjun binary not found")

// Result is one URL arjun reported for one method: the parameters that changed its response, and the
// headers it sent.
type Result struct {
	URL     string
	Method  string
	Params  []string
	Headers map[string]string
}

// entry is one value of arjun's JSON export, which maps each URL to its result.
type entry struct {
	Params  []string       `json:"params"`
	Method  string         `json:"method"`
	Headers map[string]any `json:"headers"`
}

// Options are the arjun settings Raijin passes through.
type Options struct {
	Binary string
	// Methods are arjun's request methods (-m), one arjun run each: GET, POST, JSON or XML.
	Methods  []string
	Wordlist string
	Rate     int
	Threads  int
	Timeout  int
	Delay    float64
	Extra    []string
	// RawPath, if set, receives each run's JSON export unchanged, one after the other.
	RawPath string
}

// Run looks for parameters on the targets, once per method, and returns every result, plus the last
// stderr lines if arjun failed.
func Run(ctx context.Context, targets []string, opt Options) ([]Result, string, error) {
	bin := opt.Binary
	if bin == "" {
		bin = "arjun"
	}
	path, err := exec.LookPath(bin)
	if err != nil {
		return nil, "", ErrNotFound
	}
	dir, err := os.MkdirTemp("", "raijin-params-")
	if err != nil {
		return nil, "", err
	}
	defer os.RemoveAll(dir)
	list := dir + "/targets.txt"
	if err := os.WriteFile(list, []byte(strings.Join(targets, "\n")+"\n"), 0o600); err != nil {
		return nil, "", err
	}
	var raw io.Writer = io.Discard
	if opt.RawPath != "" {
		f, err := os.Create(opt.RawPath)
		if err != nil {
			return nil, "", err
		}
		defer f.Close()
		raw = f
	}

	methods := opt.Methods
	if len(methods) == 0 {
		methods = []string{"GET"}
	}
	var results []Result
	for i, m := range methods {
		out := fmt.Sprintf("%s/out-%d.json", dir, i)
		cmd := exec.CommandContext(ctx, path, Args(list, out, m, opt)...)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		waitErr := cmd.Run()
		// arjun writes the export only when it found something.
		b, err := os.ReadFile(out)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return results, "", err
		}
		if len(b) > 0 {
			if _, err := raw.Write(append(bytes.TrimRight(b, "\n"), '\n')); err != nil {
				return results, "", err
			}
			rs, err := Parse(bytes.NewReader(b))
			results = append(results, rs...)
			if err != nil {
				return results, tail(stderr.String(), 3), err
			}
		}
		if waitErr != nil {
			return results, tail(stderr.String(), 3), fmt.Errorf("arjun -m %s exited: %w", m, waitErr)
		}
	}
	return results, "", nil
}

// Args builds the arjun command line for one method. -q keeps arjun's progress lines out of the way:
// everything Raijin reads is in the JSON export.
func Args(listFile, outFile, method string, opt Options) []string {
	args := []string{"-i", listFile, "-oJ", outFile, "-q", "-m", method}
	if opt.Wordlist != "" {
		args = append(args, "-w", opt.Wordlist)
	}
	if opt.Rate > 0 {
		args = append(args, "--rate-limit", fmt.Sprint(opt.Rate))
	}
	if opt.Threads > 0 {
		args = append(args, "-t", fmt.Sprint(opt.Threads))
	}
	if opt.Timeout > 0 {
		args = append(args, "-T", fmt.Sprint(opt.Timeout))
	}
	if opt.Delay > 0 {
		args = append(args, "-d", fmt.Sprint(opt.Delay))
	}
	return append(args, opt.Extra...)
}

// Parse reads arjun JSON exports: one object (what -oJ writes) or several in a row (what Raijin saves as
// raw, one per method). Results come out in the order of the exports, URLs sorted within each one.
func Parse(r io.Reader) ([]Result, error) {
	var results []Result
	dec := json.NewDecoder(r)
	for {
		var export map[string]entry
		err := dec.Decode(&export)
		if errors.Is(err, io.EOF) {
			return results, nil
		}
		if err != nil {
			return results, fmt.Errorf("not an arjun JSON export: %w", err)
		}
		urls := make([]string, 0, len(export))
		for u := range export {
			urls = append(urls, u)
		}
		sort.Strings(urls)
		for _, u := range urls {
			e := export[u]
			h := map[string]string{}
			for k, v := range e.Headers {
				h[k] = fmt.Sprint(v)
			}
			results = append(results, Result{URL: u, Method: e.Method, Params: e.Params, Headers: h})
		}
	}
}

// DefaultHeaders are the headers arjun 2.2 sends when --headers is not given.
var DefaultHeaders = map[string]string{
	"User-Agent":                "Mozilla/5.0 (X11; Linux x86_64; rv:83.0) Gecko/20100101 Firefox/83.0",
	"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
	"Accept-Language":           "en-US,en;q=0.5",
	"Accept-Encoding":           "gzip, deflate",
	"Connection":                "close",
	"Upgrade-Insecure-Requests": "1",
}

// CustomHeaders are the headers of a result that are not among arjun's defaults (a cookie, a token, a
// changed User-Agent): what an agent needs to repeat its requests. They are nil when there are none. The
// Content-Type arjun adds itself for the JSON and XML methods is left out.
func CustomHeaders(method string, h map[string]string) map[string]string {
	var out map[string]string
	for k, v := range h {
		if DefaultHeaders[k] == v {
			continue
		}
		if strings.EqualFold(k, "Content-Type") && ((method == "JSON" && v == "application/json") || (method == "XML" && v == "application/xml")) {
			continue
		}
		if out == nil {
			out = map[string]string{}
		}
		out[k] = v
	}
	return out
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}
