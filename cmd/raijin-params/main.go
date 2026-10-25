// Command raijin-params runs arjun and returns the hidden parameters it found, grouped and ranked, for AI
// agents.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"

	raijinparams "github.com/protonnegativo/raijin-params"
	"github.com/protonnegativo/raijin-params/internal/arjun"
	"github.com/protonnegativo/raijin-params/internal/banner"
	"github.com/protonnegativo/raijin-params/internal/reduce"
	"github.com/protonnegativo/raijin-params/internal/schema"
	"github.com/protonnegativo/raijin-params/internal/scope"
	"github.com/protonnegativo/raijin-params/internal/state"
)

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("raijin-params", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var targets, inputs multi
	fs.Var(&targets, "u", "target URL (repeatable; default: every host the scope names)")
	list := fs.String("l", "", "file with one target URL per line")
	scopeFile := fs.String("scope", "", "scope file (required): domains, *.wildcards, IPs, CIDRs, !exclusions")
	methods := fs.String("method", "GET", "comma-separated request methods, one arjun run each: GET, POST, JSON, XML (arjun -m)")
	wordlist := fs.String("wordlist", "", "parameter wordlist: a file, or small, medium or large (arjun -w; arjun's default is large)")
	rate := fs.Int("rate", 0, "requests per second (arjun --rate-limit)")
	threads := fs.Int("threads", 0, "concurrent requests (arjun -t)")
	timeout := fs.Int("timeout", 0, "request timeout in seconds (arjun -T)")
	delay := fs.Float64("delay", 0, "delay between requests in seconds (arjun -d)")
	maxItems := fs.Int("max-items", 0, "maximum findings in the output (0 keeps all)")
	maxBytes := fs.Int("max-bytes", reduce.Defaults().MaxBytes, "maximum size of the JSON output; cuts are counted in omitted")
	rawPath := fs.String("raw", "", "file for arjun's JSON exports, one per method (default: a new file in the temp dir)")
	statePath := fs.String("state", "", "state file; marks findings that are new since the last run")
	format := fs.String("format", "json", "output format: json or table")
	pretty := fs.Bool("pretty", false, "indent the JSON (compact by default, which costs fewer tokens)")
	fs.Var(&inputs, "input", "read an existing arjun JSON export (-oJ) instead of running arjun (repeatable)")
	bin := fs.String("arjun", "arjun", "path to the arjun binary")
	showVersion := fs.Bool("version", false, "print the version")
	showBanner := fs.Bool("banner", false, "print the Raijin banner to stderr (off by default to keep output small)")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: raijin-params --scope scope.txt [-u url | -l urls.txt | --input arjun.json] [flags] [-- extra arjun args]\n\nWith no targets it tests every host the scope names.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *showBanner {
		banner.Write(stderr, "raijin-params", version, useColor(stderr))
	}
	if *showVersion {
		fmt.Fprintln(stdout, versionLine())
		return 0
	}
	if *scopeFile == "" {
		fmt.Fprintln(stderr, "raijin-params: --scope is required")
		return 1
	}
	sc, err := scope.Load(*scopeFile)
	if err != nil {
		fmt.Fprintln(stderr, "raijin-params: scope:", err)
		return 1
	}
	var ms []string
	for _, m := range strings.Split(*methods, ",") {
		m = strings.ToUpper(strings.TrimSpace(m))
		switch m {
		case "":
			continue
		case "GET", "POST", "JSON", "XML":
			ms = append(ms, m)
		default:
			fmt.Fprintf(stderr, "raijin-params: unknown method %q (GET, POST, JSON or XML)\n", m)
			return 1
		}
	}

	res := schema.Result{
		Tool:     "raijin-params",
		Version:  version,
		Findings: []schema.Finding{},
		Groups:   []schema.Group{},
		Omitted:  map[string]int{},
		Errors:   []schema.Error{},
		Next:     []string{},
		Budget:   schema.Budget{MaxItems: *maxItems, MaxBytes: *maxBytes},
	}

	var results []arjun.Result
	var inScope []string
	if len(inputs) > 0 {
		for _, in := range inputs {
			f, err := os.Open(in)
			if err != nil {
				fmt.Fprintln(stderr, "raijin-params:", err)
				return 1
			}
			rs, err := arjun.Parse(f)
			f.Close()
			if err != nil {
				fmt.Fprintf(stderr, "raijin-params: %s: %v\n", in, err)
				return 1
			}
			results = append(results, rs...)
		}
		res.Target = strings.Join(inputs, ", ")
	} else {
		if *list != "" {
			lines, err := readLines(*list)
			if err != nil {
				fmt.Fprintln(stderr, "raijin-params:", err)
				return 1
			}
			targets = append(targets, lines...)
		}
		if len(targets) == 0 {
			// no targets given: test what the scope names. arjun skips a URL that does not start with
			// http, and from https:// it falls back to http, so a bare host becomes https://<host>/.
			hosts, wildcards, ranges := sc.Targets()
			for _, h := range hosts {
				if strings.Contains(h, ":") {
					h = "[" + h + "]"
				}
				inScope = append(inScope, "https://"+h+"/")
			}
			for _, w := range wildcards {
				res.Next = append(res.Next, "raijin-subs --scope "+*scopeFile+" -d "+strings.TrimPrefix(w, "*.")+", then raijin-params -l <live hosts> to cover "+w)
			}
			for _, r := range ranges {
				res.Next = append(res.Next, "raijin-ports --scope "+*scopeFile+" -host "+r+", then raijin-params -l <open ports> to cover "+r)
			}
			if len(inScope) > 0 {
				res.Next = append(res.Next, "raijin-crawl --scope "+*scopeFile+" to find more endpoints with parameters, then raijin-params -l <urls>")
			}
		} else {
			inScope = filter(targets, sc, res.Omitted)
		}
		if len(inScope) == 0 {
			if len(res.Next) > 0 {
				res.Summary = "the scope names no single host to scan"
				res.Target = *scopeFile
				write(stdout, &res, *format, *pretty)
				return 1
			}
			fmt.Fprintln(stderr, "raijin-params: no targets in scope")
			return 1
		}
		res.Target = targetSummary(inScope, res.Omitted["out_of_scope"])

		tempRaw := *rawPath == ""
		if tempRaw {
			f, err := os.CreateTemp("", "raijin-params-*.json")
			if err != nil {
				fmt.Fprintln(stderr, "raijin-params:", err)
				return 1
			}
			f.Close()
			*rawPath = f.Name()
		}
		res.Raw = *rawPath

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		res.Errors = append(res.Errors, versionCheck(ctx, *bin)...)
		var stderrTail string
		results, stderrTail, err = arjun.Run(ctx, inScope, arjun.Options{
			Binary: *bin, Methods: ms, Wordlist: *wordlist, Rate: *rate, Threads: *threads,
			Timeout: *timeout, Delay: *delay, Extra: fs.Args(), RawPath: *rawPath,
		})
		switch {
		case errors.Is(err, arjun.ErrNotFound):
			res.Errors = append(res.Errors, schema.Error{Kind: "missing_engine", Hint: "install arjun (pipx install arjun, or pip install arjun) or pass --arjun <path>, or run raijin-mcp update"})
			res.Summary = "arjun not found, nothing tested"
			res.Raw = ""
			if tempRaw {
				os.Remove(*rawPath)
			}
			write(stdout, &res, *format, *pretty)
			return 2
		case err != nil:
			hint := err.Error()
			if stderrTail != "" {
				hint += ": " + stderrTail
			}
			res.Errors = append(res.Errors, schema.Error{Kind: "engine_error", Hint: hint})
		}
	}

	if n := arjun.Malformed(results); n > 0 {
		// those results carry no parameters, so nothing else counts them
		res.Omitted["unparsed"] += n
		src := res.Raw
		if src == "" {
			src = strings.Join(inputs, ", ")
		}
		res.Errors = append(res.Errors, schema.Error{Kind: "engine_format", Hint: fmt.Sprintf("%d of %d arjun results had no params or method; the engine's output format may have changed. Read %s for the full output", n, len(results), src)})
	}

	opt := reduce.Defaults()
	opt.MaxItems = *maxItems
	opt.MaxBytes = *maxBytes
	opt.InScope = sc.Allowed
	out := reduce.Reduce(results, opt)
	res.Findings, res.Groups, res.Origin = out.Findings, out.Groups, out.Origin
	for k, v := range out.Omitted {
		res.Omitted[k] += v
	}

	newCount := -1
	if *statePath != "" {
		st, err := state.Load(*statePath)
		if err != nil {
			res.Errors = append(res.Errors, schema.Error{Kind: "state_error", Hint: err.Error()})
		} else {
			newCount = st.Mark(res.Findings, out.Locations)
			if err := st.Save(*statePath); err != nil {
				res.Errors = append(res.Errors, schema.Error{Kind: "state_error", Hint: err.Error()})
			}
		}
	}

	none := -1
	if inScope != nil {
		none = withoutParams(inScope, results)
	}
	res.Summary = summary(res, out.Stats, none, newCount)
	if res.Omitted["findings"] > 0 {
		res.Budget.Truncated = true
	}
	reduce.Fit(&res, *maxBytes)
	if res.Budget.Truncated {
		hint := "raise --max-bytes"
		if src := res.Raw + strings.Join(inputs, " "); src != "" {
			hint += " or read " + src + " for what was cut"
		}
		res.Next = append(res.Next, hint)
		reduce.Fit(&res, *maxBytes) // the hint takes room too
	}
	write(stdout, &res, *format, *pretty)
	return 0
}

// versionCheck warns when the installed arjun is not the version in engines.json (another major version,
// or older). It never fails the run: a version it cannot read is not reported.
func versionCheck(ctx context.Context, bin string) []schema.Error {
	engines, err := raijinparams.Engines()
	e, ok := engines["arjun"]
	if err != nil || !ok {
		return nil
	}
	installed := arjun.InstalledVersion(ctx, bin)
	if !arjun.Untested(installed, e.Version) {
		return nil
	}
	return []schema.Error{{Kind: "engine_version", Hint: fmt.Sprintf("arjun %s is not the tested %s; results may be incomplete. Install the tested version: %s, or run raijin-mcp update", installed, e.Version, e.Install(e.Version))}}
}

// useColor is true when w is a terminal and NO_COLOR is not set.
func useColor(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// filter drops repeated and out-of-scope targets. arjun skips a target without a scheme, so http:// is
// added to one.
func filter(targets []string, sc *scope.Scope, omitted map[string]int) []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t != "" && !strings.Contains(t, "://") {
			t = "http://" + t
		}
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		if !sc.Allowed(t) {
			omitted["out_of_scope"]++
			continue
		}
		out = append(out, t)
	}
	return out
}

// withoutParams counts the targets arjun reported nothing for, with any method.
func withoutParams(targets []string, results []arjun.Result) int {
	found := map[string]bool{}
	for _, r := range results {
		if len(r.Params) > 0 {
			found[r.URL] = true
		}
	}
	n := 0
	for _, t := range targets {
		if !found[t] {
			n++
		}
	}
	return n
}

func targetSummary(targets []string, skipped int) string {
	s := fmt.Sprintf("%d target(s)", len(targets))
	if len(targets) == 1 {
		s = targets[0]
	}
	if skipped > 0 {
		s += fmt.Sprintf(" (%d out of scope skipped)", skipped)
	}
	return s
}

// summary is written before the budget, so it stays true when Fit cuts.
func summary(res schema.Result, st reduce.Stats, none, newCount int) string {
	bySev := map[string]int{}
	for _, f := range res.Findings {
		bySev[f.Severity]++
	}
	var parts []string
	for _, sev := range []string{"critical", "high", "medium", "low", "info", "unknown"} {
		if n := bySev[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, sev))
		}
	}
	s := fmt.Sprintf("%d URLs, %d parameters (%d names): %d findings", st.URLs, st.Params, st.Names, len(res.Findings))
	if len(parts) > 0 {
		s += " (" + strings.Join(parts, ", ") + ")"
	}
	s += fmt.Sprintf(", %d groups", len(res.Groups))
	if none > 0 {
		s += fmt.Sprintf(", %d targets without parameters", none)
	}
	if newCount >= 0 {
		s += fmt.Sprintf(", %d new", newCount)
	}
	return s
}

func write(w io.Writer, res *schema.Result, format string, pretty bool) {
	if format == "table" {
		fmt.Fprintln(w, res.Summary)
		if res.Origin != "" {
			fmt.Fprintln(w, "origin  ", res.Origin)
		}
		for _, f := range res.Findings {
			mark := ""
			if f.New {
				mark = " [new]"
			}
			fmt.Fprintf(w, "%-8s %s %s (%d)%s\n", strings.ToUpper(f.Severity), strings.Join(f.Tags, ","), describe(f.Request), f.URLs, mark)
			for _, l := range f.Locations {
				fmt.Fprintf(w, "         %s\n", l)
			}
		}
		for _, g := range res.Groups {
			fmt.Fprintf(w, "group    %s (%d)\n", describe(g.Request), g.URLs)
		}
		for _, e := range res.Errors {
			fmt.Fprintf(w, "error    %s: %s\n", e.Kind, e.Hint)
		}
		return
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if pretty {
		enc.SetIndent("", "  ")
	}
	_ = enc.Encode(res)
}

// describe is a one-line view of an entry for the table: method, parameters, custom headers.
func describe(r schema.Request) string {
	s := strings.Join(r.Params, ",")
	if r.Method != "" {
		s = r.Method + " " + s
	}
	if len(r.Headers) > 0 {
		s += fmt.Sprintf(" (%d custom headers)", len(r.Headers))
	}
	return s
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out, sc.Err()
}
