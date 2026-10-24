// Package reduce turns arjun results into a small, ranked Raijin result.
//
// It is lossless for what an agent acts on: every URL, method and parameter arjun reported is kept, with
// the headers arjun sent when they are not its defaults. Each parameter gets one attack class from its
// name, or none. URLs where arjun found exactly the same parameters of a class, with the same method and
// headers, share one entry that lists every URL. Only exact duplicates are dropped. A byte budget can
// cut, but every cut is counted in omitted.
package reduce

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/protonnegativo/raijin-params/internal/arjun"
	"github.com/protonnegativo/raijin-params/internal/schema"
)

// Options control what the reducer keeps.
type Options struct {
	MaxItems int // 0 keeps every finding
	MaxBytes int
	InScope  func(target string) bool
}

// Defaults keep every finding and cap the JSON at a size that fits comfortably in an agent's context.
func Defaults() Options {
	return Options{MaxBytes: 16000}
}

// Stats are the counts of the run, before any budget, for the summary.
type Stats struct {
	URLs    int // distinct URLs with at least one parameter
	Results int // distinct URL and method pairs
	Params  int // distinct URL, method and parameter triples
	Names   int // distinct parameter names
}

// Output is what Reduce returns.
type Output struct {
	Findings []schema.Finding
	Groups   []schema.Group
	Omitted  map[string]int
	// Origin is the scheme and host every URL shares, or "" when there are several.
	Origin string
	// Locations are every URL per finding fingerprint, before any budget, for --state.
	Locations map[string][]string
	Stats     Stats
}

// Class is an attack class a parameter name suggests, with its severity. Classes are tried in order and
// a parameter takes the first that matches, so each parameter is in exactly one entry.
type Class struct {
	Name     string
	Severity string
	words    map[string]bool
}

// Classes are the attack classes, most specific first: redirect_url is a redirect, not an ssrf, and
// admin_id is admin, not id.
var Classes = []Class{
	{"rce", "high", set("cmd", "cmdline", "command", "commands", "exec", "execute", "shell", "eval", "ping",
		"system", "sh", "bash", "powershell", "cli", "daemon")},
	{"redirect", "medium", set("redirect", "redirects", "redir", "return", "returnto", "returnurl", "returnuri",
		"returnpath", "next", "nexturl", "goto", "continue", "forward", "fwd", "dest", "destination", "out", "rurl",
		"back", "backurl", "success", "successurl", "failure", "failurl", "relaystate")},
	{"ssrf", "high", set("url", "uri", "urls", "link", "href", "src", "host", "hostname", "domain", "proxy",
		"callback", "webhook", "hook", "feed", "rss", "fetch", "endpoint", "server", "site", "remote", "ip",
		"port", "target", "wsdl")},
	{"file", "high", set("file", "files", "filename", "filepath", "fname", "path", "pathname", "dir",
		"directory", "folder", "doc", "document", "include", "inc", "require", "template", "tpl", "layout",
		"load", "read", "download", "attachment", "upload", "log", "logfile")},
	{"admin", "medium", set("admin", "administrator", "isadmin", "role", "roles", "privilege", "privileges",
		"priv", "superuser", "su", "sudo", "root", "staff", "permission", "permissions", "perm", "perms",
		"grant", "access", "acl")},
	{"debug", "medium", set("debug", "debugging", "test", "testing", "dev", "develop", "verbose", "trace",
		"internal", "preview", "beta", "hidden", "show", "config", "cfg", "conf", "env", "environment", "mode",
		"dump", "source", "xdebug", "console")},
	{"id", "medium", set("id", "ids", "uid", "uuid", "guid", "pid", "oid", "user", "userid", "username",
		"account", "acct", "customer", "member", "owner", "number")},
	{"injection", "low", set("q", "query", "search", "s", "keyword", "keywords", "kw", "term", "terms",
		"filter", "filters", "sort", "sortby", "orderby", "order", "column", "col", "columns", "field",
		"fields", "table", "where", "select", "groupby", "having", "sql")},
}

// idSuffix is a name that ends in id after an object word: userid, orderId, account_ids.
var idSuffix = regexp.MustCompile(`^(user|account|acct|customer|cust|client|order|item|product|prod|post|article|doc|document|invoice|member|profile|group|org|team|project|session|ticket|message|msg|comment|report|tx|transaction|payment|cart|card|address|store|shop|vendor|record|object|obj|entry|node|ref|owner|parent|file|image|img|page|cat|category|tenant|company|employee|student|patient|course|event)(id|ids|uuid|guid)$`)

var severityOf = map[string]string{}
var classRank = map[string]int{}

func init() {
	for i, c := range Classes {
		severityOf[c.Name] = c.Severity
		classRank[c.Name] = len(Classes) - i
	}
}

// Classify is the attack class of a parameter name, or "" when it has none. The name is split into
// words at non-alphanumeric characters and camelCase boundaries ("redirect_url", "redirectUrl" and
// "redirect-url" are redirect, url); a class matches when one word, or all the words joined, is in its
// list. A name that ends in id after an object word (userid, orderId) is id.
func Classify(name string) string {
	words := Words(name)
	if len(words) == 0 {
		return ""
	}
	joined := strings.Join(words, "")
	for _, c := range Classes {
		if c.words[joined] {
			return c.Name
		}
		for _, w := range words {
			if c.words[w] {
				return c.Name
			}
		}
		if c.Name == "id" && idSuffix.MatchString(joined) {
			return c.Name
		}
	}
	return ""
}

// Words splits a parameter name into lowercase words: "returnURL[0]" is return, url, 0.
func Words(name string) []string {
	var words []string
	var cur []rune
	rs := []rune(name)
	flush := func() {
		if len(cur) > 0 {
			words = append(words, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	for i, r := range rs {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			flush()
			continue
		}
		if i > 0 && unicode.IsUpper(r) && len(cur) > 0 {
			prev := rs[i-1]
			nextLower := i+1 < len(rs) && unicode.IsLower(rs[i+1])
			if unicode.IsLower(prev) || unicode.IsDigit(prev) || (unicode.IsUpper(prev) && nextLower) {
				flush()
			}
		}
		cur = append(cur, r)
	}
	flush()
	return words
}

type entry struct {
	key     string
	class   string
	method  string
	headers map[string]string
	params  []string
	urls    map[string]bool
}

// Reduce collapses arjun results into findings and groups: for each URL and method, its parameters are
// split by class, and each class's set of parameters goes to the entry for that exact set.
func Reduce(results []arjun.Result, opt Options) Output {
	out := Output{Omitted: map[string]int{}, Locations: map[string][]string{}}
	type cell struct {
		class, method, hkey string
		headers             map[string]string
		url                 string
	}
	cells := map[string]*cell{}
	cellParams := map[string]map[string]bool{}
	var cellOrder []string
	seen := map[string]bool{}
	urls, pairs, names := map[string]bool{}, map[string]bool{}, map[string]bool{}
	origins := map[string]bool{}

	for _, r := range results {
		if opt.InScope != nil && !opt.InScope(r.URL) {
			out.Omitted["out_of_scope"]++
			continue
		}
		m := strings.ToUpper(strings.TrimSpace(r.Method))
		if m == "" {
			m = "GET"
		}
		h := arjun.CustomHeaders(m, r.Headers)
		hkey := headerKey(h)
		for _, p := range r.Params {
			if p == "" {
				continue
			}
			t := r.URL + "\x00" + m + "\x00" + p
			if seen[t] {
				out.Omitted["duplicates"]++
				continue
			}
			seen[t] = true
			urls[r.URL], pairs[r.URL+"\x00"+m], names[p] = true, true, true
			origins[Origin(r.URL)] = true
			class := Classify(p)
			ck := strings.Join([]string{class, m, hkey, r.URL}, "\x00")
			if cells[ck] == nil {
				cells[ck] = &cell{class: class, method: m, hkey: hkey, headers: h, url: r.URL}
				cellParams[ck] = map[string]bool{}
				cellOrder = append(cellOrder, ck)
			}
			cellParams[ck][p] = true
		}
	}
	out.Stats = Stats{URLs: len(urls), Results: len(pairs), Params: len(seen), Names: len(names)}
	if len(origins) == 1 {
		for o := range origins {
			out.Origin = o
		}
	}

	entries := map[string]*entry{}
	var keys []string
	for _, ck := range cellOrder {
		c := cells[ck]
		params := sorted(cellParams[ck])
		key := strings.Join([]string{c.class, c.method, c.hkey, strings.Join(params, "\x01")}, "\x00")
		e, ok := entries[key]
		if !ok {
			e = &entry{key: key, class: c.class, method: c.method, headers: c.headers, params: params, urls: map[string]bool{}}
			entries[key] = e
			keys = append(keys, key)
		}
		e.urls[c.url] = true
	}

	for _, key := range keys {
		e := entries[key]
		var locs []string
		for u := range e.urls {
			locs = append(locs, escapeBrackets(strings.TrimPrefix(u, out.Origin)))
		}
		locs = Compress(locs)
		req := schema.Request{Params: e.params, Headers: e.headers}
		if e.method != "GET" {
			req.Method = e.method
		}
		if e.class == "" {
			out.Groups = append(out.Groups, schema.Group{ID: "params-" + fingerprint(key)[:8], Request: req, Locations: locs, URLs: len(e.urls)})
			continue
		}
		id := e.class + "-" + fingerprint(key)[:8]
		f := schema.Finding{ID: id, Severity: severityOf[e.class], Tags: []string{e.class}, Request: req, Locations: locs, URLs: len(e.urls), Fingerprint: fingerprint(id)}
		out.Locations[f.Fingerprint] = sorted(e.urls)
		out.Findings = append(out.Findings, f)
	}
	if out.Findings == nil {
		out.Findings = []schema.Finding{}
	}
	if out.Groups == nil {
		out.Groups = []schema.Group{}
	}

	sort.SliceStable(out.Findings, func(i, j int) bool {
		a, b := out.Findings[i], out.Findings[j]
		if schema.SeverityRank[a.Severity] != schema.SeverityRank[b.Severity] {
			return schema.SeverityRank[a.Severity] > schema.SeverityRank[b.Severity]
		}
		if schema.ConfidenceRank[a.Confidence] != schema.ConfidenceRank[b.Confidence] {
			return schema.ConfidenceRank[a.Confidence] > schema.ConfidenceRank[b.Confidence]
		}
		if classRank[a.Tags[0]] != classRank[b.Tags[0]] {
			return classRank[a.Tags[0]] > classRank[b.Tags[0]]
		}
		if a.URLs != b.URLs {
			return a.URLs > b.URLs
		}
		if pa, pb := strings.Join(a.Params, ","), strings.Join(b.Params, ","); pa != pb {
			return pa < pb
		}
		return a.ID < b.ID
	})
	sort.SliceStable(out.Groups, func(i, j int) bool {
		a, b := out.Groups[i], out.Groups[j]
		if a.URLs != b.URLs {
			return a.URLs > b.URLs
		}
		if pa, pb := strings.Join(a.Params, ","), strings.Join(b.Params, ","); pa != pb {
			return pa < pb
		}
		return a.ID < b.ID
	})

	if opt.MaxItems > 0 && len(out.Findings) > opt.MaxItems {
		out.Omitted["findings"] += len(out.Findings) - opt.MaxItems
		out.Findings = out.Findings[:opt.MaxItems]
	}
	return out
}

// headerKey is a stable string for a set of headers.
func headerKey(h map[string]string) string {
	if h == nil {
		return ""
	}
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k + ": " + h[k] + "\n")
	}
	return b.String()
}

// Origin is the scheme and host of a URL as arjun wrote it ("http://127.0.0.1:19151"), or "" when the
// URL has none.
func Origin(raw string) string {
	i := strings.Index(raw, "://")
	if i < 0 {
		return ""
	}
	rest := raw[i+3:]
	if j := strings.IndexAny(rest, "/?#"); j >= 0 {
		return raw[:i+3+j]
	}
	return raw
}

// escapeBrackets writes a URL's own [ and ] as %5B and %5D, so a bracket in a location is always a range.
func escapeBrackets(s string) string {
	return strings.NewReplacer("[", "%5B", "]", "%5D").Replace(s)
}

var digitRun = regexp.MustCompile(`[0-9]+`)

// Compress writes URLs that differ in one number as one location with the numbers as ranges:
// "/item/1" ... "/item/60" is "/item/[1-60]", and "/p?id=1", "/p?id=2", "/p?id=7" is "/p?id=[1-2,7]".
// It tries each position of a number in the URLs (the first number, the second...) and keeps the one that
// gives the fewest locations. A number with a leading zero is never part of a range. The result is sorted.
func Compress(urls []string) []string {
	uniq := map[string]bool{}
	for _, u := range urls {
		uniq[u] = true
	}
	best := sorted(uniq)
	most := 0
	for _, u := range best {
		most = max(most, len(digitRun.FindAllStringIndex(u, -1)))
	}
	for pos := 0; pos < most; pos++ {
		if out := compressAt(best, pos); len(out) < len(best) {
			best = out
		}
	}
	return best
}

func compressAt(urls []string, pos int) []string {
	type run struct {
		prefix, suffix string
		nums           []int64
	}
	runs := map[string]*run{}
	var order []string
	var out []string
	for _, u := range urls {
		idx := digitRun.FindAllStringIndex(u, -1)
		if pos >= len(idx) {
			out = append(out, u)
			continue
		}
		a, b := idx[pos][0], idx[pos][1]
		digits := u[a:b]
		var n int64
		if len(digits) > 18 || (len(digits) > 1 && digits[0] == '0') {
			out = append(out, u)
			continue
		}
		fmt.Sscan(digits, &n)
		k := u[:a] + "\x00" + u[b:]
		r, ok := runs[k]
		if !ok {
			r = &run{prefix: u[:a], suffix: u[b:]}
			runs[k] = r
			order = append(order, k)
		}
		r.nums = append(r.nums, n)
	}
	for _, k := range order {
		r := runs[k]
		if len(r.nums) == 1 {
			out = append(out, fmt.Sprint(r.prefix, r.nums[0], r.suffix))
			continue
		}
		out = append(out, r.prefix+"["+ranges(r.nums)+"]"+r.suffix)
	}
	sort.Strings(out)
	return out
}

// ranges writes sorted numbers as "1-5,7,9-12".
func ranges(nums []int64) string {
	sort.Slice(nums, func(i, j int) bool { return nums[i] < nums[j] })
	var parts []string
	for i := 0; i < len(nums); {
		j := i
		for j+1 < len(nums) && nums[j+1] == nums[j]+1 {
			j++
		}
		if j > i {
			parts = append(parts, fmt.Sprintf("%d-%d", nums[i], nums[j]))
		} else {
			parts = append(parts, fmt.Sprint(nums[i]))
		}
		i = j + 1
	}
	return strings.Join(parts, ",")
}

// Fit shrinks the result until its JSON is at most maxBytes. It cuts the least important data first:
// group locations, then groups, then the locations of the lowest-ranked findings (each keeps one, and
// its count), then the lowest-ranked findings. Every cut is counted in Omitted.
func Fit(res *schema.Result, maxBytes int) {
	if maxBytes <= 0 || size(res) <= maxBytes {
		return
	}
	res.Budget.Truncated = true
	if res.Omitted == nil {
		res.Omitted = map[string]int{}
	}
	total := size(res) // now includes the budget object
	for i := len(res.Groups) - 1; i >= 0 && total > maxBytes; i-- {
		g := &res.Groups[i]
		if len(g.Locations) == 0 {
			continue
		}
		before := size(g)
		res.Omitted["locations"] += len(g.Locations)
		g.Locations, g.Count = nil, g.URLs
		total += size(g) - before
	}
	for total > maxBytes && len(res.Groups) > 0 {
		last := len(res.Groups) - 1
		total -= size(res.Groups[last]) + 1
		res.Groups = res.Groups[:last]
		res.Omitted["groups"]++
	}
	for i := len(res.Findings) - 1; i >= 0 && total > maxBytes; i-- {
		f := &res.Findings[i]
		if len(f.Locations) <= 1 {
			continue
		}
		before := size(f)
		res.Omitted["locations"] += len(f.Locations) - 1
		f.Locations, f.Count = f.Locations[:1], f.URLs
		total += size(f) - before
	}
	for total > maxBytes && len(res.Findings) > 1 {
		last := len(res.Findings) - 1
		total -= size(res.Findings[last]) + 1
		res.Findings = res.Findings[:last]
		res.Omitted["findings"]++
	}
	// the estimate above ignores the omitted counters it adds; settle on the real size
	for size(res) > maxBytes && len(res.Findings) > 1 {
		res.Findings = res.Findings[:len(res.Findings)-1]
		res.Omitted["findings"]++
	}
}

func size(v any) int {
	b, _ := schema.Marshal(v)
	return len(b)
}

func set(items ...string) map[string]bool {
	m := map[string]bool{}
	for _, s := range items {
		m[s] = true
	}
	return m
}

func sorted(set map[string]bool) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func fingerprint(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:8])
}
