package reduce

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/protonnegativo/raijin-params/internal/arjun"
	"github.com/protonnegativo/raijin-params/internal/schema"
	"github.com/protonnegativo/raijin-params/internal/scope"
)

func load(t *testing.T) []arjun.Result {
	t.Helper()
	f, err := os.Open("../../testdata/sample.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rs, err := arjun.Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

// get is a GET result with arjun's default headers.
func get(url string, params ...string) arjun.Result {
	return arjun.Result{URL: url, Method: "GET", Params: params, Headers: arjun.DefaultHeaders}
}

// triples lists every URL, method and parameter in the output, expanding ranges, as "METHOD url param".
func triples(out Output) map[string]bool {
	m := map[string]bool{}
	add := func(r schema.Request, locs []string) {
		method := r.Method
		if method == "" {
			method = "GET"
		}
		for _, l := range locs {
			for _, u := range expand(l) {
				for _, p := range r.Params {
					m[method+" "+out.Origin+u+" "+p] = true
				}
			}
		}
	}
	for _, f := range out.Findings {
		add(f.Request, f.Locations)
	}
	for _, g := range out.Groups {
		add(g.Request, g.Locations)
	}
	return m
}

// expand undoes Compress for one location with at most one range.
func expand(loc string) []string {
	i, j := strings.Index(loc, "["), strings.Index(loc, "]")
	if i < 0 || j < i {
		return []string{loc}
	}
	var out []string
	for _, part := range strings.Split(loc[i+1:j], ",") {
		var a, b int
		if n, _ := fmt.Sscanf(part, "%d-%d", &a, &b); n < 2 {
			fmt.Sscan(part, &a)
			b = a
		}
		for k := a; k <= b; k++ {
			out = append(out, fmt.Sprint(loc[:i], k, loc[j+1:]))
		}
	}
	return out
}

func TestReduce(t *testing.T) {
	results := load(t)
	if len(results) != 14 {
		t.Fatalf("parsed %d results, want 14 (from 4 exports in a row)", len(results))
	}
	sc, _ := scope.Parse([]string{"*.example.com"})
	opt := Defaults()
	opt.InScope = sc.Allowed
	out := Reduce(results, opt)

	if out.Origin != "https://app.example.com" {
		t.Errorf("origin = %q", out.Origin)
	}
	if out.Omitted["duplicates"] != 2 || out.Omitted["out_of_scope"] != 1 {
		t.Errorf("omitted = %v", out.Omitted)
	}
	if out.Stats != (Stats{URLs: 10, Results: 12, Params: 23, Names: 13}) {
		t.Errorf("stats = %+v", out.Stats)
	}
	var got []string
	for _, f := range out.Findings {
		got = append(got, f.Severity+" "+f.Tags[0]+" "+strings.TrimSpace(f.Method+" "+strings.Join(f.Params, ","))+" "+strings.Join(f.Locations, " "))
	}
	want := []string{
		"high rce JSON cmd /api/user",
		"high ssrf callback,url /fetch /proxy",
		"high file file /download",
		"medium redirect returnUrl /login",
		"medium admin JSON is_admin /api/user",
		"medium id orderId /api/orders",
		"medium id POST username /login",
		"low injection sort /api/orders",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("findings:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if g := out.Groups[0]; strings.Join(g.Params, ",") != "currency,page" || strings.Join(g.Locations, " ") != "/item/[1-3,7]" || g.URLs != 4 {
		t.Errorf("biggest group = %+v", g)
	}
}

// Lossless rule: every URL, method and parameter arjun reported is in exactly one entry.
func TestEveryTripleIsKept(t *testing.T) {
	sc, _ := scope.Parse([]string{"*.example.com"})
	opt := Defaults()
	opt.InScope = sc.Allowed
	results := load(t)
	out := Reduce(results, opt)
	got := triples(out)
	n := 0
	for _, r := range results {
		if !sc.Allowed(r.URL) {
			continue
		}
		for _, p := range r.Params {
			key := r.Method + " " + r.URL + " " + p
			if !got[key] {
				t.Errorf("missing %s", key)
			}
			n++
		}
	}
	if len(got) != n-out.Omitted["duplicates"] {
		t.Errorf("%d triples in the output, %d in the input with %d duplicates", len(got), n, out.Omitted["duplicates"])
	}
}

// Lossless rule: the same parameter set on many URLs is one entry that still lists every URL.
func TestSameSetCollapsesAndListsEveryURL(t *testing.T) {
	var rs []arjun.Result
	for n := 1; n <= 60; n++ {
		rs = append(rs, get(fmt.Sprintf("http://h/item/%d", n), "page", "size"))
	}
	rs = append(rs, get("http://h/item/007", "size", "page"))
	out := Reduce(rs, Defaults())
	if len(out.Groups) != 1 || len(out.Findings) != 0 {
		t.Fatalf("groups = %+v", out.Groups)
	}
	g := out.Groups[0]
	if strings.Join(g.Locations, " ") != "/item/007 /item/[1-60]" || g.URLs != 61 {
		t.Errorf("locations = %v (%d URLs)", g.Locations, g.URLs)
	}
}

// Lossless rule: a different parameter set, method or set of custom headers is another entry.
func TestSetsMethodsAndHeadersSplitEntries(t *testing.T) {
	cookie := map[string]string{}
	for k, v := range arjun.DefaultHeaders {
		cookie[k] = v
	}
	cookie["Cookie"] = "s=1"
	rs := []arjun.Result{
		get("http://h/a", "page"),
		get("http://h/b", "page", "size"),
		{URL: "http://h/c", Method: "POST", Params: []string{"page"}, Headers: arjun.DefaultHeaders},
		{URL: "http://h/d", Method: "GET", Params: []string{"page"}, Headers: cookie},
	}
	out := Reduce(rs, Defaults())
	if len(out.Groups) != 4 {
		t.Fatalf("want 4 groups, got %+v", out.Groups)
	}
	var withCookie int
	for _, g := range out.Groups {
		if len(g.Headers) > 0 {
			withCookie++
			if len(g.Headers) != 1 || g.Headers["Cookie"] != "s=1" {
				t.Errorf("only the custom header should be written: %v", g.Headers)
			}
		}
	}
	if withCookie != 1 {
		t.Errorf("one group should carry the cookie, got %d", withCookie)
	}
}

// Lossless rule: one URL's parameters of different classes go to different entries, none dropped.
func TestURLSplitsByClass(t *testing.T) {
	out := Reduce([]arjun.Result{get("http://h/admin", "debug", "admin", "tab", "url")}, Defaults())
	var got []string
	for _, f := range out.Findings {
		got = append(got, f.Tags[0]+":"+strings.Join(f.Params, ","))
	}
	if strings.Join(got, " ") != "ssrf:url admin:admin debug:debug" {
		t.Errorf("findings = %v", got)
	}
	if len(out.Groups) != 1 || out.Groups[0].Params[0] != "tab" {
		t.Errorf("groups = %+v", out.Groups)
	}
}

// Lossless rule: only exact repeats of a URL, method and parameter collapse, and they are counted.
func TestOnlyExactDuplicatesCollapse(t *testing.T) {
	rs := []arjun.Result{
		get("http://h/p", "id", "id"),
		get("http://h/p", "id"),
		{URL: "http://h/p", Method: "POST", Params: []string{"id"}},
		get("http://h/p/", "id"),
	}
	out := Reduce(rs, Defaults())
	if out.Omitted["duplicates"] != 2 {
		t.Errorf("duplicates = %d, want 2", out.Omitted["duplicates"])
	}
	if n := len(triples(out)); n != 3 {
		t.Errorf("%d triples kept, want 3 (GET /p, POST /p, GET /p/)", n)
	}
}

func TestOutOfScopeResultsAreCounted(t *testing.T) {
	sc, _ := scope.Parse([]string{"app.example.com"})
	opt := Defaults()
	opt.InScope = sc.Allowed
	out := Reduce([]arjun.Result{get("https://app.example.com/a", "q"), get("https://evil.example.net/a", "q")}, opt)
	if out.Omitted["out_of_scope"] != 1 || len(triples(out)) != 1 {
		t.Errorf("omitted = %v, triples = %v", out.Omitted, triples(out))
	}
}

func TestSeveralOriginsKeepFullURLs(t *testing.T) {
	out := Reduce([]arjun.Result{get("http://a:1/x", "q"), get("http://b:2/x", "q")}, Defaults())
	if out.Origin != "" || strings.Join(out.Findings[0].Locations, " ") != "http://a:1/x http://b:2/x" {
		t.Errorf("origin %q, locations %v", out.Origin, out.Findings[0].Locations)
	}
}

func TestBracketsInURLsAreEscaped(t *testing.T) {
	out := Reduce([]arjun.Result{get("http://h/a?x[0]=1", "page")}, Defaults())
	if l := out.Groups[0].Locations[0]; l != "/a?x%5B0%5D=1" {
		t.Errorf("location = %q", l)
	}
}

func TestClassify(t *testing.T) {
	cases := map[string]string{
		"cmd": "rce", "exec": "rce", "pingHost": "rce",
		"redirect": "redirect", "redirect_url": "redirect", "returnUrl": "redirect", "next": "redirect", "RelayState": "redirect",
		"url": "ssrf", "callback": "ssrf", "image_url": "ssrf", "webhookURL": "ssrf", "host": "ssrf",
		"file": "file", "filePath": "file", "template": "file", "include": "file",
		"admin": "admin", "is_admin": "admin", "role": "admin", "admin_id": "admin",
		"debug": "debug", "test": "debug", "verbose": "debug",
		"id": "id", "user_id": "id", "userId": "id", "userid": "id", "orderIDs": "id", "uuid": "id",
		"q": "injection", "search": "injection", "sort": "injection", "orderBy": "injection",
		"page": "", "lang": "", "tab": "", "valid": "", "paid": "", "currency": "", "password": "", "": "",
	}
	for name, want := range cases {
		if got := Classify(name); got != want {
			t.Errorf("Classify(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestWords(t *testing.T) {
	for in, want := range map[string]string{"returnURL[0]": "return url 0", "redirect-uri": "redirect uri", "XMLHttp": "xml http", "userID": "user id"} {
		if got := strings.Join(Words(in), " "); got != want {
			t.Errorf("Words(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRankingIsDeterministic(t *testing.T) {
	results := load(t)
	a := Reduce(results, Defaults())
	for i := 0; i < 20; i++ {
		b := Reduce(results, Defaults())
		for j := range a.Findings {
			if a.Findings[j].ID != b.Findings[j].ID {
				t.Fatalf("run %d: finding %d is %s, was %s", i, j, b.Findings[j].ID, a.Findings[j].ID)
			}
		}
		for j := range a.Groups {
			if a.Groups[j].ID != b.Groups[j].ID {
				t.Fatalf("run %d: group %d is %s, was %s", i, j, b.Groups[j].ID, a.Groups[j].ID)
			}
		}
	}
}

func TestIDsAreStable(t *testing.T) {
	a := Reduce([]arjun.Result{get("http://h/a", "url")}, Defaults())
	b := Reduce([]arjun.Result{get("http://h/a", "url"), get("http://h/b", "page")}, Defaults())
	if a.Findings[0].ID != b.Findings[0].ID || !strings.HasPrefix(a.Findings[0].ID, "ssrf-") {
		t.Errorf("ids %s and %s", a.Findings[0].ID, b.Findings[0].ID)
	}
}

func TestMaxItemsIsCounted(t *testing.T) {
	opt := Defaults()
	all := Reduce(load(t), Defaults())
	opt.MaxItems = 2
	out := Reduce(load(t), opt)
	if len(out.Findings) != 2 || out.Omitted["findings"] != len(all.Findings)-2 {
		t.Errorf("findings %d, omitted %v", len(out.Findings), out.Omitted)
	}
}

func TestFitCutsGroupsFirstAndCounts(t *testing.T) {
	out := Reduce(load(t), Defaults())
	res := schema.Result{Tool: "raijin-params", Findings: out.Findings, Groups: out.Groups, Omitted: map[string]int{}}
	full := size(&res)
	Fit(&res, full-60)
	if size(&res) > full-60 || !res.Budget.Truncated {
		t.Fatalf("size %d, truncated %v", size(&res), res.Budget.Truncated)
	}
	if res.Omitted["locations"]+res.Omitted["groups"] == 0 || res.Omitted["findings"] != 0 || len(res.Findings) != len(out.Findings) {
		t.Errorf("findings should survive while groups can be cut: omitted %v", res.Omitted)
	}
	res = schema.Result{Findings: out.Findings, Groups: out.Groups, Omitted: map[string]int{}}
	Fit(&res, 420)
	if size(&res) > 420 || len(res.Findings) != 1 || res.Findings[0].Tags[0] != "rce" || res.Omitted["findings"] != len(out.Findings)-1 {
		t.Errorf("tight budget keeps the top finding: %d bytes, %+v, omitted %v", size(&res), res.Findings, res.Omitted)
	}
}

func TestCompress(t *testing.T) {
	got := Compress([]string{"/p?id=1", "/p?id=2", "/p?id=7", "/a/3/b/1", "/a/3/b/2", "/a/4/b/1"})
	want := "/a/3/b/2 /a/[3-4]/b/1 /p?id=[1-2,7]"
	if strings.Join(got, " ") != want {
		t.Errorf("got %v, want %s", got, want)
	}
}
