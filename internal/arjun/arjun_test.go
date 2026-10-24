package arjun

import (
	"strings"
	"testing"
)

func TestParseOneExportAndSeveralInARow(t *testing.T) {
	in := `{
    "http://h/b": {"headers": {"Accept": "*/*"}, "method": "GET", "params": ["q"]},
    "http://h/a": {"headers": {}, "method": "GET", "params": ["url", "page"]}
}
{"http://h/a": {"headers": {}, "method": "POST", "params": ["user"]}}
`
	rs, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range rs {
		got = append(got, r.Method+" "+r.URL+" "+strings.Join(r.Params, ","))
	}
	if strings.Join(got, "|") != "GET http://h/a url,page|GET http://h/b q|POST http://h/a user" {
		t.Errorf("got %v", got)
	}
	if rs[1].Headers["Accept"] != "*/*" {
		t.Errorf("headers = %v", rs[1].Headers)
	}
}

func TestParseRejectsOtherJSON(t *testing.T) {
	if _, err := Parse(strings.NewReader(`[1,2]`)); err == nil {
		t.Error("a JSON array is not an arjun export")
	}
	if rs, err := Parse(strings.NewReader("")); err != nil || len(rs) != 0 {
		t.Errorf("an empty file is no results: %v %v", rs, err)
	}
}

func TestCustomHeaders(t *testing.T) {
	h := map[string]string{"Content-type": "application/json", "Content-Type": "application/json", "Cookie": "s=1"}
	for k, v := range DefaultHeaders {
		h[k] = v
	}
	if got := CustomHeaders("JSON", h); len(got) != 1 || got["Cookie"] != "s=1" {
		t.Errorf("JSON: %v", got)
	}
	if got := CustomHeaders("GET", h); len(got) != 3 {
		t.Errorf("a JSON Content-Type on GET is custom: %v", got)
	}
	if got := CustomHeaders("GET", DefaultHeaders); got != nil {
		t.Errorf("defaults: %v", got)
	}
}

func TestArgs(t *testing.T) {
	got := strings.Join(Args("t.txt", "o.json", "POST", Options{Wordlist: "small", Rate: 20, Threads: 2, Timeout: 5, Delay: 0.5, Extra: []string{"--stable"}}), " ")
	want := "-i t.txt -oJ o.json -q -m POST -w small --rate-limit 20 -t 2 -T 5 -d 0.5 --stable"
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}
