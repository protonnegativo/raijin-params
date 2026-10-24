package schema

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDerivableFieldsAreLeftOut(t *testing.T) {
	res := Result{
		Tool:     "raijin-params",
		Findings: []Finding{{ID: "ssrf-ab12cd34", Severity: "high", Tags: []string{"ssrf"}, Request: Request{Params: []string{"url"}}, Locations: []string{"/fetch"}, URLs: 1, Fingerprint: "fp"}},
		Groups:   []Group{{ID: "params-ef56ab78", Request: Request{Params: []string{"page"}}, Locations: []string{"/about"}, URLs: 1}},
		Omitted:  map[string]int{},
		Errors:   []Error{},
		Next:     []string{},
		Budget:   Budget{MaxItems: 20, MaxBytes: 8000},
	}
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"fingerprint", "count", "urls", "confidence", "method", "headers", "new", "origin", "omitted", "errors", "next", "raw", "budget"} {
		if strings.Contains(string(b), `"`+k+`"`) {
			t.Errorf("%s should be left out: %s", k, b)
		}
	}
	if strings.Contains(string(b), "null") {
		t.Errorf("no null values: %s", b)
	}
}

func TestRequestFieldsAreInline(t *testing.T) {
	f := Finding{ID: "id-x", Severity: "medium", Tags: []string{"id"}, Request: Request{Params: []string{"id"}, Method: "POST", Headers: map[string]string{"Cookie": "s=1"}}, Locations: []string{"/api/user?v=[1-3]&x=1"}, URLs: 3}
	b, _ := Marshal(f)
	want := `{"id":"id-x","severity":"medium","tags":["id"],"params":["id"],"method":"POST","headers":{"Cookie":"s=1"},"locations":["/api/user?v=[1-3]&x=1"]}`
	if string(b) != want {
		t.Errorf("got  %s\nwant %s", b, want)
	}
}

func TestCountAndBudgetAppearWhenSomethingIsCut(t *testing.T) {
	res := Result{
		Findings: []Finding{{ID: "ssrf-x", Tags: []string{"ssrf"}, Request: Request{Params: []string{"url"}}, Locations: []string{"/a?x=1"}, Count: 7, URLs: 7}},
		Groups:   []Group{{ID: "params-y", Request: Request{Params: []string{"page"}}, Count: 4, URLs: 4}},
		Budget:   Budget{MaxItems: 20, MaxBytes: 8000, Truncated: true},
	}
	b, _ := json.Marshal(res)
	s := string(b)
	if !strings.Contains(s, `"locations":["/a?x=1"],"count":7`) || !strings.Contains(s, `{"id":"params-y","params":["page"],"count":4}`) {
		t.Errorf("count must be written when locations were cut: %s", s)
	}
	if !strings.Contains(s, `"budget":{"max_items":20,"max_bytes":8000,"truncated":true}`) || strings.Count(s, "budget") != 1 {
		t.Errorf("budget must be written once when something was cut: %s", s)
	}
	if strings.Contains(s, `&`) {
		t.Errorf("& must not be escaped: %s", s)
	}
}
