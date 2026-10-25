package arjun

import (
	"strings"
	"testing"
)

func TestParseVersion(t *testing.T) {
	for in, want := range map[string]string{
		"2.2.7\n": "2.2.7",
		"Name: arjun\nVersion: 2.2.7\nSummary: HTTP parameter discovery suite\n": "2.2.7",
		"v3.0.1": "3.0.1",
		"Traceback (most recent call last):\nPackageNotFoundError: arjun": "",
		"": "",
	} {
		if got := ParseVersion(in); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}

func TestUntested(t *testing.T) {
	for _, c := range []struct {
		installed string
		want      bool
	}{
		{"2.2.7", false}, {"2.2.8", false}, {"2.3.0", false},
		{"2.2.6", true}, {"2.1.9", true}, {"3.0.0", true}, {"1.9.9", true}, {"", false}, {"dev", false},
	} {
		if got := Untested(c.installed, "2.2.7"); got != c.want {
			t.Errorf("%s: got %v", c.installed, got)
		}
	}
}

func TestMalformedRenamedField(t *testing.T) {
	// "params" renamed to "parameters": the entries parse but carry nothing.
	in := `{"http://h/a": {"headers": {}, "method": "GET", "parameters": ["q"]},
"http://h/b": {"headers": {}, "method": "GET", "params": ["id"]}}`
	rs, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if n := Malformed(rs); n != 1 || len(rs) != 2 {
		t.Errorf("malformed = %d of %d", n, len(rs))
	}
}
