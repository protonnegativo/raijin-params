package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func scopeFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "scope.txt")
	if err := os.WriteFile(p, []byte("*.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestNoBannerByDefault(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"--scope", scopeFile(t), "--input", "../../testdata/sample.json"}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if errb.Len() != 0 {
		t.Errorf("stderr should be empty without --banner, got %q", errb.String())
	}
	var v map[string]any
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("stdout is not JSON: %v", err)
	}
}

func TestBannerGoesToStderrOnly(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"--banner", "--scope", scopeFile(t), "--input", "../../testdata/sample.json"}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(errb.String(), "TGT-LOCK") || !strings.Contains(errb.String(), "raijin-params v"+version) {
		t.Errorf("banner missing or without the version: %q", errb.String())
	}
	if strings.Contains(out.String(), "TGT-LOCK") {
		t.Error("banner leaked into stdout")
	}
	var v map[string]any
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("stdout is not JSON with --banner: %v", err)
	}
}

func TestCompactByDefault(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--scope", scopeFile(t), "--input", "../../testdata/sample.json"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if n := strings.Count(out.String(), "\n"); n != 1 {
		t.Errorf("default JSON should be one line, got %d lines", n)
	}
	var pretty bytes.Buffer
	if code := run([]string{"--pretty", "--scope", scopeFile(t), "--input", "../../testdata/sample.json"}, &pretty, &errb); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(pretty.String(), "\n  \"tool\"") {
		t.Errorf("--pretty should indent: %q", pretty.String())
	}
	var a, b map[string]any
	if json.Unmarshal(out.Bytes(), &a) != nil || json.Unmarshal(pretty.Bytes(), &b) != nil || len(a) != len(b) {
		t.Error("compact and pretty should carry the same fields")
	}
}

func TestMissingEngineExitsTwoWithHint(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"--scope", scopeFile(t), "-u", "https://a.example.com/", "--arjun", "/nonexistent/arjun"}, &out, &errb)
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	var v struct {
		Errors []struct{ Kind, Hint string }
		Raw    string
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil || len(v.Errors) != 1 || v.Errors[0].Kind != "missing_engine" || !strings.Contains(v.Errors[0].Hint, "--arjun") || v.Raw != "" {
		t.Errorf("stdout = %s", out.String())
	}
}

func TestUsageErrorsExitOne(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--input", "../../testdata/sample.json"}, &out, &errb); code != 1 {
		t.Errorf("no --scope: exit %d, want 1", code)
	}
	if code := run([]string{"--scope", scopeFile(t), "-u", "https://out.of-scope.net/"}, &out, &errb); code != 1 {
		t.Errorf("no target in scope: exit %d, want 1", code)
	}
	if code := run([]string{"--scope", scopeFile(t), "-u", "https://a.example.com/", "--method", "PUT"}, &out, &errb); code != 1 {
		t.Errorf("unknown method: exit %d, want 1", code)
	}
}

func TestSummaryAndOrigin(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--scope", scopeFile(t), "--input", "../../testdata/sample.json"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d", code)
	}
	s := out.String()
	if !strings.Contains(s, `"summary":"10 URLs, 23 parameters (13 names): 8 findings (3 high, 4 medium, 1 low), 5 groups","origin":"https://app.example.com"`) {
		t.Errorf("summary: %s", s)
	}
	if !strings.Contains(s, `"omitted":{"duplicates":2,"out_of_scope":1}`) {
		t.Errorf("omitted: %s", s)
	}
	if !strings.Contains(s, `"method":"JSON","headers":{"Cookie":"session=abc"}`) || strings.Contains(s, "User-Agent") {
		t.Errorf("only custom headers should be written: %s", s)
	}
}

func TestTableFormat(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--format", "table", "--scope", scopeFile(t), "--input", "../../testdata/sample.json"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{"HIGH     ssrf callback,url (2)", "MEDIUM   id POST username (1)", "group    currency,page (4)", "HIGH     rce JSON cmd (1 custom headers) (1)"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("table should contain %q:\n%s", want, out.String())
		}
	}
}

func TestBudgetIsCountedAndPointsToRaw(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--max-bytes", "900", "--scope", scopeFile(t), "--input", "../../testdata/sample.json"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if out.Len() > 901 {
		t.Errorf("output is %d bytes", out.Len())
	}
	var v struct {
		Omitted map[string]int
		Next    []string
		Budget  struct{ Truncated bool }
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil || !v.Budget.Truncated || v.Omitted["groups"]+v.Omitted["locations"] == 0 || len(v.Next) != 1 || !strings.Contains(v.Next[0], "sample.json") {
		t.Errorf("stdout = %s", out.String())
	}
}

// fakeArjun writes a script that answers like arjun: one export per method, nothing for /none.
func fakeArjun(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "arjun")
	script := `#!/bin/sh
while [ $# -gt 0 ]; do
  case "$1" in
    -i) list=$2; shift ;;
    -oJ) out=$2; shift ;;
    -m) m=$2; shift ;;
  esac
  shift
done
echo "$m" >> "$(dirname "$0")/calls"
if [ "$m" = GET ]; then
  printf '{"https://a.example.com/fetch": {"headers": {}, "method": "GET", "params": ["url", "page"]}}' > "$out"
fi
grep -q evil "$list" && echo "out of scope target reached arjun" >&2 && exit 3
exit 0
`
	if err := os.WriteFile(p, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLiveRunPerMethodSavesRaw(t *testing.T) {
	bin := fakeArjun(t)
	raw := filepath.Join(t.TempDir(), "raw.json")
	var out, errb bytes.Buffer
	code := run([]string{"--scope", scopeFile(t), "-u", "https://a.example.com/fetch", "-u", "a.example.com/none", "-u", "https://evil.net/", "--method", "GET,POST", "--arjun", bin, "--raw", raw}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d: %s %s", code, out.String(), errb.String())
	}
	calls, _ := os.ReadFile(filepath.Join(filepath.Dir(bin), "calls"))
	if string(calls) != "GET\nPOST\n" {
		t.Errorf("arjun calls: %q", calls)
	}
	s := out.String()
	for _, want := range []string{`"target":"2 target(s) (1 out of scope skipped)"`, `"summary":"1 URLs, 2 parameters (2 names): 1 findings (1 high), 1 groups, 1 targets without parameters"`, `"raw":"` + raw + `"`, `"omitted":{"out_of_scope":1}`} {
		if !strings.Contains(s, want) {
			t.Errorf("want %s in %s", want, s)
		}
	}
	b, _ := os.ReadFile(raw)
	if !strings.Contains(string(b), `"params": ["url", "page"]`) {
		t.Errorf("raw should hold arjun's export: %q", b)
	}
	var replay bytes.Buffer
	if code := run([]string{"--scope", scopeFile(t), "--input", raw}, &replay, &errb); code != 0 || !strings.Contains(replay.String(), `"params":["url"]`) {
		t.Errorf("raw should replay with --input: %s", replay.String())
	}
}

// With only --scope, every host the scope names is tested as https://<host>/, a wildcard gets a
// next step, and raijin-crawl is suggested once.
func TestScopeAloneTestsWhatTheScopeNames(t *testing.T) {
	dir := t.TempDir()
	scopePath := filepath.Join(dir, "scope.txt")
	if err := os.WriteFile(scopePath, []byte("example.com\n*.example.com\n10.0.0.0/30\n!10.0.0.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := filepath.Join(dir, "targets.txt")
	fake := filepath.Join(dir, "arjun")
	script := "#!/bin/sh\nwhile [ $# -gt 0 ]; do [ \"$1\" = -i ] && cp \"$2\" " + got + "; [ \"$1\" = -oJ ] && echo '{}' > \"$2\"; shift; done\n"
	if err := os.WriteFile(fake, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"--scope", scopePath, "--arjun", fake, "--raw", filepath.Join(dir, "raw.json")}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s %s", code, errb.String(), out.String())
	}
	b, err := os.ReadFile(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(strings.Fields(string(b)), ",") != "https://example.com/,https://10.0.0.0/,https://10.0.0.2/,https://10.0.0.3/" {
		t.Errorf("arjun got targets %q", b)
	}
	var res struct{ Next []string }
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Next) != 2 || !strings.Contains(res.Next[0], "raijin-subs --scope "+scopePath+" -d example.com") || !strings.HasPrefix(res.Next[1], "raijin-crawl --scope "+scopePath) {
		t.Errorf("next = %v", res.Next)
	}
}
