package arjun

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// arjun has no version flag, so InstalledVersion asks the Python that runs it (the interpreter on the
// script's #! line, which is the venv's own for pipx) for the installed package's version.
const versionScript = "import importlib.metadata as m; print(m.version('arjun'))"

// InstalledVersion returns the version of the arjun package behind bin, or "" when it cannot tell. It
// gives up after 3 seconds.
func InstalledVersion(ctx context.Context, bin string) string {
	path, err := exec.LookPath(bin)
	if err != nil {
		return ""
	}
	py := interpreter(path)
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	args := append(py[1:], "-c", versionScript)
	out, _ := exec.CommandContext(ctx, py[0], args...).CombinedOutput()
	return ParseVersion(string(out))
}

// interpreter reads the #! line of the arjun script; python3 when there is none.
func interpreter(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return []string{"python3"}
	}
	defer f.Close()
	line, _ := bufio.NewReader(f).ReadString('\n')
	fields := strings.Fields(strings.TrimPrefix(line, "#!"))
	if !strings.HasPrefix(line, "#!") || len(fields) == 0 || !strings.Contains(line, "python") {
		return []string{"python3"}
	}
	return fields
}

var versionRe = regexp.MustCompile(`v?(\d+)\.(\d+)\.(\d+)`)

// ParseVersion returns the first X.Y.Z in s, or "".
func ParseVersion(s string) string {
	m := versionRe.FindStringSubmatch(s)
	if m == nil {
		return ""
	}
	return m[1] + "." + m[2] + "." + m[3]
}

// Untested is true when installed has another major version than tested, or is older. Newer minor and
// patch versions, and versions that do not parse, are not reported.
func Untested(installed, tested string) bool {
	a, b := nums(installed), nums(tested)
	if a == nil || b == nil {
		return false
	}
	if a[0] != b[0] {
		return true
	}
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

func nums(v string) []int {
	m := versionRe.FindStringSubmatch(v)
	if m == nil {
		return nil
	}
	out := make([]int, 3)
	for i := range out {
		out[i], _ = strconv.Atoi(m[i+1])
	}
	return out
}

// Malformed counts the results without the fields Raijin needs from each export entry: params and
// method. A missing params key decodes as nil (arjun writes an entry only when it found parameters).
func Malformed(results []Result) int {
	n := 0
	for _, r := range results {
		if r.Params == nil || r.Method == "" {
			n++
		}
	}
	return n
}
