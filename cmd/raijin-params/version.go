package main

import (
	"fmt"
	"runtime/debug"
	"sort"
	"strings"

	raijinparams "github.com/protonnegativo/raijin-params"
)

// version is the release this binary was installed from (go install ...@vX.Y.Z or @latest), or "dev"
// plus the commit for a local go build.
var version = buildVersion(debug.ReadBuildInfo())

// buildVersion is the module version when it is a real one; otherwise "dev", then the first 12 chars of
// vcs.revision and +dirty when vcs.modified is true. A build from a checkout records vcs.* settings (and,
// since Go 1.24, a pseudo-version made from them): that is a local build, not a release; go install
// from the module proxy records none.
func buildVersion(info *debug.BuildInfo, ok bool) string {
	if !ok || info == nil {
		return "dev"
	}
	local := false
	for _, s := range info.Settings {
		local = local || strings.HasPrefix(s.Key, "vcs.")
	}
	if v := info.Main.Version; !local && v != "" && v != "(devel)" {
		return v
	}
	v := "dev"
	var rev string
	var dirty bool
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if rev != "" {
		if len(rev) > 12 {
			rev = rev[:12]
		}
		v += "-" + rev
	}
	if dirty {
		v += "+dirty"
	}
	return v
}

// versionLine is what --version prints: the release and the engine versions it was tested with.
func versionLine() string {
	line := "raijin-params " + version
	engines, err := raijinparams.Engines()
	if err != nil || len(engines) == 0 {
		return line
	}
	names := make([]string, 0, len(engines))
	for n := range engines {
		names = append(names, n)
	}
	sort.Strings(names)
	tested := make([]string, len(names))
	for i, n := range names {
		tested[i] = n + " " + engines[n].Version
	}
	return fmt.Sprintf("%s (tested with %s)", line, strings.Join(tested, ", "))
}
