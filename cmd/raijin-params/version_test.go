package main

import (
	"runtime/debug"
	"testing"

	raijinparams "github.com/protonnegativo/raijin-params"
)

func TestBuildVersion(t *testing.T) {
	vcs := func(rev, modified string) []debug.BuildSetting {
		return []debug.BuildSetting{{Key: "vcs.revision", Value: rev}, {Key: "vcs.modified", Value: modified}}
	}
	for _, c := range []struct {
		info *debug.BuildInfo
		ok   bool
		want string
	}{
		{&debug.BuildInfo{Main: debug.Module{Version: "v0.1.3"}}, true, "v0.1.3"},
		{&debug.BuildInfo{Main: debug.Module{Version: "(devel)"}, Settings: vcs("0123456789abcdef", "false")}, true, "dev-0123456789ab"},
		{&debug.BuildInfo{Main: debug.Module{Version: "(devel)"}, Settings: vcs("0123456789abcdef", "true")}, true, "dev-0123456789ab+dirty"},
		{&debug.BuildInfo{Main: debug.Module{Version: "v0.1.4-0.20261025032210-0123456789ab+dirty"}, Settings: vcs("0123456789abcdef", "true")}, true, "dev-0123456789ab+dirty"},
		{&debug.BuildInfo{Main: debug.Module{Version: "(devel)"}}, true, "dev"},
		{nil, false, "dev"},
	} {
		if got := buildVersion(c.info, c.ok); got != c.want {
			t.Errorf("buildVersion(%+v) = %q, want %q", c.info, got, c.want)
		}
	}
}

func TestVersionLine(t *testing.T) {
	engines, err := raijinparams.Engines()
	if err != nil {
		t.Fatal(err)
	}
	want := "raijin-params " + version + " (tested with arjun " + engines["arjun"].Version + ")"
	if got := versionLine(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
