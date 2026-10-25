// Package raijinparams holds the engine versions raijin-params was tested with (engines.json), embedded
// into the binary so a run can tell when the installed engine is not one of them.
package raijinparams

import (
	_ "embed"
	"encoding/json"
)

//go:embed engines.json
var enginesJSON []byte

// Engine is one engine entry: the version bench/fixtures were produced with, and where it installs from
// (one of Go, Pip or System).
type Engine struct {
	Version string `json:"version"`
	Go      string `json:"go,omitempty"`
	Pip     string `json:"pip,omitempty"`
	System  string `json:"system,omitempty"`
}

// Engines parses the embedded engines.json.
func Engines() (map[string]Engine, error) {
	var m map[string]Engine
	err := json.Unmarshal(enginesJSON, &m)
	return m, err
}

// Install is the command that installs version v of the engine.
func (e Engine) Install(v string) string {
	switch {
	case e.Go != "":
		return "go install " + e.Go + "@v" + v
	case e.Pip != "":
		return "pipx install " + e.Pip + "==" + v + " (or pip install " + e.Pip + "==" + v + ")"
	default:
		return "install " + e.System + " " + v + " from your package manager"
	}
}
