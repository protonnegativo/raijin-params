// Package schema defines the Raijin Schema, the JSON shape every Raijin tool returns.
//
// Nothing the engine found is dropped silently: every URL, method and parameter arjun reported is listed,
// in a finding or in a group, and anything a budget cuts is counted in Omitted. What an agent can rebuild
// is left out of the JSON to save tokens: empty lists, the budget when nothing was cut, a count equal to
// the URLs listed, and fields at their documented default.
//
// raijin-params adds the parameter fields (params, method, headers) to findings and groups, and Origin
// to the result: they are what an agent reads to build its next requests.
package schema

import (
	"bytes"
	"encoding/json"
)

// Marshal is json.Marshal without HTML escaping: "&" in a URL stays "&" instead of "&", which costs
// tokens and nothing else.
func Marshal(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}

// Result is the top-level object a Raijin tool writes to stdout.
type Result struct {
	Tool    string `json:"tool"`
	Version string `json:"version"`
	Target  string `json:"target"`
	Summary string `json:"summary"`
	// Origin is the scheme and host every URL shares; locations are then written without it.
	Origin   string         `json:"origin,omitempty"`
	Findings []Finding      `json:"findings"`
	Groups   []Group        `json:"groups"`
	Omitted  map[string]int `json:"omitted,omitempty"`
	Errors   []Error        `json:"errors,omitempty"`
	Next     []string       `json:"next,omitempty"`
	// Raw is the file with the engine's full output, for details the result leaves out.
	Raw    string `json:"raw,omitempty"`
	Budget Budget `json:"budget"`
}

// MarshalJSON writes the budget only when something was cut.
func (r Result) MarshalJSON() ([]byte, error) {
	type plain Result
	out := struct {
		plain
		Budget *Budget `json:"budget,omitempty"`
	}{plain: plain(r)}
	if r.Budget.Truncated {
		out.Budget = &r.Budget
	}
	return Marshal(out)
}

// Request is how the parameters of an entry are sent. Zero values are left out: no method means GET
// (query string), and no headers means arjun sent only its default headers.
type Request struct {
	// Params are the parameter names, sorted. Every URL of the entry has every one of them.
	Params []string `json:"params"`
	// Method is arjun's method when it is not GET: POST (form body), JSON (JSON body) or XML.
	Method string `json:"method,omitempty"`
	// Headers are the request headers arjun sent that are not among its defaults (a cookie, a token).
	Headers map[string]string `json:"headers,omitempty"`
}

// Finding is a set of parameters whose names suggest one attack class (ssrf, file, redirect...) and every
// URL where arjun found exactly that set. The same tool and ID in two runs is the same finding.
type Finding struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	// Confidence is "verified" or "heuristic"; empty means "matched".
	Confidence string `json:"confidence,omitempty"`
	// Tags are the attack class the parameter names suggest: rce, ssrf, file, redirect, admin, debug,
	// id or injection.
	Tags []string `json:"tags"`
	Request
	// Locations are every URL of the finding, numeric runs written as ranges ("/item/[1-60]").
	Locations []string `json:"locations,omitempty"`
	// Count is the number of URLs; it is set only when the budget cut Locations.
	Count int `json:"count,omitempty"`
	// URLs is the number of URLs, for ranking, the summary and Count; it is not written.
	URLs int `json:"-"`
	// Fingerprint is the internal key for --state; it is derived from the ID and not written.
	Fingerprint string `json:"-"`
	New         bool   `json:"new,omitempty"`
}

// Group is a set of plain parameters (no attack class) and every URL where arjun found exactly that set.
// 30 product pages with page, currency and format are one group.
type Group struct {
	ID string `json:"id"`
	Request
	Locations []string `json:"locations,omitempty"`
	// Count is the number of URLs; it is set only when the budget cut Locations.
	Count int `json:"count,omitempty"`
	URLs  int `json:"-"`
}

// Error is a problem during the run, with a hint about what to try next.
type Error struct {
	Kind string `json:"kind"`
	Hint string `json:"hint"`
}

// Budget reports the output limits that were applied.
type Budget struct {
	MaxItems  int  `json:"max_items"`
	MaxBytes  int  `json:"max_bytes"`
	Truncated bool `json:"truncated"`
}

// SeverityRank orders severities from most to least important.
var SeverityRank = map[string]int{
	"critical": 5,
	"high":     4,
	"medium":   3,
	"low":      2,
	"info":     1,
	"unknown":  0,
}

// ConfidenceRank orders confidence values: a verified finding before a matched one before a heuristic one.
var ConfidenceRank = map[string]int{
	"verified":  2,
	"":          1,
	"heuristic": 0,
}
