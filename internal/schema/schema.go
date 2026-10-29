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

import core "github.com/protonnegativo/raijin-core/schema"

// The envelope (Result, Error, Budget, schema_version, Marshal, the ranks) lives in raijin-core and is
// shared by every Raijin tool. Finding and Group stay here: their fields are this tool's contract.
type (
	// Result is the top-level object this tool writes to stdout. Origin is the scheme and host every URL
	// shares; locations are then written without it.
	Result = core.Result[Finding, Group]
	Error  = core.Error
	Budget = core.Budget
)

var (
	Marshal        = core.Marshal
	Write          = core.Write
	SeverityRank   = core.SeverityRank
	ConfidenceRank = core.ConfidenceRank
)

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
