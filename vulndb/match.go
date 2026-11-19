package vulndb

// Vulnerability is a minimal normalized record, regardless of source
// (local JSON DB, WPScan API, or hand-curated list).
type Vulnerability struct {
	Title       string
	FixedIn     string // version where this was patched, "" if unknown/unpatched
	CVE         string // optional
	Reference   string // optional URL
	Severity    string // informational | low | medium | high | critical
}

// Component is something we detected a version for (core, a plugin, a theme).
type Component struct {
	Type    string // "core" | "plugin" | "theme"
	Slug    string // "" for core
	Version string
}

// Source is anything that can answer "what vulns exist for this component".
// The local stub and the future WPScan API client both implement this,
// so swapping/adding sources doesn't touch the scanning logic.
type Source interface {
	Lookup(Component) ([]Vulnerability, error)
}
