package vulndb

// NullSource is a placeholder that returns no vulnerabilities. It lets the
// scanner run standalone (no API key, no local DB) while keeping the wiring
// for a real Source in place.
//
// TODO(next): implement a WPScanAPISource that calls
// https://wpscan.com/api/v3/{wordpresses,plugins,themes}/<slug>[<version>]
// with an API key (header "Authorization: Token token=<key>"), respecting
// the free-tier rate limit (25 req/day at time of writing), and normalizing
// results into []Vulnerability. It should satisfy the same Source interface
// so main.go only needs a one-line swap.
type NullSource struct{}

func (NullSource) Lookup(c Component) ([]Vulnerability, error) {
	return nil, nil
}
