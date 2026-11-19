package report

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"wpscanner/fingerprint"
	"wpscanner/modules"
)

// Report is the full scan output, serializable to JSON.
type Report struct {
	Target    string               `json:"target"`
	ScannedAt time.Time            `json:"scanned_at"`
	Core      fingerprint.CoreResult `json:"core"`
	Plugins   []fingerprint.Plugin `json:"plugins,omitempty"`
	Themes    []fingerprint.Theme  `json:"themes,omitempty"`
	Users     []modules.User       `json:"users,omitempty"`
	XMLRPC    modules.XMLRPCResult `json:"xmlrpc"`
	Findings  []modules.Finding    `json:"findings,omitempty"`
}

// PrintConsole writes a human-readable summary to stdout.
func (r *Report) PrintConsole() {
	fmt.Printf("\n=== WordPress Scan: %s ===\n", r.Target)
	fmt.Printf("Scanned at: %s\n\n", r.ScannedAt.Format(time.RFC3339))

	fmt.Println("[Core]")
	if r.Core.IsWordPress {
		ver := r.Core.Version
		if ver == "" {
			ver = "unknown"
		}
		fmt.Printf("  WordPress detected — version: %s\n", ver)
		for _, e := range r.Core.Evidence {
			fmt.Printf("    - %s\n", e)
		}
	} else {
		fmt.Println("  WordPress not confidently detected.")
	}

	if len(r.Plugins) > 0 {
		fmt.Println("\n[Plugins]")
		for _, p := range r.Plugins {
			ver := p.Version
			if ver == "" {
				ver = "unknown"
			}
			fmt.Printf("  %-30s version: %-10s (%s)\n", p.Slug, ver, p.Source)
		}
	}

	if len(r.Themes) > 0 {
		fmt.Println("\n[Themes]")
		for _, t := range r.Themes {
			ver := t.Version
			if ver == "" {
				ver = "unknown"
			}
			fmt.Printf("  %-30s version: %-10s (%s)\n", t.Slug, ver, t.Source)
		}
	}

	if len(r.Users) > 0 {
		fmt.Println("\n[Users]")
		for _, u := range r.Users {
			label := u.Slug
			if u.Name != "" {
				label = fmt.Sprintf("%s (%s)", u.Slug, u.Name)
			}
			fmt.Printf("  id=%-4d %-30s via %s\n", u.ID, label, u.Source)
		}
	}

	fmt.Println("\n[XML-RPC]")
	if r.XMLRPC.Enabled {
		fmt.Println("  xmlrpc.php is reachable")
		if r.XMLRPC.MultiCallAvailable {
			fmt.Println("  ⚠ system.multicall exposed (brute-force amplification risk)")
		}
		if r.XMLRPC.PingbackAvailable {
			fmt.Println("  ⚠ pingback.ping exposed (SSRF/DDoS amplification risk)")
		}
	} else {
		fmt.Println("  Not reachable / disabled")
	}

	if len(r.Findings) > 0 {
		fmt.Println("\n[Findings]")
		for _, f := range r.Findings {
			fmt.Printf("  [%s] %s — %s\n", severityTag(f.Severity), f.Title, f.Path)
			fmt.Printf("      %s\n", f.Description)
		}
	}
	fmt.Println()
}

func severityTag(s string) string {
	switch s {
	case "high":
		return "HIGH"
	case "medium":
		return "MED "
	case "low":
		return "LOW "
	default:
		return "INFO"
	}
}

// WriteJSON writes the report as indented JSON to the given path.
func (r *Report) WriteJSON(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
