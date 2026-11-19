package modules

import (
	"strings"

	"wpscanner/httpclient"
)

// Finding is a generic exposure/misconfiguration hit.
type Finding struct {
	Title       string
	Path        string
	Severity    string // info | low | medium | high
	Description string
}

// CheckRESTAPIExposed confirms whether the WP REST API root is reachable.
func CheckRESTAPIExposed(c *httpclient.Client, baseURL string) *Finding {
	baseURL = strings.TrimRight(baseURL, "/")
	body, status, err := c.GetBody(baseURL+"/wp-json/", 20_000)
	if err != nil || status != 200 || !strings.Contains(body, "\"routes\"") {
		return nil
	}
	return &Finding{
		Title:       "WP REST API root reachable",
		Path:        "/wp-json/",
		Severity:    "info",
		Description: "REST API is enabled; check /wp-json/wp/v2/users for username disclosure and review exposed routes for auth-bypass-prone endpoints.",
	}
}

// CheckUploadsDirListing flags directory listing on the uploads folder,
// which can leak private media or reveal a full site structure.
func CheckUploadsDirListing(c *httpclient.Client, baseURL string) *Finding {
	baseURL = strings.TrimRight(baseURL, "/")
	body, status, err := c.GetBody(baseURL+"/wp-content/uploads/", 20_000)
	if err != nil || status != 200 {
		return nil
	}
	if strings.Contains(body, "Index of /") || strings.Contains(body, "<title>Index of") {
		return &Finding{
			Title:       "Directory listing enabled on wp-content/uploads",
			Path:        "/wp-content/uploads/",
			Severity:    "medium",
			Description: "Web server directory listing is enabled, exposing the full uploads tree.",
		}
	}
	return nil
}

// CheckConfigBackups probes common wp-config.php backup/leftover filenames.
func CheckConfigBackups(c *httpclient.Client, baseURL string) []Finding {
	baseURL = strings.TrimRight(baseURL, "/")
	candidates := []string{
		"wp-config.php.bak", "wp-config.php~", "wp-config.php.save",
		"wp-config.php.old", "wp-config.php.orig", "wp-config.php.swp",
		"wp-config.txt", "wp-config.php.1",
	}

	var findings []Finding
	for _, name := range candidates {
		body, status, err := c.GetBody(baseURL+"/"+name, 20_000)
		if err != nil || status != 200 || len(strings.TrimSpace(body)) == 0 {
			continue
		}
		// Only flag if it actually looks like config content, to avoid
		// false positives from custom 200-status error pages.
		if strings.Contains(body, "DB_PASSWORD") || strings.Contains(body, "define(") {
			findings = append(findings, Finding{
				Title:       "Exposed wp-config.php backup",
				Path:        "/" + name,
				Severity:    "high",
				Description: "A backup/leftover copy of wp-config.php is publicly readable and may contain database credentials and secret keys.",
			})
		}
	}
	return findings
}

// CheckDebugLogExposed checks for the default debug.log path when
// WP_DEBUG_LOG is enabled without disabling public access.
func CheckDebugLogExposed(c *httpclient.Client, baseURL string) *Finding {
	baseURL = strings.TrimRight(baseURL, "/")
	body, status, err := c.GetBody(baseURL+"/wp-content/debug.log", 5000)
	if err != nil || status != 200 || len(strings.TrimSpace(body)) == 0 {
		return nil
	}
	return &Finding{
		Title:       "Exposed debug.log",
		Path:        "/wp-content/debug.log",
		Severity:    "medium",
		Description: "WP_DEBUG_LOG output is publicly accessible and may leak file paths, plugin errors, or query data.",
	}
}
