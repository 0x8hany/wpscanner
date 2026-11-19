package fingerprint

import (
	"regexp"
	"strings"

	"wpscanner/httpclient"
)

var (
	generatorRe = regexp.MustCompile(`(?i)<meta\s+name=["']generator["']\s+content=["']WordPress\s+([\d.]+)["']`)
	verQueryRe  = regexp.MustCompile(`(?i)wp-(?:includes|content)/[^"']+\?ver=([\d.]+)`)
	rssVerRe    = regexp.MustCompile(`(?i)<generator>https?://wordpress\.org/\?v=([\d.]+)</generator>`)
)

// CoreResult holds what we learned about the base WP install.
type CoreResult struct {
	IsWordPress bool
	Version     string // best-effort, may be empty
	Evidence    []string
}

// DetectCore probes the target root and a few known paths to confirm WP
// and attempt version extraction from multiple signal sources.
func DetectCore(c *httpclient.Client, baseURL string) CoreResult {
	res := CoreResult{}
	baseURL = strings.TrimRight(baseURL, "/")

	// 1) Homepage: meta generator tag + asset ?ver= query strings
	if body, status, err := c.GetBody(baseURL+"/", 2_000_000); err == nil && status == 200 {
		if m := generatorRe.FindStringSubmatch(body); len(m) == 2 {
			res.IsWordPress = true
			res.Version = m[1]
			res.Evidence = append(res.Evidence, "meta generator tag on homepage")
		}
		if strings.Contains(body, "wp-content") || strings.Contains(body, "wp-includes") {
			res.IsWordPress = true
			res.Evidence = append(res.Evidence, "wp-content/wp-includes paths referenced in homepage HTML")
		}
		if res.Version == "" {
			if m := verQueryRe.FindStringSubmatch(body); len(m) == 2 {
				res.Version = m[1]
				res.Evidence = append(res.Evidence, "asset ?ver= query string")
			}
		}
	}

	// 2) readme.html — classic version disclosure
	if res.Version == "" {
		if body, status, err := c.GetBody(baseURL+"/readme.html", 200_000); err == nil && status == 200 {
			res.IsWordPress = true
			res.Evidence = append(res.Evidence, "readme.html accessible (version disclosure risk)")
			if m := regexp.MustCompile(`(?i)Version\s+([\d.]+)`).FindStringSubmatch(body); len(m) == 2 {
				res.Version = m[1]
				res.Evidence = append(res.Evidence, "version parsed from readme.html")
			}
		}
	}

	// 3) RSS feed generator tag — often accurate even when homepage is cached/stripped
	if res.Version == "" {
		if body, status, err := c.GetBody(baseURL+"/feed/", 500_000); err == nil && status == 200 {
			res.IsWordPress = true
			if m := rssVerRe.FindStringSubmatch(body); len(m) == 2 {
				res.Version = m[1]
				res.Evidence = append(res.Evidence, "version parsed from RSS feed generator tag")
			}
		}
	}

	// 4) wp-login.php presence as a final WP confirmation signal
	if !res.IsWordPress {
		if _, status, err := c.GetBody(baseURL+"/wp-login.php", 5000); err == nil && (status == 200 || status == 302) {
			res.IsWordPress = true
			res.Evidence = append(res.Evidence, "wp-login.php present")
		}
	}

	return res
}
