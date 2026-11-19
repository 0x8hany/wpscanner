package fingerprint

import (
	"regexp"
	"strings"
	"sync"

	"wpscanner/httpclient"
)

var stableTagRe = regexp.MustCompile(`(?i)Stable tag:\s*([\w.\-]+)`)

// Plugin is a detected plugin and, if found, its version.
type Plugin struct {
	Slug    string
	Version string
	Source  string // where we found it (readme.txt, style link, etc.)
}

// EnumeratePlugins checks each slug in the wordlist for a public readme.txt
// under wp-content/plugins/<slug>/readme.txt, extracting the Stable tag as
// the installed version. Runs with bounded concurrency.
func EnumeratePlugins(c *httpclient.Client, baseURL string, slugs []string, concurrency int) []Plugin {
	baseURL = strings.TrimRight(baseURL, "/")
	if concurrency <= 0 {
		concurrency = 10
	}

	sem := make(chan struct{}, concurrency)
	resultsCh := make(chan Plugin, len(slugs))
	var wg sync.WaitGroup

	for _, slug := range slugs {
		slug := slug
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			url := baseURL + "/wp-content/plugins/" + slug + "/readme.txt"
			body, status, err := c.GetBody(url, 200_000)
			if err != nil || status != 200 || len(body) == 0 {
				return
			}
			// Guard against soft-404 pages that return 200 with an HTML error page.
			if strings.Contains(strings.ToLower(body[:min(len(body), 500)]), "<html") {
				return
			}

			p := Plugin{Slug: slug, Source: "readme.txt"}
			if m := stableTagRe.FindStringSubmatch(body); len(m) == 2 {
				p.Version = strings.TrimSpace(m[1])
			}
			resultsCh <- p
		}()
	}

	wg.Wait()
	close(resultsCh)

	var found []Plugin
	for p := range resultsCh {
		found = append(found, p)
	}
	return found
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
