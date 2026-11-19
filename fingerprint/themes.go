package fingerprint

import (
	"regexp"
	"strings"
	"sync"

	"wpscanner/httpclient"
)

var themeVersionRe = regexp.MustCompile(`(?i)Version:\s*([\w.\-]+)`)

// Theme is a detected theme and, if found, its version.
type Theme struct {
	Slug    string
	Version string
	Source  string
}

// EnumerateThemes checks each slug against wp-content/themes/<slug>/style.css,
// which WordPress themes are required to ship with a version header.
func EnumerateThemes(c *httpclient.Client, baseURL string, slugs []string, concurrency int) []Theme {
	baseURL = strings.TrimRight(baseURL, "/")
	if concurrency <= 0 {
		concurrency = 10
	}

	sem := make(chan struct{}, concurrency)
	resultsCh := make(chan Theme, len(slugs))
	var wg sync.WaitGroup

	for _, slug := range slugs {
		slug := slug
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			url := baseURL + "/wp-content/themes/" + slug + "/style.css"
			body, status, err := c.GetBody(url, 100_000)
			if err != nil || status != 200 || len(body) == 0 {
				return
			}
			if strings.Contains(strings.ToLower(body[:min(len(body), 500)]), "<html") {
				return
			}
			// A real theme stylesheet has a "Theme Name:" header.
			if !strings.Contains(body, "Theme Name") {
				return
			}

			t := Theme{Slug: slug, Source: "style.css"}
			if m := themeVersionRe.FindStringSubmatch(body); len(m) == 2 {
				t.Version = strings.TrimSpace(m[1])
			}
			resultsCh <- t
		}()
	}

	wg.Wait()
	close(resultsCh)

	var found []Theme
	for t := range resultsCh {
		found = append(found, t)
	}
	return found
}
