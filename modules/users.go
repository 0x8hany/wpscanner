package modules

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"wpscanner/httpclient"
)

// User is an enumerated WordPress username/display name.
type User struct {
	ID          int
	Slug        string
	Name        string
	Source      string
}

var authorSlugRe = regexp.MustCompile(`(?i)author/([\w\-]+)/?["']`)

// EnumerateUsersViaAuthorParam walks ?author=1..N and reads the redirect
// Location header or page content to recover author slugs. Many hardened
// sites block this, so failures here are expected/normal.
func EnumerateUsersViaAuthorParam(c *httpclient.Client, baseURL string, maxID int) []User {
	baseURL = strings.TrimRight(baseURL, "/")
	var users []User

	// Don't follow redirects automatically so we can read Location directly.
	noRedirect := *c.HTTP
	noRedirect.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	for id := 1; id <= maxID; id++ {
		url := fmt.Sprintf("%s/?author=%d", baseURL, id)
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", c.UserAgent)
		resp, err := noRedirect.Do(req)
		if err != nil {
			continue
		}
		loc := resp.Header.Get("Location")
		resp.Body.Close()

		if loc != "" {
			if m := authorSlugRe.FindStringSubmatch(loc + `"`); len(m) == 2 {
				users = append(users, User{ID: id, Slug: m[1], Source: "?author= redirect"})
			}
		}
	}
	return users
}

// wpUser mirrors the relevant fields of the WP REST API /wp/v2/users response.
type wpUser struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
	Slug string `json:"slug"`
}

// EnumerateUsersViaRESTAPI hits /wp-json/wp/v2/users, which is enabled by
// default and frequently leaks display names + slugs for all users.
func EnumerateUsersViaRESTAPI(c *httpclient.Client, baseURL string) []User {
	baseURL = strings.TrimRight(baseURL, "/")
	body, status, err := c.GetBody(baseURL+"/wp-json/wp/v2/users", 500_000)
	if err != nil || status != 200 {
		return nil
	}

	var raw []wpUser
	if err := json.Unmarshal([]byte(body), &raw); err != nil {
		return nil
	}

	var users []User
	for _, u := range raw {
		users = append(users, User{ID: u.ID, Slug: u.Slug, Name: u.Name, Source: "REST API /wp/v2/users"})
	}
	return users
}
