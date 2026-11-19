package httpclient

import (
	"crypto/tls"
	"io"
	"net/http"
	"time"
)

// Client wraps http.Client with scanner-friendly defaults.
type Client struct {
	HTTP      *http.Client
	UserAgent string
	Throttle  <-chan time.Time // optional rate limiter ticker channel
}

// New builds a Client. reqPerSec <= 0 disables throttling.
// insecureSkipVerify lets you scan targets with self-signed certs (lab use).
func New(timeout time.Duration, reqPerSec float64, insecureSkipVerify bool) *Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureSkipVerify},
		MaxIdleConns:    100,
		IdleConnTimeout: 30 * time.Second,
	}

	c := &Client{
		HTTP: &http.Client{
			Transport: tr,
			Timeout:   timeout,
			// Don't auto-follow redirects blindly past 5 hops (default), but keep default policy.
		},
		UserAgent: "wpscanner/0.1 (+security-research)",
	}

	if reqPerSec > 0 {
		interval := time.Duration(float64(time.Second) / reqPerSec)
		c.Throttle = time.Tick(interval)
	}

	return c
}

// Get performs a GET with the scanner UA, honoring throttle if set.
func (c *Client) Get(url string) (*http.Response, error) {
	if c.Throttle != nil {
		<-c.Throttle
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.UserAgent)
	return c.HTTP.Do(req)
}

// GetBody performs a GET and returns the body as a string, capped at maxBytes.
func (c *Client) GetBody(url string, maxBytes int64) (string, int, error) {
	resp, err := c.Get(url)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	if err != nil {
		return "", resp.StatusCode, err
	}
	return string(body), resp.StatusCode, nil
}
