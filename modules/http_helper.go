package modules

import (
	"net/http"
	"strings"
)

func httpNewPost(url, body string) (*http.Request, error) {
	return http.NewRequest(http.MethodPost, url, strings.NewReader(body))
}
