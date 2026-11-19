package modules

import (
	"strings"

	"wpscanner/httpclient"
)

// XMLRPCResult reports whether xmlrpc.php is reachable and which risky
// methods respond, without actually exploiting anything.
type XMLRPCResult struct {
	Enabled             bool
	MultiCallAvailable  bool // system.multicall -> brute-force amplification risk
	PingbackAvailable   bool // pingback.ping -> SSRF/DDoS amplification risk
	Notes               []string
}

const listMethodsBody = `<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>`

// CheckXMLRPC posts a benign system.listMethods call and inspects the
// response for methods known to be abused (multicall brute force, pingback
// SSRF/amplification). This does not attempt to actually exploit either.
func CheckXMLRPC(c *httpclient.Client, baseURL string) XMLRPCResult {
	res := XMLRPCResult{}
	baseURL = strings.TrimRight(baseURL, "/")
	url := baseURL + "/xmlrpc.php"

	// GET should return "XML-RPC server accepts POST requests only." on a
	// stock install — that alone confirms the endpoint is live.
	body, status, err := c.GetBody(url, 50_000)
	if err != nil {
		return res
	}
	if status == 200 || status == 405 {
		res.Enabled = true
		res.Notes = append(res.Notes, "xmlrpc.php reachable")
	}
	if strings.Contains(body, "XML-RPC server accepts POST") {
		res.Enabled = true
	}

	if !res.Enabled {
		return res
	}

	// POST system.listMethods to see what's exposed. This is read-only
	// introspection, not an attack.
	respBody, postStatus, err := postXML(c, url, listMethodsBody)
	if err == nil && postStatus == 200 {
		if strings.Contains(respBody, "system.multicall") {
			res.MultiCallAvailable = true
			res.Notes = append(res.Notes, "system.multicall exposed — usable for brute-force amplification")
		}
		if strings.Contains(respBody, "pingback.ping") {
			res.PingbackAvailable = true
			res.Notes = append(res.Notes, "pingback.ping exposed — usable for SSRF/DDoS amplification")
		}
	}

	return res
}

func postXML(c *httpclient.Client, url, body string) (string, int, error) {
	if c.Throttle != nil {
		<-c.Throttle
	}
	req, err := httpNewPost(url, body)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("User-Agent", c.UserAgent)
	req.Header.Set("Content-Type", "text/xml")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	buf := make([]byte, 100_000)
	n, _ := resp.Body.Read(buf)
	return string(buf[:n]), resp.StatusCode, nil
}
