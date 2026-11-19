// wpscanner is a lightweight WordPress recon / vulnerability-surface scanner
// intended for authorized security testing only. Always confirm you have
// explicit permission to scan a target before running this against it.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"time"

	"wpscanner/fingerprint"
	"wpscanner/httpclient"
	"wpscanner/modules"
	"wpscanner/report"
)

// defaultPluginSlugs / defaultThemeSlugs are small built-in lists so the
// tool works out of the box. For real engagements, pass -plugin-list /
// -theme-list pointing at a proper wordlist (e.g. SecLists' wp-plugins.fuzz.txt).
var defaultPluginSlugs = []string{
	"akismet", "jetpack", "woocommerce", "contact-form-7", "wordfence",
	"yoast-seo", "elementor", "wp-super-cache", "all-in-one-seo-pack",
	"duplicate-post", "wp-fastest-cache", "really-simple-ssl", "mailchimp-for-wp",
	"wpforms-lite", "classic-editor", "updraftplus", "litespeed-cache",
	"advanced-custom-fields", "wp-mail-smtp", "google-site-kit",
}

var defaultThemeSlugs = []string{
	"twentytwentyfour", "twentytwentythree", "twentytwentytwo", "twentytwentyone",
	"astra", "generatepress", "oceanwp", "divi", "avada", "hello-elementor",
}

func main() {
	target := flag.String("u", "", "Target base URL, e.g. https://example.com (required)")
	timeout := flag.Duration("timeout", 10*time.Second, "Per-request timeout")
	rps := flag.Float64("rps", 5, "Max requests per second (politeness/rate limit)")
	concurrency := flag.Int("c", 10, "Concurrency for plugin/theme enumeration")
	insecure := flag.Bool("insecure", false, "Skip TLS certificate verification (self-signed/lab targets)")
	enumUsers := flag.Bool("enum-users", true, "Attempt username enumeration (?author= + REST API)")
	enumAuthorMax := flag.Int("enum-users-max", 10, "Highest ?author=N ID to try")
	pluginList := flag.String("plugin-list", "", "Path to a newline-delimited plugin slug wordlist (overrides built-in list)")
	themeList := flag.String("theme-list", "", "Path to a newline-delimited theme slug wordlist (overrides built-in list)")
	jsonOut := flag.String("json", "", "Write full report as JSON to this path")
	skipPlugins := flag.Bool("no-plugins", false, "Skip plugin enumeration")
	skipThemes := flag.Bool("no-themes", false, "Skip theme enumeration")

	flag.Parse()

	if *target == "" {
		fmt.Fprintln(os.Stderr, "Usage: wpscanner -u https://target.example [flags]")
		flag.PrintDefaults()
		os.Exit(1)
	}

	fmt.Println("wpscanner — for authorized security testing only.")
	fmt.Println("Make sure you have explicit permission to scan:", *target)

	client := httpclient.New(*timeout, *rps, *insecure)

	rep := &report.Report{
		Target:    *target,
		ScannedAt: time.Now(),
	}

	fmt.Println("\n[*] Fingerprinting WordPress core...")
	rep.Core = fingerprint.DetectCore(client, *target)
	if !rep.Core.IsWordPress {
		fmt.Println("[!] WordPress not confidently detected. Continuing anyway (results may be sparse).")
	} else {
		v := rep.Core.Version
		if v == "" {
			v = "unknown"
		}
		fmt.Printf("[+] WordPress detected (version: %s)\n", v)
	}

	if !*skipPlugins {
		slugs := defaultPluginSlugs
		if *pluginList != "" {
			loaded, err := loadWordlist(*pluginList)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[!] Failed to load plugin wordlist: %v (falling back to built-in list)\n", err)
			} else {
				slugs = loaded
			}
		}
		fmt.Printf("[*] Enumerating plugins (%d candidates)...\n", len(slugs))
		rep.Plugins = fingerprint.EnumeratePlugins(client, *target, slugs, *concurrency)
		fmt.Printf("[+] Found %d plugin(s)\n", len(rep.Plugins))
	}

	if !*skipThemes {
		slugs := defaultThemeSlugs
		if *themeList != "" {
			loaded, err := loadWordlist(*themeList)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[!] Failed to load theme wordlist: %v (falling back to built-in list)\n", err)
			} else {
				slugs = loaded
			}
		}
		fmt.Printf("[*] Enumerating themes (%d candidates)...\n", len(slugs))
		rep.Themes = fingerprint.EnumerateThemes(client, *target, slugs, *concurrency)
		fmt.Printf("[+] Found %d theme(s)\n", len(rep.Themes))
	}

	if *enumUsers {
		fmt.Println("[*] Enumerating users (REST API + ?author=)...")
		var users []modules.User
		users = append(users, modules.EnumerateUsersViaRESTAPI(client, *target)...)
		users = append(users, modules.EnumerateUsersViaAuthorParam(client, *target, *enumAuthorMax)...)
		rep.Users = dedupeUsers(users)
		fmt.Printf("[+] Found %d user(s)\n", len(rep.Users))
	}

	fmt.Println("[*] Checking XML-RPC exposure...")
	rep.XMLRPC = modules.CheckXMLRPC(client, *target)

	fmt.Println("[*] Checking common misconfigurations...")
	if f := modules.CheckRESTAPIExposed(client, *target); f != nil {
		rep.Findings = append(rep.Findings, *f)
	}
	if f := modules.CheckUploadsDirListing(client, *target); f != nil {
		rep.Findings = append(rep.Findings, *f)
	}
	if f := modules.CheckDebugLogExposed(client, *target); f != nil {
		rep.Findings = append(rep.Findings, *f)
	}
	rep.Findings = append(rep.Findings, modules.CheckConfigBackups(client, *target)...)

	rep.PrintConsole()

	if *jsonOut != "" {
		if err := rep.WriteJSON(*jsonOut); err != nil {
			fmt.Fprintf(os.Stderr, "[!] Failed to write JSON report: %v\n", err)
		} else {
			fmt.Printf("[+] JSON report written to %s\n", *jsonOut)
		}
	}
}

func loadWordlist(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines, sc.Err()
}

func dedupeUsers(users []modules.User) []modules.User {
	seen := map[string]bool{}
	var out []modules.User
	for _, u := range users {
		key := u.Slug
		if key == "" {
			key = fmt.Sprintf("id-%d", u.ID)
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, u)
	}
	return out
}
