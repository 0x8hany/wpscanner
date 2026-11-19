# wpscanner
# wpscanner

A lightweight WordPress recon and vulnerability-surface scanner written in Go.

> **For authorized security testing only.** Only scan systems you own or have explicit written permission to test.

## Features
- WordPress core detection and version fingerprinting
- Plugin and theme enumeration (built-in lists or custom wordlists)
- User enumeration via the REST API and `?author=` IDs
- XML-RPC exposure check
- Misconfiguration checks: exposed REST API, uploads directory listing, exposed `debug.log`, config file backups
- Rate limiting, concurrency control, and JSON report output

## Requirements
- Go 1.21+ (adjust to the version in `go.mod`)

## Installation

```bash
git clone https://github.com/0x8hany/wpscanner.git
cd wpscanner
go build -o wpscanner .
```

Run it directly without building:

```bash
go run . -u https://target.example.com
```

## Usage

```bash
./wpscanner -u https://target.example.com
```

With wordlists and a JSON report:

```bash
./wpscanner -u https://target.example.com \
  -plugin-list wp-plugins.txt \
  -theme-list wp-themes.txt \
  -rps 3 -c 5 \
  -json report.json
```

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `-u` | – | Target base URL (required) |
| `-timeout` | `10s` | Per-request timeout |
| `-rps` | `5` | Max requests per second |
| `-c` | `10` | Concurrency for plugin/theme enumeration |
| `-insecure` | `false` | Skip TLS certificate verification |
| `-enum-users` | `true` | Enumerate usernames (REST API and `?author=`) |
| `-enum-users-max` | `10` | Highest `?author=N` ID to try |
| `-plugin-list` | built-in | Path to a plugin slug wordlist |
| `-theme-list` | built-in | Path to a theme slug wordlist |
| `-json` | – | Write the full report as JSON to this path |
| `-no-plugins` | `false` | Skip plugin enumeration |
| `-no-themes` | `false` | Skip theme enumeration |

For real engagements, use a larger wordlist such as SecLists' `wp-plugins.fuzz.txt`.

## Disclaimer
The author is not responsible for misuse. You are responsible for complying with all applicable laws and obtaining authorization before testing.

## License
MIT
