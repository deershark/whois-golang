# whois-golang

English | [中文](README_CN.md)

[![Go Reference](https://pkg.go.dev/badge/github.com/deershark/whois-golang.svg)](https://pkg.go.dev/github.com/deershark/whois-golang)
[![CI](https://github.com/deershark/whois-golang/actions/workflows/ci.yml/badge.svg)](https://github.com/deershark/whois-golang/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/deershark/whois-golang)](https://goreportcard.com/report/github.com/deershark/whois-golang)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A zero-dependency Go library for domain registration lookup.

**RDAP first, WHOIS fallback.** Queries go through the [rdap.org](https://rdap.org) bootstrap service (built on the [IANA RDAP bootstrap registry](https://data.iana.org/rdap/dns.json), the same dataset behind [deployment.rdap.org](https://deployment.rdap.org/)). If the TLD has no RDAP deployment, the library automatically falls back to the classic WHOIS protocol on TCP port 43 — with a parser that actually understands the wildly different formats registries use.

```
google.com   → RDAP  (rdap.verisign.com)
google.de    → WHOIS (whois.denic.de)     .de has no RDAP
google.shop  → RDAP  (rdap.gmoregistry.net) .shop retired port 43 in 2026
```

## Features

- **RDAP-first strategy** — correct distinction between *"TLD has no RDAP"* (fall back) and *"domain not registered"* (report availability).
- **Battle-tested WHOIS parser** — generic key/value extraction plus per-TLD rules, validated against **28 real responses** captured from the official servers: `com org de jp uk ru cn fr br it eu kr hk tw tr au nl us ca xyz in io me vc` (and more).
  - JPRS bracket format (`[Created on]`, `p. [Name Server]`, expiry from `[State] Connected (…)`)
  - Nominet block format with next-line values and IPv6-carrying name server lines
  - EURid / nic.it colon-less sections, TRABIS `** Key` decoration, KISA bilingual layout, TWNIC colon-less dates, CNNIC, TCI (.ru), registro.br compact dates …
- **Availability detection** — per-registry not-found patterns (`Status: free`, `No match`, `AVAILABLE`, `No entries found`, …); throttled/empty answers are reported as errors, never as "available".
- **Embedded server map** — ~580 TLD → WHOIS server entries, cross-checked against `whois.iana.org`; unknown TLDs are discovered at runtime through the IANA referral service and cached.
- **Thin-registry referral following** (optional) — enrich Verisign-style thin answers with the registrar's own WHOIS.
- **IDN support** — built-in RFC 3492 punycode encoder (`münchen.de` → `xn--mnchen-3ya.de`), no external dependencies.

## Install

```sh
go get github.com/deershark/whois-golang
```

## Usage

```go
package main

import (
	"fmt"

	whois "github.com/deershark/whois-golang"
)

func main() {
	c := whois.New()
	rec, err := c.Query("google.jp") // .jp has no RDAP → WHOIS fallback
	if err != nil {
		panic(err)
	}
	fmt.Println(rec.Source, rec.Server)       // whois whois.jprs.jp
	fmt.Println(rec.Registered)               // true
	fmt.Println(rec.Parsed.Statuses)          // [Active]
	fmt.Println(rec.Parsed.NameServers)       // [ns1.google.com ns2.google.com ns3.google.com ns4.google.com]
	fmt.Println(rec.Parsed.Created)           // 2005-05-30
	fmt.Println(rec.Parsed.Expiry)            // 2027-05-31
}
```

### Options

```go
c := whois.New(
	whois.WithTimeout(15*time.Second),        // per-request network timeout
	whois.WithPreferRDAP(true),               // try RDAP first (default)
	whois.WithWhoisFallback(true),            // fall back to port 43 (default)
	whois.WithReferralFollowing(true),        // follow "Registrar WHOIS Server" for thick data
	whois.WithRDAPBaseURL("https://rdap.verisign.com/com/v1"), // custom RDAP endpoint
	whois.WithWhoisServer("test", "127.0.0.1:1043"),           // pin a server per TLD
	whois.WithHTTPClient(customHTTP),         // custom *http.Client
)
```

### Result

```go
type Record struct {
	Domain      string      // normalized A-label form
	Source      Source      // "rdap" or "whois"
	Server      string      // authoritative server that answered
	Registered  bool        // false when the registry reports the domain as available
	Raw         string      // raw response (JSON for RDAP, text for WHOIS)
	RegistryRaw string      // original thin-registry answer when a referral was followed
	Parsed      *ParsedInfo // normalized fields: dates, registrar, statuses, name servers, contacts…
}
```

### Helpers

```go
info, registered := whois.Parse("uk", rawResponse) // offline WHOIS parsing
ok := whois.IsAvailable("de", rawResponse)
alabel, _ := whois.ToASCII("新华网.cn")              // xn--xkrr14bows.cn
```

## Testing

```sh
go test ./...                 # unit tests (offline, fake servers, real samples)
WHOIS_LIVE=1 go test ./...    # additionally hit real registries (rate limits apply)
```

The `testdata/` samples are genuine responses fetched from the official
servers in July 2026 — they document each registry's real format, including
edge cases like DENIC's two-line answers and EURid's dateless output.

## Notes on coverage

- All ~1200 TLDs in the IANA RDAP bootstrap work through the RDAP path.
- The embedded WHOIS map covers ~580 TLDs and is cross-verified against IANA;
  registries that shut down port 43 (`.info`, `.mobi`, `.pro`, Google TLDs,
  GMO TLDs like `.shop`/`.tokyo`, …) are intentionally absent — they are
  served by RDAP.
- Some registries (`.ch`, `.li`, `.at`, …) restrict port-43 access by client
  IP; the library surfaces their refusal as an error rather than guessing.

## License

[MIT](LICENSE)
