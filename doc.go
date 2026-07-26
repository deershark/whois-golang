// Package whois queries domain registration data.
//
// Lookup strategy (per https://deployment.rdap.org/ deployment status):
//
//  1. RDAP is attempted first via the rdap.org bootstrap service, which
//     redirects to the authoritative RDAP server for the TLD based on the
//     IANA bootstrap registry (https://data.iana.org/rdap/dns.json).
//  2. If the TLD has no RDAP deployment (rdap.org answers 404 without a
//     redirect), the client falls back to the classic WHOIS protocol on
//     TCP port 43. The responsible server is resolved from an embedded
//     table, falling back to a whois.iana.org referral lookup.
//
// WHOIS responses differ wildly per registry, so parsing is best-effort:
// a generic key/value parser plus per-TLD rules (jp, uk, br, eu, it, ...)
// normalize the common fields (dates, registrar, name servers, status).
//
// Beyond domains, QueryIP looks up IPv4/IPv6 registrations (RDAP via the
// five RIRs, with a whois.iana.org-referred WHOIS fallback) and QueryASN
// looks up autonomous system numbers (RDAP only).
//
// Usage:
//
//	c := whois.New()
//	rec, err := c.Query("example.com")
//	if err != nil { ... }
//	fmt.Println(rec.Source, rec.Registered, rec.Parsed.Expiry)
//
//	ip, err := c.QueryIP("8.8.8.8")
//	asn, err := c.QueryASN(15169)
//
// The zero-dependency package also exposes Parse and ParseIPWhois (for
// offline WHOIS parsing) and ToASCII (IDN conversion) for reuse.
package whois
