package whois

import "time"

// Source indicates which protocol produced a Record.
type Source string

const (
	// SourceRDAP means the record came from an RDAP (HTTPS JSON) server.
	SourceRDAP Source = "rdap"
	// SourceWhois means the record came from a classic port-43 WHOIS server.
	SourceWhois Source = "whois"
)

// Record is the result of a successful Query.
type Record struct {
	// Domain is the queried domain, normalized to its A-label form.
	Domain string
	// Source tells whether RDAP or the raw WHOIS protocol answered.
	Source Source
	// Server is the authoritative server that produced the final answer
	// (host name of the RDAP server, or the WHOIS server).
	Server string
	// Registered is false when the registry reports the domain as available.
	Registered bool
	// Raw is the raw response body (JSON for RDAP, plain text for WHOIS).
	// When a WHOIS referral was followed, this is the referral (thick) response.
	Raw string
	// RegistryRaw holds the original thin-registry WHOIS response when a
	// referral was followed; empty otherwise.
	RegistryRaw string
	// Parsed is a best-effort structured view of Raw.
	Parsed *ParsedInfo
}

// ParsedInfo is the normalized registration data shared by RDAP and WHOIS
// responses. Any field may be empty when the registry does not publish it.
type ParsedInfo struct {
	DomainName  string
	Handle      string // registry domain ID / ROID
	Registrar   string
	RegistrarID string // IANA registrar ID
	WhoisServer string // port-43 server advertised by the registry
	Created     *time.Time
	Updated     *time.Time
	Expiry      *time.Time
	Statuses    []string
	NameServers []string
	DNSSec      string
	Registrant  Contact
	Admin       Contact
	Tech        Contact
	Billing     Contact
	// Extra contains every parsed key/value pair (WHOIS source only),
	// keyed by lower-cased field name.
	Extra map[string][]string
}

// Contact is a normalized role contact.
type Contact struct {
	Name         string
	Organization string
	Email        string
	Phone        string
}
