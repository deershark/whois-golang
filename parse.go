package whois

import (
	"regexp"
	"strings"
	"time"
)

// Parse converts a raw WHOIS response for tld into a ParsedInfo and reports
// whether the domain appears to be registered. Parsing is best-effort:
// registries use wildly different formats, so a generic key/value parser is
// combined with per-TLD rules.
func Parse(tld, raw string) (*ParsedInfo, bool) {
	pairs := extractPairs(raw)
	p := &ParsedInfo{Extra: map[string][]string{}}
	for i, kv := range pairs {
		if i >= 400 {
			break
		}
		p.Extra[kv.key] = append(p.Extra[kv.key], kv.value)
	}

	f := &fieldGetter{pairs: pairs}
	p.DomainName = f.get(domainKeys)
	p.Handle = f.get(handleKeys)
	p.Registrar = f.get(registrarKeys)
	p.RegistrarID = f.get(registrarIDKeys)
	p.WhoisServer = f.get(whoisServerKeys)
	p.Created = f.getDate(createdKeys)
	p.Updated = f.getDate(updatedKeys)
	p.Expiry = f.getDate(expiryKeys)
	p.Statuses = f.statuses(statusKeys)
	p.NameServers = f.nameservers(nsKeys)
	// .kr prints the Korean section first; prefer an ASCII DNSSEC value.
	for _, v := range f.getAll(dnssecKeys) {
		if p.DNSSec == "" {
			p.DNSSec = v
		}
		if isASCII(v) {
			p.DNSSec = v
			break
		}
	}

	p.Registrant.Name = f.get(regNameKeys)
	p.Registrant.Organization = f.get(regOrgKeys)
	p.Registrant.Email = f.get(regEmailKeys)
	p.Admin.Name = f.get(adminNameKeys)
	p.Admin.Organization = f.get(adminOrgKeys)
	p.Admin.Email = f.get(adminEmailKeys)
	p.Tech.Name = f.get(techNameKeys)
	p.Tech.Organization = f.get(techOrgKeys)
	p.Tech.Email = f.get(techEmailKeys)
	p.Billing.Name = f.get(billingNameKeys)
	p.Billing.Email = f.get(billingEmailKeys)

	applyTLDRules(strings.ToLower(tld), raw, pairs, p)
	return p, determineRegistered(raw, pairs, p)
}

// IsAvailable reports whether a raw WHOIS response indicates that the domain
// is not registered.
func IsAvailable(tld, raw string) bool {
	_, registered := Parse(tld, raw)
	return !registered
}

type kvPair struct{ key, value string }

// --- field aliases (keys are normalized: lower-cased, no trailing dots) ---

var domainKeys = []string{"domain name", "domain", "domain-name"}
var handleKeys = []string{"registry domain id", "roid", "domain id"}
var registrarKeys = []string{
	"registrar", "sponsoring registrar", "registrar name", "registrar organization",
	"authorized agency",             // kr
	"registration service provider", // tw
}
var registrarIDKeys = []string{"registrar iana id", "iana id"}
var whoisServerKeys = []string{"registrar whois server", "whois server"}

var createdKeys = []string{
	"creation date", "created on", "created", "registered on", "registration time",
	"registration date", "registered date", "domain name commencement date",
	"record created on", "domain registered", "registered",
}
var updatedKeys = []string{
	"updated date", "last updated on", "last update", "last modified", "last-update",
	"last updated", "last updated date", "updated", "changed", "modified",
	"record last updated on",
}
var expiryKeys = []string{
	"registry expiry date", "registrar registration expiration date", "expiration date",
	"expiry date", "expire date", "expires", "expires on", "expiration time",
	"paid-till", "valid until", "record expires on", "renewal date", "expiry",
	"expiration date (yyyy-mm-dd)",
}
var statusKeys = []string{"domain status", "status", "state", "registration status", "eppstatus"}
var nsKeys = []string{
	"name server", "name servers", "nameserver", "nameservers", "nserver",
	"dns servers", "domain servers", "domain servers in listed order", "name servers information",
	"domain nameservers", "hostname", "host name", // nl / kr
}
var dnssecKeys = []string{"dnssec", "dnssec status"}

var regNameKeys = []string{"registrant", "registrant name", "registrant contact name"}
var regOrgKeys = []string{"registrant organization", "registrant contact organization", "org"}
var regEmailKeys = []string{"registrant email", "registrant contact email", "registrant e-mail"}
var adminNameKeys = []string{"admin name", "admin contact name", "administrative contact", "administrative contact(ac)", "admin contact"}
var adminOrgKeys = []string{"admin organization", "admin contact organization"}
var adminEmailKeys = []string{"admin email", "admin contact email", "admin e-mail", "ac e-mail"}
var techNameKeys = []string{"tech name", "tech contact name", "technical contact", "tech contact"}
var techOrgKeys = []string{"tech organization", "tech contact organization"}
var techEmailKeys = []string{"tech email", "tech contact email", "tech e-mail"}
var billingNameKeys = []string{"billing name", "billing contact"}
var billingEmailKeys = []string{"billing email", "billing contact email"}

// --- line-based key/value extraction ---

var (
	bracketLineRe = regexp.MustCompile(`^(?:[a-z]\.\s*)?\[([^\]]{1,60})\]\s*(.*)$`)                 // jp: [Key] / p. [Key]
	recordDateRe  = regexp.MustCompile(`(?i)^record (created|expires|last updated) on\s+(.+?)\s*$`) // tw
)

// looksLikeKeyHeader reports whether line starts a "Key: value" pair, as
// opposed to being a bare value that merely contains a colon (e.g. a name
// server line carrying an IPv6 address). Key headers are short and contain
// no digits.
func looksLikeKeyHeader(line string) bool {
	i := strings.IndexByte(line, ':')
	if i <= 0 || i > 40 {
		return false
	}
	for _, r := range line[:i] {
		switch {
		case r >= '0' && r <= '9':
			return false
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z',
			r == ' ', r == '\'', r == '(', r == ')', r == '/', r == '-', r == '&', r == '.':
		default:
			return false
		}
	}
	return true
}

func extractPairs(raw string) []kvPair {
	var pairs []kvPair
	lines := strings.Split(raw, "\n")
	listKey := ""
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(strings.TrimRight(lines[i], "\r"))
		if line == "" {
			listKey = ""
			continue
		}
		if isNoise(line) {
			continue
		}
		if m := recordDateRe.FindStringSubmatch(line); m != nil {
			pairs = append(pairs, kvPair{"record " + strings.ToLower(m[1]) + " on", m[2]})
			continue
		}
		// Continuation of a bare list (name servers blocks in uk/eu/it/...).
		// A line stays in the list unless it starts a new "Key:" header;
		// values may themselves contain colons (IPv6 addresses).
		if listKey != "" && !looksLikeKeyHeader(line) && !strings.HasPrefix(line, "[") {
			pairs = append(pairs, kvPair{listKey, line})
			continue
		}
		listKey = ""
		if m := bracketLineRe.FindStringSubmatch(line); m != nil {
			pairs = append(pairs, kvPair{normKey(m[1]), strings.TrimSpace(m[2])})
			continue
		}
		idx := strings.Index(line, ":")
		if idx < 0 {
			// Bare block header without colon (.it style: "Nameservers").
			lk := normKey(line)
			if isNSHeader(lk) {
				if j := nextNonEmpty(lines, i+1); j >= 0 {
					nl := strings.TrimSpace(strings.TrimRight(lines[j], "\r"))
					if nl != "" && !strings.Contains(nl, ":") {
						pairs = append(pairs, kvPair{lk, nl})
						listKey = lk
						i = j
					}
				}
			}
			continue
		}
		key := normKey(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		if key == "" || len(key) > 60 {
			continue
		}
		if val == "" {
			// Block header with colon (uk "Registrar:", eu "Name servers:").
			j := nextNonEmpty(lines, i+1)
			if j < 0 {
				continue
			}
			nl := strings.TrimSpace(strings.TrimRight(lines[j], "\r"))
			if looksLikeKeyHeader(nl) || bracketLineRe.MatchString(nl) {
				continue // a sub-key block (fr "Registrant:", jp "Contact Information:")
			}
			pairs = append(pairs, kvPair{key, nl})
			if isNSHeader(key) {
				listKey = key
			}
			i = j
			continue
		}
		pairs = append(pairs, kvPair{key, val})
	}
	return pairs
}

func nextNonEmpty(lines []string, from int) int {
	for j := from; j < len(lines) && j < from+3; j++ {
		if strings.TrimSpace(lines[j]) != "" {
			return j
		}
	}
	return -1
}

func isNSHeader(lk string) bool {
	return strings.Contains(lk, "server") && !strings.Contains(lk, "whois")
}

func normKey(k string) string {
	k = strings.TrimRight(strings.ToLower(strings.TrimSpace(k)), ".")
	k = strings.TrimLeft(k, "* ") // .tr decorates keys as "** Key"
	return strings.Join(strings.Fields(k), " ")
}

var noiseSubstrings = []string{
	"terms of use", "url of the icann", "for more information on whois",
	"whois lookup made at", "this whois information is provided",
	"the data in this whois", "access to .", "all rights reserved",
	"this service is intended", "by submitting this query",
}

func isNoise(l string) bool {
	switch l[0] {
	case '%', '#', '>', ';', '-':
		return true
	}
	ll := strings.ToLower(l)
	for _, p := range noiseSubstrings {
		if strings.Contains(ll, p) {
			return true
		}
	}
	return false
}

// --- field lookup ---

type fieldGetter struct{ pairs []kvPair }

func (f *fieldGetter) get(aliases []string) string {
	for _, a := range aliases {
		for _, kv := range f.pairs {
			if kv.key == a && kv.value != "" {
				return kv.value
			}
		}
	}
	return ""
}

func (f *fieldGetter) getAll(aliases []string) []string {
	var out []string
	for _, kv := range f.pairs {
		for _, a := range aliases {
			if kv.key == a && kv.value != "" {
				out = append(out, kv.value)
				break
			}
		}
	}
	return out
}

func (f *fieldGetter) getDate(aliases []string) *time.Time {
	return parseDate(f.get(aliases))
}

func (f *fieldGetter) statuses(aliases []string) []string {
	var out []string
	for _, v := range f.getAll(aliases) {
		if i := strings.Index(v, " http"); i >= 0 {
			v = v[:i]
		}
		for _, part := range strings.Split(v, ",") {
			s := strings.TrimSpace(part)
			if s == "" || s == "-" {
				continue
			}
			if !containsFold(out, s) {
				out = append(out, s)
			}
		}
	}
	return out
}

func (f *fieldGetter) nameservers(aliases []string) []string {
	var out []string
	for _, v := range f.getAll(aliases) {
		fields := strings.Fields(v)
		if len(fields) == 0 {
			continue
		}
		ns := strings.TrimSuffix(strings.ToLower(fields[0]), ".")
		if ns == "" || !strings.Contains(ns, ".") {
			continue
		}
		if !containsFold(out, ns) {
			out = append(out, ns)
		}
	}
	return out
}

func isASCII(s string) bool {
	for _, r := range s {
		if r > 127 {
			return false
		}
	}
	return true
}

func containsFold(s []string, v string) bool {
	for _, e := range s {
		if strings.EqualFold(e, v) {
			return true
		}
	}
	return false
}

// --- per-TLD rules ---

var jpStateRe = regexp.MustCompile(`\((\d{4}/\d{2}/\d{2})\)`)

func applyTLDRules(tld, raw string, pairs []kvPair, p *ParsedInfo) {
	switch tld {
	case "jp":
		// .co.jp style: [State] Connected (2027/03/31) implies the expiry.
		if p.Expiry == nil {
			for _, kv := range pairs {
				if kv.key == "state" {
					if m := jpStateRe.FindStringSubmatch(kv.value); m != nil {
						p.Expiry = parseDate(m[1])
					}
				}
			}
		}
		if p.Registrant.Organization == "" {
			for _, kv := range pairs {
				if kv.key == "organization" && kv.value != "" {
					p.Registrant.Organization = kv.value
					break
				}
			}
		}
	case "tr":
		// TRABIS: the registrar name lives in "Organization Name" inside
		// the "** Registrar:" block.
		if v := (&fieldGetter{pairs: pairs}).get([]string{"organization name"}); v != "" {
			p.Registrar = v
		}
	case "eu", "it":
		// Block format: "Registrar:" followed by indented "Name:"/"Organization:".
		if p.Registrar == "" {
			p.Registrar = blockField(raw, "registrar", []string{"name", "organization"})
		}
		if tld == "it" {
			if p.Registrant.Organization == "" {
				p.Registrant.Organization = blockField(raw, "registrant", []string{"organization"})
			}
			if p.Admin.Name == "" {
				p.Admin.Name = blockField(raw, "admin contact", []string{"name"})
			}
			if p.Tech.Name == "" {
				p.Tech.Name = blockField(raw, "technical contacts", []string{"name"})
			}
		}
	}
}

// blockField finds a "Header:" (or bare "Header") line and returns the value
// of the first matching sub-key line below it.
func blockField(raw, header string, subKeys []string) string {
	lines := strings.Split(raw, "\n")
	for i, l := range lines {
		t := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(strings.TrimRight(l, "\r"))), ":")
		if t != header {
			continue
		}
		for j := i + 1; j < len(lines) && j < i+8; j++ {
			nl := strings.TrimSpace(strings.TrimRight(lines[j], "\r"))
			if nl == "" {
				break
			}
			idx := strings.Index(nl, ":")
			if idx < 0 {
				continue
			}
			k := strings.ToLower(strings.TrimSpace(nl[:idx]))
			for _, sk := range subKeys {
				if k == sk {
					return strings.TrimSpace(nl[idx+1:])
				}
			}
		}
	}
	return ""
}

// --- date parsing ---

var dateLayouts = []string{
	time.RFC3339,
	"2006-01-02T15:04:05Z0700",
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05Z07:00",
	"2006-01-02 15:04:05 -0700",
	"2006-01-02 15:04:05 MST",
	"2006-01-02 15:04:05",
	"2006-01-02 15:04",
	"2006-01-02",
	"2006/01/02 15:04:05",
	"2006/01/02",
	"2006. 01. 02. 15:04:05", // kr
	"2006. 01. 02",
	"2006.01.02 15:04:05",
	"2006.01.02",
	"02-Jan-2006 15:04:05 MST",
	"02-Jan-2006 15:04:05",
	"02-Jan-2006",
	"2006-Jan-02", // tr
	"02 January 2006",
	"02-01-2006", // dd-mm-yyyy (hk)
	"20060102",   // br
	"Jan 02, 2006",
	"January 2, 2006",
}

func parseDate(v string) *time.Time {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	if i := strings.Index(v, " #"); i >= 0 { // br: "19951218 #123456"
		v = v[:i]
	}
	if i := strings.Index(v, " ("); i >= 0 { // jp: "2026/04/01 01:05:09 (JST)"
		v = v[:i]
	}
	v = strings.TrimSpace(strings.TrimRight(v, "."))
	if v == "" {
		return nil
	}
	for _, layout := range dateLayouts {
		if t, err := time.Parse(layout, v); err == nil {
			t = t.UTC()
			return &t
		}
	}
	return nil
}

// --- availability detection ---

var notFoundPatterns = []string{
	"no match", "not found", "no entries found", "no data found",
	"no records found", "no matching record", "not been registered",
	"not registered", "domain not found", "no such domain", "no object found",
	"object does not exist", "does not exist in the registry", "status: free",
	"status: available", "available for registration", "no information available",
	"nothing found", "domain_status: free", "queried object does not exist",
	"the domain has not been registered", "status: inactive",
	"no information was found", // .za
}

func determineRegistered(raw string, pairs []kvPair, p *ParsedInfo) bool {
	// Not-found patterns win over an echoed "Domain:" line: DENIC and
	// EURid include the queried name even for available domains.
	norm := strings.Join(strings.Fields(strings.ToLower(raw)), " ")
	for _, pat := range notFoundPatterns {
		if strings.Contains(norm, pat) {
			return false
		}
	}
	if p.DomainName != "" {
		return true
	}
	return len(pairs) >= 2
}
