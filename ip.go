package whois

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// IPRecord is the result of a QueryIP lookup.
type IPRecord struct {
	// Query is the queried IP address in canonical form.
	Query string
	// Source tells whether RDAP or the raw WHOIS protocol answered.
	Source Source
	// Server is the RIR server that produced the final answer.
	Server string
	// Found is false when the RIR reports no registration for the address.
	Found bool
	// Raw is the raw response body (JSON for RDAP, plain text for WHOIS).
	Raw string
	// Parsed is a best-effort structured view of Raw.
	Parsed *IPInfo
}

// IPInfo is a normalized view of an IP network registration (RDAP "ip
// network" object or an RIR WHOIS response).
type IPInfo struct {
	Handle       string
	Name         string
	Type         string // e.g. "DIRECT ALLOCATION", "ASSIGNED PA"
	StartAddress string
	EndAddress   string
	CIDR         string
	Version      string // "v4" or "v6" (RDAP only)
	Country      string
	ParentHandle string
	Statuses     []string
	Created      *time.Time
	Updated      *time.Time
	Organization string
	Description  string
	Entities     []EntityContact
}

// EntityContact associates registry roles with contact data.
type EntityContact struct {
	Handle  string
	Roles   []string
	Contact Contact
}

// ASNRecord is the result of a QueryASN lookup.
type ASNRecord struct {
	Query  uint32
	Source Source
	Server string
	Found  bool
	Raw    string
	Parsed *ASNInfo
}

// ASNInfo is a normalized view of an autnum registration.
type ASNInfo struct {
	Handle      string
	Name        string
	Type        string
	Country     string
	StartAutnum uint32
	EndAutnum   uint32
	Statuses    []string
	Created     *time.Time
	Updated     *time.Time
	Entities    []EntityContact
}

// QueryIP looks up the registration of an IPv4 or IPv6 address: RDAP first
// (rdap.org redirects to the responsible RIR), falling back to the classic
// WHOIS protocol via the whois.iana.org referral.
func (c *Client) QueryIP(ip string) (*IPRecord, error) {
	return c.QueryIPContext(context.Background(), ip)
}

// QueryIPContext is QueryIP with a context.
func (c *Client) QueryIPContext(ctx context.Context, ip string) (*IPRecord, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return nil, fmt.Errorf("whois: invalid IP address %q", ip)
	}
	norm := addr.String()
	if c.preferRDAP {
		rec, err := c.rdapQueryIP(ctx, norm)
		if err == nil {
			return rec, nil
		}
		if !c.fallbackWhois {
			return nil, err
		}
	}
	return c.whoisQueryIP(ctx, norm)
}

func (c *Client) rdapQueryIP(ctx context.Context, ip string) (*IPRecord, error) {
	body, server, status, err := c.rdapGet(ctx, "/ip/"+ip)
	if err != nil {
		return nil, err
	}
	switch status {
	case http.StatusOK:
		info, err := parseRDAPIP(body)
		if err != nil {
			return nil, err
		}
		return &IPRecord{Query: ip, Source: SourceRDAP, Server: server, Found: true, Raw: string(body), Parsed: info}, nil
	case http.StatusNotFound:
		return &IPRecord{Query: ip, Source: SourceRDAP, Server: server, Found: false, Raw: string(body), Parsed: &IPInfo{}}, nil
	default:
		return nil, fmt.Errorf("whois: rdap: unexpected status %d", status)
	}
}

// whoisQueryIP resolves the responsible RIR through a whois.iana.org
// referral and queries it with the WHOIS protocol.
func (c *Client) whoisQueryIP(ctx context.Context, ip string) (*IPRecord, error) {
	server, err := c.resolveRIR(ctx, ip)
	if err != nil {
		return nil, err
	}
	raw, err := c.queryServer(ctx, server, ip)
	if err != nil {
		return nil, fmt.Errorf("whois: %s: %w", server, err)
	}
	if strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("whois: %s: empty response", server)
	}
	info, found := ParseIPWhois(raw)
	return &IPRecord{Query: ip, Source: SourceWhois, Server: server, Found: found, Raw: raw, Parsed: info}, nil
}

// resolveRIR asks whois.iana.org which RIR serves an IP (cached per address).
func (c *Client) resolveRIR(ctx context.Context, ip string) (string, error) {
	key := "rir:" + ip
	if v, ok := c.serverCache.Load(key); ok {
		return v.(string), nil
	}
	raw, err := c.queryServer(ctx, c.ianaServer, ip)
	if err != nil {
		return "", fmt.Errorf("whois: iana lookup for %s: %w", ip, err)
	}
	server := parseIANAReferral(raw)
	if server == "" {
		return "", fmt.Errorf("%w: %s", ErrNoWhoisServer, ip)
	}
	c.serverCache.Store(key, server)
	return server, nil
}

// --- RDAP ip network / autnum objects (RFC 9083) ---

type rdapIPNetwork struct {
	Handle       string `json:"handle"`
	StartAddress string `json:"startAddress"`
	EndAddress   string `json:"endAddress"`
	IPVersion    string `json:"ipVersion"`
	Name         string `json:"name"`
	Type         string `json:"type"`
	Country      string `json:"country"`
	ParentHandle string `json:"parentHandle"`
	Status       []string
	Events       []rdapEvent  `json:"events"`
	Entities     []rdapEntity `json:"entities"`
	CIDRs        []struct {
		V4Prefix string `json:"v4prefix"`
		V6Prefix string `json:"v6prefix"`
		Length   int    `json:"length"`
	} `json:"cidr0_cidrs"`
}

func parseRDAPIP(body []byte) (*IPInfo, error) {
	var d rdapIPNetwork
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, fmt.Errorf("whois: rdap: invalid JSON: %w", err)
	}
	info := &IPInfo{
		Handle:       d.Handle,
		Name:         d.Name,
		Type:         d.Type,
		StartAddress: d.StartAddress,
		EndAddress:   d.EndAddress,
		Version:      d.IPVersion,
		Country:      d.Country,
		ParentHandle: d.ParentHandle,
		Statuses:     d.Status,
		Entities:     rdapEntityContacts(d.Entities),
	}
	for _, c := range d.CIDRs {
		prefix := c.V4Prefix
		if prefix == "" {
			prefix = c.V6Prefix
		}
		if prefix != "" {
			info.CIDR = fmt.Sprintf("%s/%d", prefix, c.Length)
			break
		}
	}
	rdapDates(d.Events, &info.Created, &info.Updated, nil)
	return info, nil
}

type rdapAutnum struct {
	Handle      string `json:"handle"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Country     string `json:"country"`
	StartAutnum uint32 `json:"startAutnum"`
	EndAutnum   uint32 `json:"endAutnum"`
	Status      []string
	Events      []rdapEvent  `json:"events"`
	Entities    []rdapEntity `json:"entities"`
}

// QueryASN looks up an autonomous system number. RDAP covers every
// allocated ASN via the IANA bootstrap, so no WHOIS fallback is needed.
func (c *Client) QueryASN(asn uint32) (*ASNRecord, error) {
	return c.QueryASNContext(context.Background(), asn)
}

// QueryASNContext is QueryASN with a context.
func (c *Client) QueryASNContext(ctx context.Context, asn uint32) (*ASNRecord, error) {
	body, server, status, err := c.rdapGet(ctx, fmt.Sprintf("/autnum/%d", asn))
	if err != nil {
		return nil, err
	}
	switch status {
	case http.StatusOK:
		var d rdapAutnum
		if err := json.Unmarshal(body, &d); err != nil {
			return nil, fmt.Errorf("whois: rdap: invalid JSON: %w", err)
		}
		info := &ASNInfo{
			Handle:      d.Handle,
			Name:        d.Name,
			Type:        d.Type,
			Country:     d.Country,
			StartAutnum: d.StartAutnum,
			EndAutnum:   d.EndAutnum,
			Statuses:    d.Status,
			Entities:    rdapEntityContacts(d.Entities),
		}
		rdapDates(d.Events, &info.Created, &info.Updated, nil)
		return &ASNRecord{Query: asn, Source: SourceRDAP, Server: server, Found: true, Raw: string(body), Parsed: info}, nil
	case http.StatusNotFound:
		return &ASNRecord{Query: asn, Source: SourceRDAP, Server: server, Found: false, Raw: string(body), Parsed: &ASNInfo{}}, nil
	default:
		return nil, fmt.Errorf("whois: rdap: unexpected status %d", status)
	}
}

// --- RIR WHOIS parsing (ARIN / RIPE / APNIC / LACNIC / AFRINIC) ---

var (
	ipRangeKeys   = []string{"inetnum", "netrange"}
	ipCIDRKeys    = []string{"cidr"}
	ipNameKeys    = []string{"netname"}
	ipTypeKeys    = []string{"nettype", "status"}
	ipHandleKeys  = []string{"nethandle"}
	ipParentKeys  = []string{"parent"}
	ipOrgKeys     = []string{"orgname", "org-name", "organization", "owner"}
	ipDescrKeys   = []string{"descr"}
	ipCreatedKeys = []string{"regdate", "created"}
	ipUpdatedKeys = []string{"updated", "last-modified", "changed"}
)

// ParseIPWhois converts a raw RIR WHOIS response into an IPInfo and reports
// whether the address block is registered.
func ParseIPWhois(raw string) (*IPInfo, bool) {
	pairs := extractPairs(raw)
	f := &fieldGetter{pairs: pairs}
	info := &IPInfo{Entities: []EntityContact{}}

	rng := f.get(ipRangeKeys)
	if strings.Contains(rng, "/") {
		info.CIDR = strings.Fields(rng)[0]
	} else if parts := strings.SplitN(rng, "-", 2); len(parts) == 2 {
		info.StartAddress = strings.TrimSpace(parts[0])
		info.EndAddress = strings.TrimSpace(parts[1])
	}
	if v := f.get(ipCIDRKeys); v != "" {
		info.CIDR = strings.Fields(v)[0]
	}
	info.Handle = f.get(ipHandleKeys)
	info.Name = f.get(ipNameKeys)
	info.Type = f.get(ipTypeKeys)
	info.Country = f.get([]string{"country"})
	info.ParentHandle = f.get(ipParentKeys)
	info.Organization = f.get(ipOrgKeys)
	info.Description = f.get(ipDescrKeys)
	info.Created = f.getDate(ipCreatedKeys)
	info.Updated = f.getDate(ipUpdatedKeys)

	// Availability: not-found patterns first, then presence of a range.
	found := false
	norm := strings.Join(strings.Fields(strings.ToLower(raw)), " ")
	for _, pat := range notFoundPatterns {
		if strings.Contains(norm, pat) {
			return info, false
		}
	}
	if info.StartAddress != "" || info.CIDR != "" {
		found = true
	} else {
		found = len(pairs) >= 2
	}
	return info, found
}
