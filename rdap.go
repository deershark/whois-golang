package whois

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// rdapQuery asks the configured RDAP endpoint for domain. With the default
// rdap.org bootstrap the first response is a redirect to the authoritative
// server; a direct 404 means the TLD has no RDAP deployment (ErrNoRDAP).
func (c *Client) rdapQuery(ctx context.Context, domain string) (*Record, error) {
	// Never follow redirects silently: the first hop tells us whether the
	// TLD is RDAP-enabled at all.
	hc := &http.Client{
		Transport: c.httpClient.Transport,
		Timeout:   c.httpClient.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	u := c.rdapBase + "/domain/" + domain
	redirected := false
	var resp *http.Response
	for i := 0; i < 5; i++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/rdap+json, application/json")
		r, err := hc.Do(req)
		if err != nil {
			return nil, err
		}
		if r.StatusCode >= 300 && r.StatusCode < 400 {
			loc := r.Header.Get("Location")
			r.Body.Close()
			if loc == "" {
				return nil, fmt.Errorf("whois: rdap: %d without Location", r.StatusCode)
			}
			nu, err := url.Parse(loc)
			if err != nil {
				return nil, err
			}
			base, _ := url.Parse(u)
			u = base.ResolveReference(nu).String()
			redirected = true
			continue
		}
		resp = r
		break
	}
	if resp == nil {
		return nil, fmt.Errorf("whois: rdap: too many redirects")
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	server := resp.Request.URL.Host

	switch resp.StatusCode {
	case http.StatusOK:
		p, err := parseRDAP(body)
		if err != nil {
			return nil, err
		}
		return &Record{
			Domain:     domain,
			Source:     SourceRDAP,
			Server:     server,
			Registered: true,
			Raw:        string(body),
			Parsed:     p,
		}, nil
	case http.StatusNotFound:
		if c.rdapBootstrap && !redirected {
			return nil, ErrNoRDAP
		}
		return &Record{
			Domain:     domain,
			Source:     SourceRDAP,
			Server:     server,
			Registered: false,
			Raw:        string(body),
			Parsed:     &ParsedInfo{DomainName: domain},
		}, nil
	default:
		return nil, fmt.Errorf("whois: rdap: unexpected status %s", resp.Status)
	}
}

// --- Minimal RFC 9083 domain object model ---

type rdapDomain struct {
	ObjectClassName string `json:"objectClassName"`
	Handle          string `json:"handle"`
	LDHName         string `json:"ldhName"`
	UnicodeName     string `json:"unicodeName"`
	Status          []string
	Events          []rdapEvent  `json:"events"`
	Entities        []rdapEntity `json:"entities"`
	Nameservers     []rdapNS     `json:"nameservers"`
	SecureDNS       *rdapDNSSEC  `json:"secureDNS"`
	Port43          string       `json:"port43"`
	ErrorCode       int          `json:"errorCode"`
	Title           string       `json:"title"`
	Description     []string     `json:"description"`
}

type rdapEvent struct {
	Action string `json:"eventAction"`
	Date   string `json:"eventDate"`
}

type rdapEntity struct {
	Handle     string        `json:"handle"`
	Roles      []string      `json:"roles"`
	VCardArray []interface{} `json:"vcardArray"`
	PublicIDs  []struct {
		Type       string `json:"type"`
		Identifier string `json:"identifier"`
	} `json:"publicIds"`
	Entities []rdapEntity `json:"entities"`
}

type rdapNS struct {
	LDHName     string `json:"ldhName"`
	UnicodeName string `json:"unicodeName"`
}

type rdapDNSSEC struct {
	DelegationSigned *bool `json:"delegationSigned"`
}

// parseRDAP converts an RDAP domain object into ParsedInfo.
func parseRDAP(body []byte) (*ParsedInfo, error) {
	var d rdapDomain
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, fmt.Errorf("whois: rdap: invalid JSON: %w", err)
	}
	p := &ParsedInfo{
		DomainName:  d.LDHName,
		Handle:      d.Handle,
		Statuses:    d.Status,
		WhoisServer: d.Port43,
		Extra:       map[string][]string{},
	}
	if p.DomainName == "" {
		p.DomainName = d.UnicodeName
	}

	for _, e := range d.Events {
		t, err := time.Parse(time.RFC3339, e.Date)
		if err != nil {
			continue
		}
		t = t.UTC()
		switch strings.ToLower(e.Action) {
		case "registration", "reregistration":
			if p.Created == nil {
				p.Created = &t
			}
		case "expiration":
			p.Expiry = &t
		case "last changed":
			p.Updated = &t
		case "last update of rdap database":
			if p.Updated == nil {
				p.Updated = &t
			}
		}
	}

	for _, ns := range d.Nameservers {
		name := strings.TrimSuffix(strings.ToLower(ns.LDHName), ".")
		if name != "" {
			p.NameServers = appendUnique(p.NameServers, name)
		}
	}

	if d.SecureDNS != nil && d.SecureDNS.DelegationSigned != nil {
		if *d.SecureDNS.DelegationSigned {
			p.DNSSec = "signedDelegation"
		} else {
			p.DNSSec = "unsigned"
		}
	}

	var walk func(ents []rdapEntity)
	walk = func(ents []rdapEntity) {
		for _, e := range ents {
			ct := vcardContact(e.VCardArray)
			for _, role := range e.Roles {
				switch strings.ToLower(role) {
				case "registrar":
					if ct.Name != "" {
						p.Registrar = ct.Name
					} else {
						p.Registrar = ct.Organization
					}
					if p.Registrar == "" {
						p.Registrar = e.Handle
					}
					for _, id := range e.PublicIDs {
						if strings.Contains(strings.ToLower(id.Type), "iana") {
							p.RegistrarID = id.Identifier
						}
					}
				case "registrant":
					p.Registrant = mergeContact(p.Registrant, ct)
				case "administrative":
					p.Admin = mergeContact(p.Admin, ct)
				case "technical":
					p.Tech = mergeContact(p.Tech, ct)
				case "billing":
					p.Billing = mergeContact(p.Billing, ct)
				}
			}
			walk(e.Entities)
		}
	}
	walk(d.Entities)
	return p, nil
}

// vcardContact extracts the interesting fields from a jCard (RFC 7095)
// vcardArray: ["vcard", [[name, params, type, value], ...]].
func vcardContact(vca []interface{}) Contact {
	var c Contact
	if len(vca) != 2 {
		return c
	}
	props, ok := vca[1].([]interface{})
	if !ok {
		return c
	}
	for _, pi := range props {
		prop, ok := pi.([]interface{})
		if !ok || len(prop) < 4 {
			continue
		}
		name, _ := prop[0].(string)
		value := vcardText(prop[3])
		switch strings.ToLower(name) {
		case "fn":
			c.Name = value
		case "org":
			c.Organization = value
		case "email":
			if c.Email == "" {
				c.Email = value
			}
		case "tel":
			if c.Phone == "" {
				c.Phone = strings.TrimPrefix(value, "tel:")
			}
		}
	}
	return c
}

func vcardText(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case []interface{}:
		parts := make([]string, 0, len(t))
		for _, e := range t {
			parts = append(parts, vcardText(e))
		}
		return strings.Join(parts, " ")
	}
	return ""
}

func mergeContact(dst, src Contact) Contact {
	if dst.Name == "" {
		dst.Name = src.Name
	}
	if dst.Organization == "" {
		dst.Organization = src.Organization
	}
	if dst.Email == "" {
		dst.Email = src.Email
	}
	if dst.Phone == "" {
		dst.Phone = src.Phone
	}
	return dst
}

func appendUnique(s []string, v string) []string {
	for _, e := range s {
		if e == v {
			return s
		}
	}
	return append(s, v)
}
