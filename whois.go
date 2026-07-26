package whois

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// whoisQuery performs the classic WHOIS protocol lookup for domain.
func (c *Client) whoisQuery(ctx context.Context, domain, tld string) (*Record, error) {
	server, err := c.resolveServer(ctx, tld)
	if err != nil {
		return nil, err
	}
	raw, err := c.queryServer(ctx, server, formatQuery(server, domain))
	if err != nil {
		return nil, fmt.Errorf("whois: %s: %w", server, err)
	}
	if strings.TrimSpace(raw) == "" {
		// An empty answer is a throttled/refused query, not an
		// availability signal — never report "not registered" for it.
		return nil, fmt.Errorf("whois: %s: empty response", server)
	}
	parsed, registered := Parse(tld, raw)
	rec := &Record{
		Domain:     domain,
		Source:     SourceWhois,
		Server:     server,
		Registered: registered,
		Raw:        raw,
		Parsed:     parsed,
	}

	// Thin registries (com/net/...) point at the registrar's own WHOIS.
	if registered && c.followReferral && parsed.WhoisServer != "" &&
		!strings.EqualFold(parsed.WhoisServer, server) {
		refServer := parsed.WhoisServer
		if strings.HasPrefix(refServer, "whois://") {
			refServer = strings.TrimPrefix(refServer, "whois://")
		}
		if raw2, err := c.queryServer(ctx, refServer, domain); err == nil {
			if parsed2, registered2 := Parse(tld, raw2); registered2 {
				mergeParsed(parsed2, parsed)
				rec.RegistryRaw = raw
				rec.Raw = raw2
				rec.Parsed = parsed2
			}
		}
	}
	return rec, nil
}

// resolveServer finds the port-43 server for a TLD: overrides first, then
// the embedded table, then a whois.iana.org referral lookup (cached).
func (c *Client) resolveServer(ctx context.Context, tld string) (string, error) {
	if s, ok := c.overrides[tld]; ok {
		return s, nil
	}
	if v, ok := c.serverCache.Load(tld); ok {
		return v.(string), nil
	}
	if s, ok := whoisServers[tld]; ok {
		c.serverCache.Store(tld, s)
		return s, nil
	}
	raw, err := c.queryServer(ctx, c.ianaServer, tld)
	if err != nil {
		return "", fmt.Errorf("whois: iana lookup for .%s: %w", tld, err)
	}
	s := parseIANAReferral(raw)
	if s == "" {
		return "", fmt.Errorf("%w: .%s", ErrNoWhoisServer, tld)
	}
	c.serverCache.Store(tld, s)
	return s, nil
}

// parseIANAReferral extracts the whois server from a whois.iana.org response.
func parseIANAReferral(raw string) string {
	s := bufio.NewScanner(strings.NewReader(raw))
	for s.Scan() {
		line := s.Text()
		i := strings.Index(line, ":")
		if i < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:i]))
		val := strings.TrimSpace(line[i+1:])
		if (key == "whois" || key == "refer") && val != "" {
			return strings.ToLower(val)
		}
	}
	return ""
}

// queryServer speaks the WHOIS protocol: connect to port 43, send the query
// terminated by CRLF, read everything until the server closes.
// server may include an explicit port (used by tests).
func (c *Client) queryServer(ctx context.Context, server, query string) (string, error) {
	addr := server
	if _, _, err := net.SplitHostPort(server); err != nil {
		addr = net.JoinHostPort(server, "43")
	}
	d := net.Dialer{Timeout: c.timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(c.timeout))
	if _, err := io.WriteString(conn, query+"\r\n"); err != nil {
		return "", err
	}
	b, err := io.ReadAll(io.LimitReader(conn, 2<<20))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// formatQuery applies registry-specific query syntax.
func formatQuery(server, domain string) string {
	// Verisign-like servers default to partial matches; "=" forces exact.
	switch strings.ToLower(server) {
	case "whois.verisign-grs.com", "ccwhois.verisign-grs.com", "tvwhois.verisign-grs.com":
		return "=" + domain
	case "whois.jprs.jp":
		return domain + "/e" // English output
	}
	return domain
}

// mergeParsed fills empty fields of dst with values from src.
func mergeParsed(dst, src *ParsedInfo) {
	if dst.DomainName == "" {
		dst.DomainName = src.DomainName
	}
	if dst.Handle == "" {
		dst.Handle = src.Handle
	}
	if dst.Registrar == "" {
		dst.Registrar = src.Registrar
	}
	if dst.RegistrarID == "" {
		dst.RegistrarID = src.RegistrarID
	}
	if dst.Created == nil {
		dst.Created = src.Created
	}
	if dst.Updated == nil {
		dst.Updated = src.Updated
	}
	if dst.Expiry == nil {
		dst.Expiry = src.Expiry
	}
	if len(dst.Statuses) == 0 {
		dst.Statuses = src.Statuses
	}
	if len(dst.NameServers) == 0 {
		dst.NameServers = src.NameServers
	}
	if dst.DNSSec == "" {
		dst.DNSSec = src.DNSSec
	}
	dst.Registrant = mergeContact(dst.Registrant, src.Registrant)
	dst.Admin = mergeContact(dst.Admin, src.Admin)
	dst.Tech = mergeContact(dst.Tech, src.Tech)
	dst.Billing = mergeContact(dst.Billing, src.Billing)
}
