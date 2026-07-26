package whois

import (
	"bufio"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
)

// startFakeWhois runs a fake port-43 server on 127.0.0.1 and returns its
// address (host:port) plus a hit counter.
func startFakeWhois(t *testing.T, respond func(query string) string) (string, *int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var hits int32
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				atomic.AddInt32(&hits, 1)
				q, _ := bufio.NewReader(c).ReadString('\n')
				io.WriteString(c, respond(strings.TrimSpace(q)))
			}(conn)
		}
	}()
	return ln.Addr().String(), &hits
}

func TestWhoisQueryBasic(t *testing.T) {
	addr, hits := startFakeWhois(t, func(q string) string {
		if q != "google.zz" {
			t.Errorf("query = %q, want google.zz", q)
		}
		return "Domain: google.zz\nStatus: connect\n"
	})
	c := New(WithPreferRDAP(false), WithWhoisServer("zz", addr))
	rec, err := c.Query("google.zz")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Source != SourceWhois {
		t.Errorf("Source = %q", rec.Source)
	}
	if rec.Server != addr {
		t.Errorf("Server = %q, want %q", rec.Server, addr)
	}
	if !rec.Registered {
		t.Error("Registered = false")
	}
	if *hits != 1 {
		t.Errorf("hits = %d, want 1", *hits)
	}
}

func TestWhoisAvailable(t *testing.T) {
	addr, _ := startFakeWhois(t, func(q string) string {
		return "No match for domain \"FREE.ZZ\".\n"
	})
	c := New(WithPreferRDAP(false), WithWhoisServer("zz", addr))
	rec, err := c.Query("free.zz")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Registered {
		t.Error("Registered = true, want false")
	}
}

// TestIANADiscoveryAndCache: unknown TLDs are resolved through the IANA
// bootstrap server, and the result is cached.
func TestIANADiscoveryAndCache(t *testing.T) {
	registry, regHits := startFakeWhois(t, func(q string) string {
		return "Domain: example.zzz\nStatus: connect\n"
	})
	iana, ianaHits := startFakeWhois(t, func(q string) string {
		if q != "zzz" {
			t.Errorf("iana query = %q, want zzz", q)
		}
		return "% IANA WHOIS server\n\ndomain:       ZZZ\n\nwhois:        " + registry + "\n\nstatus:       ACTIVE\n"
	})
	c := New(WithPreferRDAP(false), WithIANAServer(iana))

	for i := 0; i < 2; i++ {
		rec, err := c.Query("example.zzz")
		if err != nil {
			t.Fatal(err)
		}
		if !rec.Registered {
			t.Error("Registered = false")
		}
		if rec.Server != registry {
			t.Errorf("Server = %q, want %q", rec.Server, registry)
		}
	}
	if *ianaHits != 1 {
		t.Errorf("iana hits = %d, want 1 (cached)", *ianaHits)
	}
	if *regHits != 2 {
		t.Errorf("registry hits = %d, want 2", *regHits)
	}
}

func TestNoWhoisServer(t *testing.T) {
	iana, _ := startFakeWhois(t, func(q string) string {
		return "% IANA WHOIS server\n\ndomain:       QQQ\n\nstatus:       ACTIVE\n"
	})
	c := New(WithPreferRDAP(false), WithIANAServer(iana))
	_, err := c.Query("example.qqq")
	if !errors.Is(err, ErrNoWhoisServer) {
		t.Fatalf("err = %v, want ErrNoWhoisServer", err)
	}
}

const thinResponse = `   Domain Name: EXAMPLE.COM
   Registry Domain ID: 2138514_DOMAIN_COM-VRSN
   Registrar WHOIS Server: %s
   Registrar: Registry Placeholder Ltd
   Creation Date: 1997-09-15T04:00:00Z
>>> Last update of whois database: 2026-07-26T00:00:00Z <<<
`

const thickResponse = `Domain Name: EXAMPLE.COM
Registry Domain ID: 2138514_DOMAIN_COM-VRSN
Registrar: MarkMonitor Inc.
Registrar IANA ID: 292
Creation Date: 1997-09-15T04:00:00Z
Registry Expiry Date: 2028-09-14T04:00:00Z
Name Server: NS1.GOOGLE.COM
Name Server: NS2.GOOGLE.COM
`

// TestReferralFollowing: thin-registry responses are enriched by querying
// the registrar's WHOIS server when referral following is enabled.
func TestReferralFollowing(t *testing.T) {
	registrar, _ := startFakeWhois(t, func(q string) string { return thickResponse })
	registry, _ := startFakeWhois(t, func(q string) string {
		return strings.Replace(thinResponse, "%s", registrar, 1)
	})
	c := New(WithPreferRDAP(false), WithWhoisServer("com", registry), WithReferralFollowing(true))
	rec, err := c.Query("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Parsed.Registrar != "MarkMonitor Inc." {
		t.Errorf("Registrar = %q", rec.Parsed.Registrar)
	}
	if rec.Parsed.Expiry == nil || rec.Parsed.Expiry.Format("2006-01-02") != "2028-09-14" {
		t.Errorf("Expiry = %v", rec.Parsed.Expiry)
	}
	if !strings.Contains(rec.Raw, "MarkMonitor Inc.") {
		t.Error("Raw should be the thick response")
	}
	if !strings.Contains(rec.RegistryRaw, "Registry Placeholder Ltd") {
		t.Error("RegistryRaw should keep the thin response")
	}
	if len(rec.Parsed.NameServers) != 2 {
		t.Errorf("NameServers = %v", rec.Parsed.NameServers)
	}
}

func TestReferralDisabled(t *testing.T) {
	registrar, refHits := startFakeWhois(t, func(q string) string { return thickResponse })
	registry, _ := startFakeWhois(t, func(q string) string {
		return strings.Replace(thinResponse, "%s", registrar, 1)
	})
	c := New(WithPreferRDAP(false), WithWhoisServer("com", registry))
	rec, err := c.Query("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Parsed.Registrar != "Registry Placeholder Ltd" {
		t.Errorf("Registrar = %q", rec.Parsed.Registrar)
	}
	if *refHits != 0 {
		t.Errorf("referral hit %d times, want 0", *refHits)
	}
}

func TestFormatQuery(t *testing.T) {
	cases := []struct{ server, domain, want string }{
		{"whois.verisign-grs.com", "example.com", "=example.com"},
		{"ccwhois.verisign-grs.com", "example.cc", "=example.cc"},
		{"whois.jprs.jp", "example.jp", "example.jp/e"},
		{"whois.denic.de", "example.de", "example.de"},
		{"whois.nic.uk", "example.uk", "example.uk"},
	}
	for _, c := range cases {
		if got := formatQuery(c.server, c.domain); got != c.want {
			t.Errorf("formatQuery(%q, %q) = %q, want %q", c.server, c.domain, got, c.want)
		}
	}
}

func TestParseIANAReferral(t *testing.T) {
	raw := "% IANA WHOIS server\n\ndomain:       IN\n\nwhois:        whois.nixiregistry.in\n\nstatus:       ACTIVE\n"
	if got := parseIANAReferral(raw); got != "whois.nixiregistry.in" {
		t.Errorf("parseIANAReferral = %q", got)
	}
	if got := parseIANAReferral("domain: XX\nstatus: ACTIVE\n"); got != "" {
		t.Errorf("parseIANAReferral empty = %q", got)
	}
}
