package whois

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// TestParseRDAPReal parses the live response captured from
// https://rdap.org/domain/google.com (rdap.verisign.com).
func TestParseRDAPReal(t *testing.T) {
	body, err := os.ReadFile("testdata/rdap_google_com.json")
	if err != nil {
		t.Fatal(err)
	}
	p, err := parseRDAP(body)
	if err != nil {
		t.Fatal(err)
	}
	if p.DomainName != "GOOGLE.COM" {
		t.Errorf("DomainName = %q", p.DomainName)
	}
	if p.Handle != "2138514_DOMAIN_COM-VRSN" {
		t.Errorf("Handle = %q", p.Handle)
	}
	if p.Registrar != "MarkMonitor Inc." {
		t.Errorf("Registrar = %q", p.Registrar)
	}
	if p.RegistrarID != "292" {
		t.Errorf("RegistrarID = %q", p.RegistrarID)
	}
	assertDate(t, "Created", p.Created, "1997-09-15")
	assertDate(t, "Updated", p.Updated, "2019-09-09")
	assertDate(t, "Expiry", p.Expiry, "2028-09-14")
	if len(p.NameServers) != 4 || p.NameServers[0] != "ns1.google.com" {
		t.Errorf("NameServers = %v", p.NameServers)
	}
	if !containsFold(p.Statuses, "client transfer prohibited") {
		t.Errorf("Statuses = %v", p.Statuses)
	}
	if p.DNSSec != "unsigned" {
		t.Errorf("DNSSec = %q", p.DNSSec)
	}
}

func assertDate(t *testing.T, field string, got *time.Time, want string) {
	t.Helper()
	if got == nil {
		t.Errorf("%s = nil, want %s", field, want)
		return
	}
	if got.Format("2006-01-02") != want {
		t.Errorf("%s = %s, want %s", field, got.Format("2006-01-02"), want)
	}
}

func TestVcardContact(t *testing.T) {
	vca := []interface{}{
		"vcard",
		[]interface{}{
			[]interface{}{"version", map[string]interface{}{}, "text", "4.0"},
			[]interface{}{"fn", map[string]interface{}{}, "text", "Example Inc."},
			[]interface{}{"org", map[string]interface{}{}, "text", []interface{}{"Example", "Group"}},
			[]interface{}{"email", map[string]interface{}{}, "text", "admin@example.com"},
			[]interface{}{"tel", map[string]interface{}{"type": "voice"}, "uri", "tel:+1.5551234567"},
		},
	}
	c := vcardContact(vca)
	if c.Name != "Example Inc." {
		t.Errorf("Name = %q", c.Name)
	}
	if c.Organization != "Example Group" {
		t.Errorf("Organization = %q", c.Organization)
	}
	if c.Email != "admin@example.com" {
		t.Errorf("Email = %q", c.Email)
	}
	if c.Phone != "+1.5551234567" {
		t.Errorf("Phone = %q", c.Phone)
	}
}

const testRDAPBody = `{
  "objectClassName": "domain",
  "handle": "D123-TEST",
  "ldhName": "EXAMPLE.TEST",
  "status": ["active"],
  "events": [
    {"eventAction": "registration", "eventDate": "2020-01-02T03:04:05Z"},
    {"eventAction": "expiration", "eventDate": "2030-01-02T03:04:05Z"}
  ],
  "nameservers": [{"objectClassName": "nameserver", "ldhName": "NS1.EXAMPLE.TEST"}]
}`

// TestRDAPQueryRedirect simulates the rdap.org bootstrap behavior: a 302 to
// the authoritative server, which then answers 200.
func TestRDAPQueryRedirect(t *testing.T) {
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/domain/example.test", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL+"/rdap/domain/example.test", http.StatusFound)
	})
	mux.HandleFunc("/rdap/domain/example.test", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.Write([]byte(testRDAPBody))
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()

	c := New()
	c.rdapBase = srv.URL
	c.rdapBootstrap = true
	rec, err := c.rdapQuery(context.Background(), "example.test")
	if err != nil {
		t.Fatal(err)
	}
	if !rec.Registered {
		t.Error("Registered = false")
	}
	if rec.Source != SourceRDAP {
		t.Errorf("Source = %q", rec.Source)
	}
	if !strings.Contains(rec.Server, "127.0.0.1") {
		t.Errorf("Server = %q", rec.Server)
	}
	assertDate(t, "Created", rec.Parsed.Created, "2020-01-02")
	assertDate(t, "Expiry", rec.Parsed.Expiry, "2030-01-02")
}

// TestRDAPQueryNoRDAP: the bootstrap answers 404 directly => the TLD has no
// RDAP deployment and the caller should fall back to WHOIS.
func TestRDAPQueryNoRDAP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := New()
	c.rdapBase = srv.URL
	c.rdapBootstrap = true
	_, err := c.rdapQuery(context.Background(), "example.test")
	if !errors.Is(err, ErrNoRDAP) {
		t.Fatalf("err = %v, want ErrNoRDAP", err)
	}
}

// TestRDAPQueryNotFound: bootstrap redirected, but the authoritative server
// answers 404 => the domain is not registered.
func TestRDAPQueryNotFound(t *testing.T) {
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/domain/free.test", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL+"/rdap/domain/free.test", http.StatusFound)
	})
	mux.HandleFunc("/rdap/domain/free.test", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"errorCode":404,"title":"Not Found"}`))
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()

	c := New()
	c.rdapBase = srv.URL
	c.rdapBootstrap = true
	rec, err := c.rdapQuery(context.Background(), "free.test")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Registered {
		t.Error("Registered = true, want false")
	}
}

// TestQueryFallbackEndToEnd: RDAP says "no RDAP for this TLD", so the query
// falls back to the WHOIS protocol transparently.
func TestQueryFallbackEndToEnd(t *testing.T) {
	rdapSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer rdapSrv.Close()

	whoisAddr, _ := startFakeWhois(t, func(q string) string {
		if q != "example.zz" {
			t.Errorf("whois query = %q", q)
		}
		return "Domain: example.zz\nStatus: connect\n"
	})

	c := New(WithWhoisServer("zz", whoisAddr))
	c.rdapBase = rdapSrv.URL
	c.rdapBootstrap = true
	rec, err := c.Query("example.zz")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Source != SourceWhois {
		t.Errorf("Source = %q, want whois", rec.Source)
	}
	if !rec.Registered {
		t.Error("Registered = false")
	}
	if !containsFold(rec.Parsed.Statuses, "connect") {
		t.Errorf("Statuses = %v", rec.Parsed.Statuses)
	}
}

// TestQueryRDAPPreferred: when RDAP works, WHOIS is never touched.
func TestQueryRDAPPreferred(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.Write([]byte(testRDAPBody))
	}))
	defer srv.Close()

	whoisAddr, hits := startFakeWhois(t, func(q string) string { return "" })
	c := New(WithWhoisServer("test", whoisAddr))
	c.rdapBase = srv.URL
	c.rdapBootstrap = false // treat as authoritative server: 200 directly

	rec, err := c.Query("example.test")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Source != SourceRDAP {
		t.Errorf("Source = %q", rec.Source)
	}
	if *hits != 0 {
		t.Errorf("whois server hit %d times, want 0", *hits)
	}
}
