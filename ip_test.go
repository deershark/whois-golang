package whois

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestParseRDAPIP parses the live response captured from
// https://rdap.org/ip/8.8.8.8 (rdap.arin.net).
func TestParseRDAPIP(t *testing.T) {
	body := []byte(load(t, "rdap_ip_arin.json"))
	info, err := parseRDAPIP(body)
	if err != nil {
		t.Fatal(err)
	}
	if info.Handle != "NET-8-8-8-0-2" {
		t.Errorf("Handle = %q", info.Handle)
	}
	if info.Name != "GOGL" {
		t.Errorf("Name = %q", info.Name)
	}
	if info.StartAddress != "8.8.8.0" || info.EndAddress != "8.8.8.255" {
		t.Errorf("range = %q - %q", info.StartAddress, info.EndAddress)
	}
	if info.CIDR != "8.8.8.0/24" {
		t.Errorf("CIDR = %q", info.CIDR)
	}
	if info.Version != "v4" {
		t.Errorf("Version = %q", info.Version)
	}
	if info.Type != "DIRECT ALLOCATION" {
		t.Errorf("Type = %q", info.Type)
	}
	assertDate(t, "Created", info.Created, "2023-12-28")
	assertDate(t, "Updated", info.Updated, "2023-12-28")
	if len(info.Entities) == 0 || info.Entities[0].Contact.Name != "Google LLC" {
		t.Errorf("Entities = %+v", info.Entities)
	}
}

func TestParseRDAPAutnum(t *testing.T) {
	body := []byte(load(t, "rdap_autnum_15169.json"))
	c := New()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/autnum/15169" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/rdap+json")
		w.Write(body)
	}))
	defer srv.Close()
	c.rdapBase = srv.URL
	c.rdapBootstrap = false

	rec, err := c.QueryASN(15169)
	if err != nil {
		t.Fatal(err)
	}
	if !rec.Found {
		t.Fatal("Found = false")
	}
	if rec.Parsed.Handle != "AS15169" {
		t.Errorf("Handle = %q", rec.Parsed.Handle)
	}
	if rec.Parsed.Name != "GOOGLE" {
		t.Errorf("Name = %q", rec.Parsed.Name)
	}
	if rec.Parsed.StartAutnum != 15169 || rec.Parsed.EndAutnum != 15169 {
		t.Errorf("range = %d - %d", rec.Parsed.StartAutnum, rec.Parsed.EndAutnum)
	}
}

// TestParseIPWhois covers real ARIN / APNIC / RIPE responses.
func TestParseIPWhois(t *testing.T) {
	type expect struct {
		handle, name, typ, start, end, cidr, country, org, descr string
		created, updated                                         string
	}
	cases := map[string]expect{
		"whois_ip_arin.txt": {
			handle: "NET-8-8-8-0-2", name: "GOGL", typ: "Direct Allocation",
			start: "8.8.8.0", end: "8.8.8.255", cidr: "8.8.8.0/24",
			country: "US", org: "Google LLC",
			created: "2023-12-28", updated: "2023-12-28",
		},
		"whois_ip_apnic.txt": {
			name: "APNIC-LABS", typ: "ASSIGNED PORTABLE",
			start: "1.1.1.0", end: "1.1.1.255",
			country: "AU", org: "APNIC Research and Development",
			descr:   "Cloudflare",
			updated: "2023-04-26",
		},
		"whois_ip_ripe.txt": {
			name: "RIPE-NCC", typ: "ASSIGNED PA",
			start: "193.0.0.0", end: "193.0.7.255",
			country: "NL", org: "RIPE NCC",
			descr:   "RIPE Network Coordination Centre",
			created: "2003-03-17", updated: "2026-03-19",
		},
	}
	for file, exp := range cases {
		t.Run(file, func(t *testing.T) {
			info, found := ParseIPWhois(load(t, file))
			if !found {
				t.Fatal("found = false")
			}
			if exp.handle != "" && info.Handle != exp.handle {
				t.Errorf("Handle = %q, want %q", info.Handle, exp.handle)
			}
			if info.Name != exp.name {
				t.Errorf("Name = %q, want %q", info.Name, exp.name)
			}
			if info.Type != exp.typ {
				t.Errorf("Type = %q, want %q", info.Type, exp.typ)
			}
			if info.StartAddress != exp.start || info.EndAddress != exp.end {
				t.Errorf("range = %q - %q, want %q - %q", info.StartAddress, info.EndAddress, exp.start, exp.end)
			}
			if exp.cidr != "" && info.CIDR != exp.cidr {
				t.Errorf("CIDR = %q, want %q", info.CIDR, exp.cidr)
			}
			if info.Country != exp.country {
				t.Errorf("Country = %q, want %q", info.Country, exp.country)
			}
			if !strings.Contains(info.Organization, exp.org) {
				t.Errorf("Organization = %q, want substring %q", info.Organization, exp.org)
			}
			if exp.descr != "" && !strings.Contains(info.Description, exp.descr) {
				t.Errorf("Description = %q, want substring %q", info.Description, exp.descr)
			}
			checkDate(t, "Created", info.Created, exp.created)
			checkDate(t, "Updated", info.Updated, exp.updated)
		})
	}
}

// TestQueryIPWhoisPath: with RDAP disabled, QueryIP resolves the RIR through
// the IANA referral and parses the response.
func TestQueryIPWhoisPath(t *testing.T) {
	rirRaw := load(t, "whois_ip_arin.txt")
	rir, _ := startFakeWhois(t, func(q string) string {
		if q != "8.8.8.8" {
			t.Errorf("rir query = %q", q)
		}
		return rirRaw
	})
	iana, _ := startFakeWhois(t, func(q string) string {
		if q != "8.8.8.8" {
			t.Errorf("iana query = %q", q)
		}
		return "% IANA WHOIS server\n\nrefer:        " + rir + "\n\ninetnum:      8.0.0.0 - 8.255.255.255\n"
	})
	c := New(WithPreferRDAP(false), WithIANAServer(iana))
	rec, err := c.QueryIP("8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Source != SourceWhois {
		t.Errorf("Source = %q", rec.Source)
	}
	if rec.Server != rir {
		t.Errorf("Server = %q, want %q", rec.Server, rir)
	}
	if !rec.Found {
		t.Error("Found = false")
	}
	if rec.Parsed.Name != "GOGL" {
		t.Errorf("Name = %q", rec.Parsed.Name)
	}
	if rec.Parsed.Organization != "Google LLC" {
		t.Errorf("Organization = %q", rec.Parsed.Organization)
	}
}

// TestQueryIPRDAPPath: rdap.org-style redirect to the RIR.
func TestQueryIPRDAPPath(t *testing.T) {
	body := []byte(load(t, "rdap_ip_arin.json"))
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/ip/8.8.8.8", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL+"/rdap/ip/8.8.8.8", http.StatusFound)
	})
	mux.HandleFunc("/rdap/ip/8.8.8.8", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.Write(body)
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()

	c := New()
	c.rdapBase = srv.URL
	c.rdapBootstrap = true
	rec, err := c.QueryIP("8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Source != SourceRDAP || !rec.Found {
		t.Errorf("Source = %q Found = %v", rec.Source, rec.Found)
	}
	if rec.Parsed.Name != "GOGL" {
		t.Errorf("Name = %q", rec.Parsed.Name)
	}
}

// TestQueryIPNotFound: RIR answers 404 after the redirect.
func TestQueryIPNotFound(t *testing.T) {
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/ip/203.0.113.7", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL+"/rdap/ip/203.0.113.7", http.StatusFound)
	})
	mux.HandleFunc("/rdap/ip/203.0.113.7", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()

	c := New()
	c.rdapBase = srv.URL
	c.rdapBootstrap = true
	rec, err := c.QueryIP("203.0.113.7")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Found {
		t.Error("Found = true, want false")
	}
}

// TestQueryIPFallback: no RDAP entry → fall back to WHOIS via IANA referral.
func TestQueryIPFallback(t *testing.T) {
	rdapSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer rdapSrv.Close()

	rir, _ := startFakeWhois(t, func(q string) string { return load(t, "whois_ip_arin.txt") })
	iana, _ := startFakeWhois(t, func(q string) string { return "refer: " + rir + "\n" })

	c := New(WithIANAServer(iana))
	c.rdapBase = rdapSrv.URL
	c.rdapBootstrap = true
	rec, err := c.QueryIP("8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Source != SourceWhois || !rec.Found {
		t.Errorf("Source = %q Found = %v", rec.Source, rec.Found)
	}
	if rec.Parsed.Handle != "NET-8-8-8-0-2" {
		t.Errorf("Handle = %q", rec.Parsed.Handle)
	}
}

func TestQueryIPInvalid(t *testing.T) {
	for _, bad := range []string{"999.1.1.1", "not-an-ip", "", "example.com"} {
		if _, err := New().QueryIP(bad); err == nil {
			t.Errorf("QueryIP(%q): expected error", bad)
		}
	}
}

func TestQueryIPNoWhoisFallback(t *testing.T) {
	rdapSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer rdapSrv.Close()
	c := New(WithWhoisFallback(false))
	c.rdapBase = rdapSrv.URL
	c.rdapBootstrap = true
	_, err := c.rdapQueryIP(context.Background(), "8.8.8.8")
	if !errors.Is(err, ErrNoRDAP) {
		t.Fatalf("err = %v, want ErrNoRDAP", err)
	}
}
