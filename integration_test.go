package whois

import (
	"net"
	"os"
	"testing"
)

// Live tests against real registries. Run with: WHOIS_LIVE=1 go test -run Live
func live(t *testing.T) {
	t.Helper()
	if os.Getenv("WHOIS_LIVE") != "1" {
		t.Skip("set WHOIS_LIVE=1 to run live registry tests")
	}
}

func TestLiveRDAP(t *testing.T) {
	live(t)
	rec, err := New().Query("google.com")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Source != SourceRDAP {
		t.Errorf("Source = %q, want rdap", rec.Source)
	}
	if !rec.Registered {
		t.Error("Registered = false")
	}
	if rec.Parsed.Registrar == "" {
		t.Error("Registrar empty")
	}
	if len(rec.Parsed.NameServers) == 0 {
		t.Error("NameServers empty")
	}
	t.Logf("google.com via %s: registrar=%s expiry=%v", rec.Server, rec.Parsed.Registrar, rec.Parsed.Expiry)
}

func TestLiveWhoisFallback(t *testing.T) {
	live(t)
	// .de has no RDAP deployment (per deployment.rdap.org), so this must
	// fall back to the WHOIS protocol.
	rec, err := New().Query("google.de")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Source != SourceWhois {
		t.Errorf("Source = %q, want whois", rec.Source)
	}
	if !rec.Registered {
		t.Error("Registered = false")
	}
	t.Logf("google.de via %s: statuses=%v", rec.Server, rec.Parsed.Statuses)
}

func TestLiveAvailableDomain(t *testing.T) {
	live(t)
	rec, err := New().Query("this-domain-should-not-exist-9f8d7c6b5a.com")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Registered {
		t.Error("Registered = true, want false")
	}
}

func TestLiveIDN(t *testing.T) {
	live(t)
	rec, err := New().Query("münchen.de")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Domain != "xn--mnchen-3ya.de" {
		t.Errorf("Domain = %q, want xn--mnchen-3ya.de", rec.Domain)
	}
	if !rec.Registered {
		t.Error("Registered = false")
	}
}

// TestLiveEmbeddedServers DNS-resolves every server in the embedded map.
// It catches map entries rotting over time. Failures are reported but only
// fail the test above a threshold (some networks block port 43 lookups).
func TestLiveEmbeddedServers(t *testing.T) {
	live(t)
	type failure struct{ tld, server string }
	var failures []failure
	for tld, server := range whoisServers {
		if _, err := net.LookupHost(server); err != nil {
			failures = append(failures, failure{tld, server})
		}
	}
	for _, f := range failures {
		t.Logf("DNS FAIL: .%s -> %s", f.tld, f.server)
	}
	if len(failures) > len(whoisServers)/10 {
		t.Fatalf("%d/%d embedded whois servers do not resolve", len(failures), len(whoisServers))
	}
	t.Logf("%d/%d embedded whois servers resolve", len(whoisServers)-len(failures), len(whoisServers))
}

func TestLiveUKViaRDAP(t *testing.T) {
	live(t)
	// .uk deployed RDAP in 2022.
	rec, err := New().Query("nominet.uk")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Source != SourceRDAP {
		t.Errorf("Source = %q, want rdap", rec.Source)
	}
	if !rec.Registered {
		t.Error("Registered = false")
	}
}
