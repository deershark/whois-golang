package whois

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// parseExpect describes the fields we assert against real registry
// responses stored in testdata (fetched live from the official servers).
type parseExpect struct {
	tld         string
	registered  bool
	domain      string
	registrar   string // substring, case-sensitive
	registrarID string
	whoisServer string
	created     string // "2006-01-02"; "" means expect nil
	updated     string
	expiry      string
	nsContains  []string
	nsCount     int // -1 = don't check
	statuses    []string
	dnssec      string
	regName     string // substring
	regOrg      string // substring
	regEmail    string
	adminName   string
	techName    string
}

func load(t *testing.T, file string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", file))
	if err != nil {
		t.Fatalf("read %s: %v", file, err)
	}
	return string(b)
}

func TestParseRealResponses(t *testing.T) {
	cases := map[string]parseExpect{
		// Verisign thin registry
		"whois_com.txt": {
			tld: "com", registered: true, domain: "GOOGLE.COM",
			registrar: "MarkMonitor Inc.", registrarID: "292",
			whoisServer: "whois.markmonitor.com",
			created:     "1997-09-15", updated: "2019-09-09", expiry: "2028-09-14",
			nsContains: []string{"ns1.google.com", "ns2.google.com", "ns3.google.com", "ns4.google.com"},
			nsCount:    4,
			statuses:   []string{"clientTransferProhibited", "serverUpdateProhibited"},
			dnssec:     "unsigned",
		},
		"whois_com_nomatch.txt": {tld: "com", registered: false},

		// PIR thick registry
		"whois_org.txt": {
			tld: "org", registered: true, domain: "example.org",
			registrar: "ICANN", whoisServer: "",
			created: "1995-08-31", updated: "2026-01-16", expiry: "2026-08-30",
			nsContains: []string{"katelyn.ns.cloudflare.com", "mitch.ns.cloudflare.com"},
			statuses:   []string{"serverTransferProhibited"},
			dnssec:     "signedDelegation",
		},

		// DENIC: port 43 only echoes Domain + Status (measured 2026-07)
		"whois_de.txt": {
			tld: "de", registered: true, domain: "google.de",
			statuses: []string{"connect"},
		},
		"whois_de_free.txt": {tld: "de", registered: false},

		// JPRS bracket format
		"whois_jp.txt": {
			tld: "jp", registered: true, domain: "GOOGLE.JP",
			created: "2005-05-30", updated: "2026-06-01", expiry: "2027-05-31",
			regName:    "Google LLC",
			nsContains: []string{"ns1.google.com", "ns4.google.com"},
			nsCount:    4,
			statuses:   []string{"Active"},
		},
		// JPRS .co.jp style with letter prefixes; expiry from [State]
		"whois_jp_co.txt": {
			tld: "jp", registered: true, domain: "GOOGLE.CO.JP",
			created: "2001-03-22", updated: "2026-04-01", expiry: "2027-03-31",
			regOrg:     "Google Japan G.K.",
			nsContains: []string{"ns1.google.com"},
			nsCount:    4,
		},
		// JPRS reserved name (most fields empty, still not available)
		"whois_jp_reserved.txt": {
			tld: "jp", registered: true, domain: "EXAMPLE.JP",
			updated:  "2001-02-21",
			statuses: []string{"Reserved"},
		},

		// Nominet block format with next-line values and IPv6-carrying NS lines
		"whois_uk.txt": {
			tld: "uk", registered: true, domain: "nominet.uk",
			registrar: "No registrar listed",
			regName:   "Nominet UK",
			created:   "2014-06-10", updated: "2026-05-15",
			nsContains: []string{"dns1.nominetdns.uk", "dnsd.nominetdns.uk"},
			nsCount:    8,
			dnssec:     "Signed",
		},
		"whois_uk_avail.txt": {tld: "uk", registered: false},

		// TCI (ru)
		"whois_ru.txt": {
			tld: "ru", registered: true, domain: "YA.RU",
			registrar: "RU-CENTER-RU",
			created:   "1999-07-12", expiry: "2026-07-31",
			nsContains: []string{"ns1.yandex.ru", "ns2.yandex.ru"},
			statuses:   []string{"REGISTERED", "DELEGATED", "VERIFIED"},
		},

		// CNNIC
		"whois_cn.txt": {
			tld: "cn", registered: true, domain: "baidu.com.cn",
			registrar: "互联网域名系统",
			regName:   "百度",
			created:   "2000-02-15", expiry: "2029-02-15",
			nsContains: []string{"dns.baidu.com"},
			statuses:   []string{"clientTransferProhibited"},
			dnssec:     "unsigned",
		},

		// AFNIC
		"whois_fr.txt": {
			tld: "fr", registered: true, domain: "google.fr",
			registrar: "MARKMONITOR Inc.",
			created:   "2000-07-26", updated: "2025-12-03", expiry: "2026-12-30",
			nsContains: []string{"ns1.google.com"},
			nsCount:    4,
			statuses:   []string{"ACTIVE", "serverUpdateProhibited"},
		},
		"whois_fr_avail.txt": {tld: "fr", registered: false},

		// registro.br: compact dates with "#" suffix, no expiry field
		"whois_br.txt": {
			tld: "br", registered: true, domain: "registro.br",
			created: "1999-02-21", updated: "2018-04-02",
			nsContains: []string{"a.dns.br", "e.dns.br"},
			nsCount:    5,
			statuses:   []string{"published"},
		},

		// nic.it: section blocks without colons
		"whois_it.txt": {
			tld: "it", registered: true, domain: "google.it",
			registrar: "MarkMonitor International Limited",
			regOrg:    "Google Ireland Holdings Unlimited Company",
			adminName: "Jared Oberhaus",
			techName:  "Domain Administrator",
			created:   "1999-12-10", updated: "2026-06-09", expiry: "2027-04-21",
			nsContains: []string{"ns1.google.com"},
			nsCount:    4,
			statuses:   []string{"ok"},
		},

		// EURid: no dates at all, registrar/NS blocks, IPv6 in parens
		"whois_eu.txt": {
			tld: "eu", registered: true, domain: "europa.eu",
			registrar:  "ClearMedia NV",
			nsContains: []string{"ns1.bt.net", "ns4az2.europa.eu", "ans1.cw.net"},
		},
		"whois_eu_avail.txt": {tld: "eu", registered: false},

		// KISA/KRNIC: "2007. 02. 28." dates, Authorized Agency registrar
		"whois_kr.txt": {
			tld: "kr", registered: true, domain: "naver.kr",
			registrar: "Gabia",
			regName:   "NAVER Corp.",
			adminName: "NAVER Corp.",
			regEmail:  "",
			created:   "2007-02-28", updated: "2018-02-28", expiry: "2027-02-28",
			nsContains: []string{"ns1.naver.com", "ns2.naver.com"},
			nsCount:    2,
			dnssec:     "unsigned",
		},

		// HKIRC: dd-mm-yyyy dates
		"whois_hk.txt": {
			tld: "hk", registered: true, domain: "GOOGLE.COM.HK",
			registrar: "MARKMONITOR INC.",
			created:   "2001-07-14", expiry: "2026-11-20",
			nsContains: []string{"ns1.google.com"},
			nsCount:    4,
			statuses:   []string{"Active"},
			dnssec:     "unsigned",
		},

		// TWNIC: "Record created on ..." lines without colons
		"whois_tw.txt": {
			tld: "tw", registered: true, domain: "google.tw",
			registrar: "Markmonitor, Inc.",
			regName:   "Google LLC",
			created:   "2005-10-27", expiry: "2026-10-31",
			nsContains: []string{"ns1.google.com"},
			nsCount:    4,
			statuses:   []string{"clientTransferProhibited"},
		},

		// AUDA (Identity Digital): no created/expiry published
		"whois_au.txt": {
			tld: "au", registered: true, domain: "google.com.au",
			registrar:  "MarkMonitor Corporate Services Inc",
			regName:    "Google LLC",
			updated:    "2026-05-01",
			nsContains: []string{"ns1.google.com"},
			nsCount:    4,
			statuses:   []string{"serverTransferProhibited"},
			dnssec:     "unsigned",
		},

		// SIDN: "Domain nameservers:" block
		"whois_nl.txt": {
			tld: "nl", registered: true, domain: "google.nl",
			registrar: "MarkMonitor Inc.",
			created:   "1999-05-27", updated: "2025-04-18",
			nsContains: []string{"ns1.google.com"},
			nsCount:    4,
			dnssec:     "no",
			statuses:   []string{"active"},
		},

		// Neustar/GoDaddy registry thick format
		"whois_us.txt": {
			tld: "us", registered: true, domain: "google.us",
			registrar: "MarkMonitor, Inc.",
			regName:   "Google LLC",
			regOrg:    "Google LLC",
			regEmail:  "dns-admin@google.com",
			created:   "2002-04-19", updated: "2026-03-22", expiry: "2027-04-18",
			nsContains: []string{"ns1.google.com"},
		},

		// CIRA
		"whois_ca.txt": {
			tld: "ca", registered: true, domain: "google.ca",
			registrar: "MarkMonitor International Canada Ltd.",
			regOrg:    "Google Canada Corporation",
			created:   "2000-10-04", updated: "2026-04-28", expiry: "2027-04-28",
		},

		// CentralNic: fractional-second timestamps
		"whois_xyz.txt": {
			tld: "xyz", registered: true, domain: "GOOGLE.XYZ",
			registrar: "MarkMonitor Inc.",
			created:   "2014-05-20", updated: "2025-11-11", expiry: "2026-11-26",
			nsContains: []string{"ns1.google.com"},
			nsCount:    4,
			dnssec:     "unsigned",
		},

		// NIXI
		"whois_in.txt": {
			tld: "in", registered: true, domain: "google.co.in",
			registrar: "MarkMonitor Inc.",
			regOrg:    "Google LLC",
			created:   "2003-06-23", updated: "2026-05-27", expiry: "2027-06-23",
			nsContains: []string{"ns1.google.com"},
			nsCount:    4,
		},

		// TRABIS (.tr): "** Key" decoration, tab-aligned sub-keys
		"whois_tr.txt": {
			tld: "tr", registered: true, domain: "google.tr",
			registrar: "ODTÜ",
			regName:   "Google LLC",
			created:   "2024-08-26", expiry: "2026-08-25",
			nsContains: []string{"ns1.googledomains.com"},
			nsCount:    4,
			statuses:   []string{"Active"},
		},

		// .vc via whois.identitydigital.services
		"whois_vc.txt": {
			tld: "vc", registered: true, domain: "google.vc",
			registrar: "MarkMonitor Inc.",
			created:   "2005-06-29", updated: "2026-06-02", expiry: "2027-06-29",
			nsContains: []string{"ns1.google.com"},
			nsCount:    4,
		},

		// Identity Digital thick
		"whois_io.txt": {
			tld: "io", registered: true, domain: "google.io",
			registrar: "MarkMonitor Inc.", registrarID: "292",
			whoisServer: "whois.markmonitor.com",
			regOrg:      "Google LLC",
			created:     "2002-10-01", updated: "2025-09-03", expiry: "2026-09-30",
			nsContains: []string{"ns1.google.com"},
			nsCount:    4,
			dnssec:     "unsigned",
		},
		"whois_me.txt": {
			tld: "me", registered: true, domain: "google.me",
			registrar: "MarkMonitor Inc.",
			created:   "2008-06-13", updated: "2026-05-17", expiry: "2027-06-13",
		},
	}

	for file, exp := range cases {
		t.Run(file, func(t *testing.T) {
			raw := load(t, file)
			p, registered := Parse(exp.tld, raw)
			if registered != exp.registered {
				t.Fatalf("registered = %v, want %v", registered, exp.registered)
			}
			if !exp.registered {
				return
			}
			if exp.domain != "" && !strings.EqualFold(p.DomainName, exp.domain) {
				t.Errorf("DomainName = %q, want %q", p.DomainName, exp.domain)
			}
			if exp.registrar != "" && !strings.Contains(p.Registrar, exp.registrar) {
				t.Errorf("Registrar = %q, want substring %q", p.Registrar, exp.registrar)
			}
			if exp.registrarID != "" && p.RegistrarID != exp.registrarID {
				t.Errorf("RegistrarID = %q, want %q", p.RegistrarID, exp.registrarID)
			}
			if exp.whoisServer != "" && p.WhoisServer != exp.whoisServer {
				t.Errorf("WhoisServer = %q, want %q", p.WhoisServer, exp.whoisServer)
			}
			checkDate(t, "Created", p.Created, exp.created)
			checkDate(t, "Updated", p.Updated, exp.updated)
			checkDate(t, "Expiry", p.Expiry, exp.expiry)
			for _, ns := range exp.nsContains {
				if !containsFold(p.NameServers, ns) {
					t.Errorf("NameServers %v missing %q", p.NameServers, ns)
				}
			}
			if exp.nsCount > 0 && len(p.NameServers) != exp.nsCount {
				t.Errorf("len(NameServers) = %d, want %d (%v)", len(p.NameServers), exp.nsCount, p.NameServers)
			}
			for _, s := range exp.statuses {
				if !containsFold(p.Statuses, s) {
					t.Errorf("Statuses %v missing %q", p.Statuses, s)
				}
			}
			if exp.dnssec != "" && !strings.EqualFold(p.DNSSec, exp.dnssec) {
				t.Errorf("DNSSec = %q, want %q", p.DNSSec, exp.dnssec)
			}
			if exp.regName != "" && !strings.Contains(p.Registrant.Name, exp.regName) {
				t.Errorf("Registrant.Name = %q, want substring %q", p.Registrant.Name, exp.regName)
			}
			if exp.regOrg != "" && !strings.Contains(p.Registrant.Organization, exp.regOrg) {
				t.Errorf("Registrant.Organization = %q, want substring %q", p.Registrant.Organization, exp.regOrg)
			}
			if exp.regEmail != "" && p.Registrant.Email != exp.regEmail {
				t.Errorf("Registrant.Email = %q, want %q", p.Registrant.Email, exp.regEmail)
			}
			if exp.adminName != "" && !strings.Contains(p.Admin.Name, exp.adminName) {
				t.Errorf("Admin.Name = %q, want substring %q", p.Admin.Name, exp.adminName)
			}
			if exp.techName != "" && !strings.Contains(p.Tech.Name, exp.techName) {
				t.Errorf("Tech.Name = %q, want substring %q", p.Tech.Name, exp.techName)
			}
		})
	}
}

func checkDate(t *testing.T, field string, got *time.Time, want string) {
	t.Helper()
	if want == "" {
		if got != nil {
			t.Errorf("%s = %v, want nil", field, got.Format("2006-01-02"))
		}
		return
	}
	if got == nil {
		t.Errorf("%s = nil, want %s", field, want)
		return
	}
	if got.Format("2006-01-02") != want {
		t.Errorf("%s = %s, want %s", field, got.Format("2006-01-02"), want)
	}
}

func TestParseDate(t *testing.T) {
	cases := map[string]string{
		"2026-07-26T14:55:57Z":        "2026-07-26",
		"2025-12-03T10:12:00.351952Z": "2025-12-03",
		"2025-11-11T12:00:30.0Z":      "2025-11-11",
		"2024-01-15T10:20:30+01:00":   "2024-01-15",
		"2000-02-15 00:00:00":         "2000-02-15",
		"2026-04-01 01:05:09 (JST)":   "2026-04-01",
		"2001/03/26":                  "2001-03-26",
		"05-Aug-1996":                 "1996-08-05",
		"15-may-2026":                 "2026-05-15",
		"2007. 02. 28.":               "2007-02-28",
		"14-07-2001":                  "2001-07-14",
		"19951218 #123456":            "1995-12-18",
		"20180402":                    "2018-04-02",
		"1999-05-27":                  "1999-05-27",
		"before Aug-1996":             "",
		"":                            "",
		"NOT DISCLOSED!":              "",
	}
	for in, want := range cases {
		got := parseDate(in)
		if want == "" {
			if got != nil {
				t.Errorf("parseDate(%q) = %v, want nil", in, got)
			}
			continue
		}
		if got == nil {
			t.Errorf("parseDate(%q) = nil, want %s", in, want)
			continue
		}
		if got.Format("2006-01-02") != want {
			t.Errorf("parseDate(%q) = %s, want %s", in, got.Format("2006-01-02"), want)
		}
	}
}

func TestIsAvailable(t *testing.T) {
	available := []string{
		"Status: free",
		"No match for \"FOO.COM\".",
		"%% NOT FOUND",
		"Domain: foo.eu\nScript: LATIN\nStatus: AVAILABLE\n",
		"    No match for \"foo.uk\".\n\n    This domain name has not been registered.\n",
		"No entries found for the selected source(s).",
		"Domain: foo.it\nStatus:             AVAILABLE\n",
		"no matching record.",
	}
	for _, raw := range available {
		if !IsAvailable("x", raw) {
			t.Errorf("IsAvailable(%q) = false, want true", raw)
		}
	}
	registered := []string{
		"Domain: foo.de\nStatus: connect\n",
		"Domain Name: FOO.COM\nCreation Date: 1997-09-15T04:00:00Z\nRegistrar: X\n",
	}
	for _, raw := range registered {
		if IsAvailable("x", raw) {
			t.Errorf("IsAvailable(%q) = true, want false", raw)
		}
	}
}
