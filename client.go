package whois

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Errors returned by the client.
var (
	// ErrNoRDAP is returned (wrapped) when the TLD has no RDAP deployment.
	// With fallback enabled this is handled internally.
	ErrNoRDAP = errors.New("whois: TLD has no RDAP service")
	// ErrNoWhoisServer is returned when no port-43 server is known for a TLD.
	ErrNoWhoisServer = errors.New("whois: no WHOIS server known for TLD")
)

const (
	defaultRDAPBase   = "https://rdap.org"
	defaultIANAServer = "whois.iana.org"
)

// Client queries domain registration data. It is safe for concurrent use.
type Client struct {
	httpClient     *http.Client
	rdapBase       string
	rdapBootstrap  bool // rdapBase is a bootstrap redirector (like rdap.org)
	ianaServer     string
	timeout        time.Duration
	preferRDAP     bool
	fallbackWhois  bool
	followReferral bool
	overrides      map[string]string // tld -> whois server
	serverCache    sync.Map          // tld -> resolved whois server
}

// Option configures a Client.
type Option func(*Client)

// WithTimeout sets the per-request network timeout (default 10s).
func WithTimeout(d time.Duration) Option {
	return func(c *Client) { c.timeout = d }
}

// WithHTTPClient sets the HTTP client used for RDAP requests.
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) {
		if h != nil {
			c.httpClient = h
		}
	}
}

// WithRDAPBaseURL replaces the RDAP endpoint (default https://rdap.org).
// A custom URL is treated as an authoritative RDAP server: a 404 then means
// "domain not found" instead of "TLD without RDAP".
func WithRDAPBaseURL(u string) Option {
	return func(c *Client) {
		c.rdapBase = strings.TrimSuffix(u, "/")
		c.rdapBootstrap = false
	}
}

// WithPreferRDAP toggles trying RDAP before WHOIS (default true).
func WithPreferRDAP(v bool) Option {
	return func(c *Client) { c.preferRDAP = v }
}

// WithWhoisFallback toggles falling back to the WHOIS protocol when RDAP is
// unavailable for the TLD or fails (default true).
func WithWhoisFallback(v bool) Option {
	return func(c *Client) { c.fallbackWhois = v }
}

// WithReferralFollowing toggles following the "Registrar WHOIS Server"
// referral found in thin-registry (com/net) responses to obtain thick data
// (default false, to stay polite with registrar rate limits).
func WithReferralFollowing(v bool) Option {
	return func(c *Client) { c.followReferral = v }
}

// WithWhoisServer pins the WHOIS server used for a given TLD
// (e.g. WithWhoisServer("example", "127.0.0.1:1043") for tests).
func WithWhoisServer(tld, server string) Option {
	return func(c *Client) { c.overrides[strings.ToLower(tld)] = server }
}

// WithIANAServer overrides the bootstrap WHOIS server used to discover
// unknown TLD servers (default whois.iana.org).
func WithIANAServer(server string) Option {
	return func(c *Client) { c.ianaServer = server }
}

// New builds a Client with sane defaults.
func New(opts ...Option) *Client {
	c := &Client{
		httpClient:    &http.Client{Timeout: 15 * time.Second},
		rdapBase:      defaultRDAPBase,
		rdapBootstrap: true,
		ianaServer:    defaultIANAServer,
		timeout:       10 * time.Second,
		preferRDAP:    true,
		fallbackWhois: true,
		overrides:     map[string]string{},
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

var defaultClient = New()

// Query looks up domain with a default client.
func Query(domain string) (*Record, error) {
	return defaultClient.Query(domain)
}

// Query looks up domain: RDAP first (via rdap.org bootstrap), falling back
// to the raw WHOIS protocol for TLDs without RDAP deployment.
func (c *Client) Query(domain string) (*Record, error) {
	return c.QueryContext(context.Background(), domain)
}

// QueryContext is Query with a context.
func (c *Client) QueryContext(ctx context.Context, domain string) (*Record, error) {
	d, err := normalizeDomain(domain)
	if err != nil {
		return nil, err
	}
	tld := d
	if i := strings.LastIndex(d, "."); i >= 0 {
		tld = d[i+1:]
	}
	var rdapErr error
	if c.preferRDAP {
		rec, err := c.rdapQuery(ctx, d)
		if err == nil {
			return rec, nil
		}
		if !c.fallbackWhois {
			return nil, err
		}
		rdapErr = err
	}
	rec, err := c.whoisQuery(ctx, d, tld)
	if err != nil && rdapErr != nil && !errors.Is(rdapErr, ErrNoRDAP) {
		// Both protocols failed: report them together.
		return nil, fmt.Errorf("whois: rdap failed: %v; whois fallback failed: %w", rdapErr, err)
	}
	return rec, err
}
