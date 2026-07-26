package whois

import "testing"

// Test vectors from RFC 3492 §7.1 plus well-known IDN examples.
func TestEncodePunycode(t *testing.T) {
	cases := []struct{ in, want string }{
		{"mañana", "maana-pta"},   // RFC 3492 (b)
		{"bücher", "bcher-kva"},   // RFC 3492 (d)
		{"münchen", "mnchen-3ya"}, // RFC 3492 (j) lower-cased
		{"café", "caf-dma"},       //
		{"☃", "n3h"},              // snowman
		{"他们为什么不说中文", "ihqwcrb4cv8a8dqg056pqjye"},       // RFC 3492 (i)
		{"ليهمابتكلموشعربي؟", "egbpdaj6bu4bxfgehfvwxn"}, // RFC 3492 (a)
		{"例え", "r8jz45g"}, // 例え.jp → xn--r8jz45g.jp
		{"中国", "fiqs8s"},  // .中国 → xn--fiqs8s
		{"рф", "p1ai"},    // .рф → xn--p1ai
	}
	for _, c := range cases {
		got, err := encodePunycode(c.in)
		if err != nil {
			t.Errorf("encodePunycode(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("encodePunycode(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestToASCII(t *testing.T) {
	cases := []struct{ in, want string }{
		{"google.com", "google.com"},
		{"GOOGLE.COM", "google.com"},
		{"例え.jp", "xn--r8jz45g.jp"},
		{"münchen.de", "xn--mnchen-3ya.de"},
		{"bücher.de", "xn--bcher-kva.de"},
		{"example.中国", "example.xn--fiqs8s"},
		{"example。中国", "example.xn--fiqs8s"}, // U+3002 separator
		{"新华网.cn", "xn--xkrr14bows.cn"},
		{"xn--r8jz45g.jp", "xn--r8jz45g.jp"}, // already A-label
	}
	for _, c := range cases {
		got, err := ToASCII(c.in)
		if err != nil {
			t.Errorf("ToASCII(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ToASCII(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNormalizeDomain(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Example.COM", "example.com"},
		{" example.com ", "example.com"},
		{"example.com.", "example.com"},
		{"https://example.com/path?q=1", "example.com"},
		{"例え.JP", "xn--r8jz45g.jp"},
	}
	for _, c := range cases {
		got, err := normalizeDomain(c.in)
		if err != nil {
			t.Errorf("normalizeDomain(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("normalizeDomain(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	for _, bad := range []string{"", " ", "exa mple.com", "foo/bar"} {
		if _, err := normalizeDomain(bad); err == nil {
			t.Errorf("normalizeDomain(%q): expected error", bad)
		}
	}
}
