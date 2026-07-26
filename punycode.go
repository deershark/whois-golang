package whois

import (
	"errors"
	"strings"
	"unicode/utf8"
)

// Punycode encoder (RFC 3492) used to convert IDN labels to A-labels.
// Only encoding is needed: registries are always queried with A-labels.

const (
	pcBase        = 36
	pcTMin        = 1
	pcTMax        = 26
	pcSkew        = 38
	pcDamp        = 700
	pcInitialBias = 72
	pcInitialN    = 128
)

func pcDigit(d uint32) byte {
	if d < 26 {
		return byte('a' + d)
	}
	return byte('0' + d - 26)
}

func pcAdapt(delta, numPoints uint32, firstTime bool) uint32 {
	if firstTime {
		delta /= pcDamp
	} else {
		delta /= 2
	}
	delta += delta / numPoints
	k := uint32(0)
	for delta > ((pcBase-pcTMin)*pcTMax)/2 {
		delta /= pcBase - pcTMin
		k += pcBase
	}
	return k + (pcBase-pcTMin+1)*delta/(delta+pcSkew)
}

// encodePunycode encodes a single DNS label (without the "xn--" prefix).
func encodePunycode(label string) (string, error) {
	runes := []rune(label)
	var b strings.Builder

	// Copy basic code points.
	nBasic := 0
	for _, r := range runes {
		if r < 0x80 {
			b.WriteByte(byte(r))
			nBasic++
		}
	}
	h := nBasic
	if nBasic > 0 && nBasic < len(runes) {
		b.WriteByte('-')
	}

	n := uint32(pcInitialN)
	delta := uint32(0)
	bias := uint32(pcInitialBias)

	for h < len(runes) {
		// Find the next smallest code point >= n.
		m := uint32(0x7FFFFFFF)
		for _, r := range runes {
			if uint32(r) >= n && uint32(r) < m {
				m = uint32(r)
			}
		}
		if m == 0x7FFFFFFF {
			return "", errors.New("punycode: no code point >= n")
		}
		delta += (m - n) * uint32(h+1)
		n = m
		for _, r := range runes {
			c := uint32(r)
			if c < n {
				delta++
			}
			if c == n {
				q := delta
				for k := uint32(pcBase); ; k += pcBase {
					var t uint32
					switch {
					case k <= bias:
						t = pcTMin
					case k >= bias+pcTMax:
						t = pcTMax
					default:
						t = k - bias
					}
					if q < t {
						break
					}
					b.WriteByte(pcDigit(t + (q-t)%(pcBase-t)))
					q = (q - t) / (pcBase - t)
				}
				b.WriteByte(pcDigit(q))
				bias = pcAdapt(delta, uint32(h+1), h == nBasic)
				delta = 0
				h++
			}
		}
		delta++
		n++
	}
	return b.String(), nil
}

var idnDotReplacer = strings.NewReplacer(
	"。", ".", // U+3002 ideographic full stop
	"．", ".", // U+FF0E fullwidth full stop
	"｡", ".", // U+FF61 halfwidth ideographic full stop
)

// ToASCII converts a (possibly internationalized) domain name to its
// A-label form (punycode per non-ASCII label, lower-cased).
func ToASCII(domain string) (string, error) {
	domain = idnDotReplacer.Replace(domain)
	labels := strings.Split(domain, ".")
	for i, label := range labels {
		if label == "" {
			if i == len(labels)-1 { // trailing dot already trimmed by caller
				continue
			}
			return "", errors.New("whois: empty label in domain")
		}
		ascii := true
		for _, r := range label {
			if r >= 0x80 {
				ascii = false
				break
			}
		}
		if ascii {
			labels[i] = strings.ToLower(label)
			continue
		}
		enc, err := encodePunycode(label)
		if err != nil {
			return "", err
		}
		labels[i] = "xn--" + enc
	}
	return strings.Join(labels, "."), nil
}

// normalizeDomain cleans and validates user input, returning the lower-cased
// A-label form used for queries.
func normalizeDomain(domain string) (string, error) {
	d := strings.TrimSpace(domain)
	if i := strings.Index(d, "://"); i >= 0 && i <= 5 {
		d = d[i+3:]
		if j := strings.IndexAny(d, "/?#"); j >= 0 {
			d = d[:j]
		}
	}
	d = strings.TrimSuffix(strings.ToLower(d), ".")
	if d == "" {
		return "", errors.New("whois: empty domain")
	}
	ascii, err := ToASCII(d)
	if err != nil {
		return "", err
	}
	if len(ascii) > 253 || !utf8.ValidString(ascii) {
		return "", errors.New("whois: domain too long")
	}
	for _, r := range ascii {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '.' || r == '_'
		if !ok {
			return "", errors.New("whois: invalid character in domain")
		}
	}
	return ascii, nil
}
