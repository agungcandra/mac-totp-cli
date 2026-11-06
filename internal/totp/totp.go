// Package totp implements RFC 4226 HOTP and RFC 6238 TOTP, plus otpauth:// URI parsing.
package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Algorithm is the HMAC hash used for HOTP/TOTP computations.
type Algorithm string

const (
	AlgorithmSHA1   Algorithm = "SHA1"
	AlgorithmSHA256 Algorithm = "SHA256"
	AlgorithmSHA512 Algorithm = "SHA512"
)

func (a Algorithm) hasher() (func() hash.Hash, error) {
	switch Algorithm(strings.ToUpper(string(a))) {
	case AlgorithmSHA1, "":
		return sha1.New, nil
	case AlgorithmSHA256:
		return sha256.New, nil
	case AlgorithmSHA512:
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", a)
	}
}

// Secret holds a decoded TOTP configuration ready for code generation.
type Secret struct {
	Name      string    `json:"-"`
	Issuer    string    `json:"issuer,omitempty"`
	Secret    string    `json:"secret"` // base32, no padding, uppercase
	Algorithm Algorithm `json:"algorithm"`
	Digits    int       `json:"digits"`
	Period    int       `json:"period"`
}

// Normalize fills in defaults and uppercases/strips the base32 secret.
func (s *Secret) Normalize() error {
	s.Secret = normalizeBase32(s.Secret)
	if s.Secret == "" {
		return fmt.Errorf("secret is empty")
	}
	if _, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s.Secret); err != nil {
		return fmt.Errorf("invalid base32 secret: %w", err)
	}
	if s.Digits == 0 {
		s.Digits = 6
	}
	if s.Digits != 6 && s.Digits != 8 {
		return fmt.Errorf("digits must be 6 or 8, got %d", s.Digits)
	}
	if s.Period == 0 {
		s.Period = 30
	}
	if s.Period <= 0 {
		return fmt.Errorf("period must be positive, got %d", s.Period)
	}
	if s.Algorithm == "" {
		s.Algorithm = AlgorithmSHA1
	}
	s.Algorithm = Algorithm(strings.ToUpper(string(s.Algorithm)))
	if _, err := s.Algorithm.hasher(); err != nil {
		return err
	}
	return nil
}

func normalizeBase32(s string) string {
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "-", "")
	s = strings.TrimRight(s, "=")
	return strings.ToUpper(s)
}

// HOTP implements RFC 4226.
func HOTP(secret []byte, counter uint64, digits int, algo Algorithm) (string, error) {
	hfn, err := algo.hasher()
	if err != nil {
		return "", err
	}
	mac := hmac.New(hfn, secret)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[offset])&0x7f)<<24 |
		(uint32(sum[offset+1])&0xff)<<16 |
		(uint32(sum[offset+2])&0xff)<<8 |
		(uint32(sum[offset+3]) & 0xff)
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	code := bin % mod
	return fmt.Sprintf("%0*d", digits, code), nil
}

// GenerateAt returns the TOTP code for the given point in time.
func (s *Secret) GenerateAt(t time.Time) (string, error) {
	if err := s.Normalize(); err != nil {
		return "", err
	}
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s.Secret)
	if err != nil {
		return "", err
	}
	counter := uint64(t.Unix() / int64(s.Period))
	return HOTP(raw, counter, s.Digits, s.Algorithm)
}

// Generate returns the current TOTP code.
func (s *Secret) Generate() (string, error) {
	return s.GenerateAt(time.Now())
}

// SecondsRemaining returns seconds until the current code rolls over.
func (s *Secret) SecondsRemaining(now time.Time) int {
	p := s.Period
	if p <= 0 {
		p = 30
	}
	return p - int(now.Unix()%int64(p))
}

// ParseURI parses an otpauth://totp/... URI into a Secret.
func ParseURI(raw string) (*Secret, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse uri: %w", err)
	}
	if u.Scheme != "otpauth" {
		return nil, fmt.Errorf("uri scheme must be otpauth, got %q", u.Scheme)
	}
	if strings.ToLower(u.Host) != "totp" {
		return nil, fmt.Errorf("only totp uris supported, got %q", u.Host)
	}
	label := strings.TrimPrefix(u.Path, "/")
	label, err = url.PathUnescape(label)
	if err != nil {
		return nil, fmt.Errorf("decode label: %w", err)
	}
	var issuer, name string
	if idx := strings.Index(label, ":"); idx >= 0 {
		issuer = strings.TrimSpace(label[:idx])
		name = strings.TrimSpace(label[idx+1:])
	} else {
		name = label
	}
	q := u.Query()
	s := &Secret{
		Name:      name,
		Issuer:    issuer,
		Secret:    q.Get("secret"),
		Algorithm: Algorithm(q.Get("algorithm")),
	}
	if v := q.Get("issuer"); v != "" {
		s.Issuer = v
	}
	if v := q.Get("digits"); v != "" {
		d, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("invalid digits: %w", err)
		}
		s.Digits = d
	}
	if v := q.Get("period"); v != "" {
		p, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("invalid period: %w", err)
		}
		s.Period = p
	}
	if err := s.Normalize(); err != nil {
		return nil, err
	}
	return s, nil
}
