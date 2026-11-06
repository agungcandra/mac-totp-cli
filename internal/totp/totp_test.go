package totp

import (
	"encoding/base32"
	"testing"
	"time"
)

// RFC 6238 Appendix B test vectors.
func TestRFC6238(t *testing.T) {
	key20 := []byte("12345678901234567890")
	key32 := []byte("12345678901234567890123456789012")
	key64 := []byte("1234567890123456789012345678901234567890123456789012345678901234")

	enc := func(b []byte) string {
		return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
	}

	cases := []struct {
		name string
		key  string
		algo Algorithm
		t    int64
		want string
	}{
		{"sha1-59", enc(key20), AlgorithmSHA1, 59, "94287082"},
		{"sha1-1111111109", enc(key20), AlgorithmSHA1, 1111111109, "07081804"},
		{"sha1-1111111111", enc(key20), AlgorithmSHA1, 1111111111, "14050471"},
		{"sha1-1234567890", enc(key20), AlgorithmSHA1, 1234567890, "89005924"},
		{"sha1-2000000000", enc(key20), AlgorithmSHA1, 2000000000, "69279037"},
		{"sha1-20000000000", enc(key20), AlgorithmSHA1, 20000000000, "65353130"},

		{"sha256-59", enc(key32), AlgorithmSHA256, 59, "46119246"},
		{"sha256-1111111109", enc(key32), AlgorithmSHA256, 1111111109, "68084774"},
		{"sha256-1111111111", enc(key32), AlgorithmSHA256, 1111111111, "67062674"},
		{"sha256-1234567890", enc(key32), AlgorithmSHA256, 1234567890, "91819424"},
		{"sha256-2000000000", enc(key32), AlgorithmSHA256, 2000000000, "90698825"},
		{"sha256-20000000000", enc(key32), AlgorithmSHA256, 20000000000, "77737706"},

		{"sha512-59", enc(key64), AlgorithmSHA512, 59, "90693936"},
		{"sha512-1111111109", enc(key64), AlgorithmSHA512, 1111111109, "25091201"},
		{"sha512-1111111111", enc(key64), AlgorithmSHA512, 1111111111, "99943326"},
		{"sha512-1234567890", enc(key64), AlgorithmSHA512, 1234567890, "93441116"},
		{"sha512-2000000000", enc(key64), AlgorithmSHA512, 2000000000, "38618901"},
		{"sha512-20000000000", enc(key64), AlgorithmSHA512, 20000000000, "47863826"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &Secret{Secret: tc.key, Algorithm: tc.algo, Digits: 8, Period: 30}
			got, err := s.GenerateAt(time.Unix(tc.t, 0))
			if err != nil {
				t.Fatalf("GenerateAt: %v", err)
			}
			if got != tc.want {
				t.Errorf("code = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestNormalizeSecret(t *testing.T) {
	// Spaces and lowercase + no padding should be tolerated.
	s := &Secret{Secret: "jbsw y3dp ehpk 3pxp"} // "Hello!" in base32
	if err := s.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if s.Secret != "JBSWY3DPEHPK3PXP" {
		t.Errorf("Secret = %q", s.Secret)
	}
	if s.Digits != 6 || s.Period != 30 || s.Algorithm != AlgorithmSHA1 {
		t.Errorf("defaults not applied: %+v", s)
	}
}

func TestInvalidBase32(t *testing.T) {
	s := &Secret{Secret: "not-base32-!!!"}
	if err := s.Normalize(); err == nil {
		t.Fatal("expected error")
	}
}

func TestInvalidDigits(t *testing.T) {
	s := &Secret{Secret: "JBSWY3DPEHPK3PXP", Digits: 7}
	if err := s.Normalize(); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseURI(t *testing.T) {
	uri := "otpauth://totp/ACME%20Co:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30"
	s, err := ParseURI(uri)
	if err != nil {
		t.Fatalf("ParseURI: %v", err)
	}
	if s.Issuer != "ACME Co" {
		t.Errorf("Issuer = %q", s.Issuer)
	}
	if s.Name != "alice@example.com" {
		t.Errorf("Name = %q", s.Name)
	}
	if s.Secret != "JBSWY3DPEHPK3PXP" {
		t.Errorf("Secret = %q", s.Secret)
	}
	if s.Digits != 6 || s.Period != 30 || s.Algorithm != AlgorithmSHA1 {
		t.Errorf("fields: %+v", s)
	}
}

func TestParseURIDefaults(t *testing.T) {
	uri := "otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP"
	s, err := ParseURI(uri)
	if err != nil {
		t.Fatalf("ParseURI: %v", err)
	}
	if s.Name != "alice" || s.Issuer != "" {
		t.Errorf("name/issuer: %+v", s)
	}
	if s.Digits != 6 || s.Period != 30 || s.Algorithm != AlgorithmSHA1 {
		t.Errorf("defaults: %+v", s)
	}
}

func TestParseURIBadScheme(t *testing.T) {
	if _, err := ParseURI("http://totp/alice?secret=JBSWY3DPEHPK3PXP"); err == nil {
		t.Fatal("expected error")
	}
}

func TestSecondsRemaining(t *testing.T) {
	s := &Secret{Period: 30}
	got := s.SecondsRemaining(time.Unix(29, 0))
	if got != 1 {
		t.Errorf("SecondsRemaining = %d, want 1", got)
	}
	got = s.SecondsRemaining(time.Unix(0, 0))
	if got != 30 {
		t.Errorf("SecondsRemaining = %d, want 30", got)
	}
}
