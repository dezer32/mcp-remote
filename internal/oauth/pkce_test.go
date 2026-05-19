package oauth

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestGenerateVerifier(t *testing.T) {
	v, err := generateVerifier()
	if err != nil {
		t.Fatalf("generateVerifier: %v", err)
	}
	if got := len(v); got != 43 {
		t.Fatalf("verifier length = %d, want 43", got)
	}
	// base64url-safe alphabet: A-Z a-z 0-9 - _
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	for _, r := range v {
		if !strings.ContainsRune(alphabet, r) {
			t.Fatalf("verifier contains non-base64url char: %q", r)
		}
	}
	if strings.Contains(v, "=") {
		t.Fatalf("verifier has padding: %q", v)
	}
}

func TestGenerateVerifierUnique(t *testing.T) {
	seen := map[string]struct{}{}
	for i := 0; i < 64; i++ {
		v, err := generateVerifier()
		if err != nil {
			t.Fatalf("generateVerifier: %v", err)
		}
		if _, dup := seen[v]; dup {
			t.Fatalf("verifier duplicated within 64 iterations: %s", v)
		}
		seen[v] = struct{}{}
	}
}

func TestChallengeS256RFC7636Vector(t *testing.T) {
	// RFC 7636 Appendix B.
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	want := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	got := challengeS256(verifier)
	if got != want {
		t.Fatalf("challengeS256 = %s, want %s", got, want)
	}
}

func TestChallengeS256NoPadding(t *testing.T) {
	v, err := generateVerifier()
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	c := challengeS256(v)
	if strings.Contains(c, "=") {
		t.Fatalf("challenge has padding: %s", c)
	}
	// raw url-safe: decode reverse-trip
	if _, err := base64.RawURLEncoding.DecodeString(c); err != nil {
		t.Fatalf("challenge not base64url: %v", err)
	}
}

func TestGenerateState(t *testing.T) {
	s, err := generateState()
	if err != nil {
		t.Fatalf("generateState: %v", err)
	}
	if got := len(s); got != 43 {
		t.Fatalf("state length = %d, want 43", got)
	}
	if _, err := base64.RawURLEncoding.DecodeString(s); err != nil {
		t.Fatalf("state not base64url: %v", err)
	}
}
