package oauth

// PKCE (RFC 7636) S256 + state.
//   verifier — 32 байта из crypto/rand → base64url(no padding); длина 43.
//   challenge = base64url(no padding)(sha256(verifier)).
//   code_challenge_method=S256 ставится в authorize-запросе явно.
//   state — 32 байта crypto/rand → base64url(no padding); проверяется в callback.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// generateVerifier возвращает code_verifier по RFC 7636:
// 32 случайных байта закодированных base64url без padding (длина 43).
func generateVerifier() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// challengeS256 вычисляет code_challenge по методу S256:
// base64url(no padding)(SHA-256(verifier)).
func challengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// generateState возвращает значение state для защиты от CSRF:
// 32 случайных байта закодированных base64url без padding.
func generateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
