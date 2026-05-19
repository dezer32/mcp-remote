package oauth

// TODO(unit-4): PKCE S256.
//   verifier — 32 байта из crypto/rand → base64url(no padding); длина 43.
//   challenge = base64url(sha256(verifier)).
//   code_challenge_method=S256 ставится в authorize-запросе явно.
//
//   state — 32 байта crypto/rand → base64url; проверяется в callback.
