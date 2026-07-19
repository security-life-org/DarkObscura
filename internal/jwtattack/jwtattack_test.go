package jwtattack

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func hs256(secret string) string {
	h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	p := base64.RawURLEncoding.EncodeToString([]byte(`{"user":"alice","admin":false}`))
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(h + "." + p))
	return h + "." + p + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func TestCrack_WeakSecret(t *testing.T) {
	tok, _ := Decode(hs256("secret"))
	fs := Analyze(tok, nil)
	found := false
	for _, f := range fs { if f.Class == "jwt-weak-secret" { found = true } }
	if !found { t.Fatalf("expected weak-secret finding; got %v", fs) }
}

func TestCrack_StrongSecret_NoFinding(t *testing.T) {
	tok, _ := Decode(hs256("Zx9$Kq2!vB7mNw4pLr8sTf3uHy6dGc1a"))
	for _, f := range Analyze(tok, nil) {
		if f.Class == "jwt-weak-secret" { t.Fatal("strong secret must NOT be cracked (false positive)") }
	}
}

func TestAlgNone(t *testing.T) {
	h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	p := base64.RawURLEncoding.EncodeToString([]byte(`{"user":"bob"}`))
	tok, err := Decode(h + "." + p + ".")
	if err != nil { t.Fatal(err) }
	found := false
	for _, f := range Analyze(tok, nil) { if f.Class == "jwt-alg-none" { found = true } }
	if !found { t.Fatal("expected alg-none finding") }
}
