package core

import (
	"encoding/base64"
	"net/url"
	"testing"

	"evilgophish/shared/rid"
)

// TestExtractParamsRoundTrip proves that a phishing URL generated through the
// canonical shared/rid encoder is decoded by the proxy's extractParams into
// the same parameters (single end-to-end URL flow).
func TestExtractParamsRoundTrip(t *testing.T) {
	q := url.Values{}
	q.Set("fname", "Foo Bar")
	q.Set("email", "victim@example.com")
	q.Set("rid", "abcd1234")

	u, err := url.Parse(rid.CreatePhishUrl("https://phish.example/invite", &q))
	if err != nil {
		t.Fatalf("parse lure url: %v", err)
	}

	p := &HttpProxy{}
	s := &Session{Params: map[string]string{}}
	if !p.extractParams(s, u) {
		t.Fatal("extractParams failed on a valid encoded url")
	}
	if s.Params["rid"] != "abcd1234" {
		t.Fatalf("decoded rid = %q, want abcd1234", s.Params["rid"])
	}
	if s.Params["fname"] != "Foo Bar" || s.Params["email"] != "victim@example.com" {
		t.Fatalf("decoded params mismatch: %v", s.Params)
	}
}

// TestExtractParamsRejectsCorruptedValue verifies a tampered lure value is
// rejected (checksum failure) without panicking.
func TestExtractParamsRejectsCorruptedValue(t *testing.T) {
	q := url.Values{}
	q.Set("rid", "abc123")
	good := rid.CreatePhishUrl("https://phish.example/", &q)
	ugood, _ := url.Parse(good)
	enc := ugood.Query().Get(rid.RecipientParameter)

	blob, err := base64.RawURLEncoding.DecodeString(enc[8:])
	if err != nil {
		t.Fatalf("decode blob: %v", err)
	}
	blob[0] ^= 0xff
	corrupt := enc[:8] + base64.RawURLEncoding.EncodeToString(blob)

	q2 := url.Values{}
	q2.Set(rid.RecipientParameter, corrupt)
	u, err := url.Parse("https://phish.example/?" + q2.Encode())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	p := &HttpProxy{}
	if p.extractParams(&Session{Params: map[string]string{}}, u) {
		t.Fatal("extractParams accepted a corrupted lure value")
	}
}