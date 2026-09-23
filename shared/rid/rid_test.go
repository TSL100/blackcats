package rid

import (
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
)

func TestRecipientParameter(t *testing.T) {
	if RecipientParameter != "user_id" {
		t.Fatalf("expected default recipient parameter to be user_id, got %q", RecipientParameter)
	}
}

func TestCreatePhishUrlNoParams(t *testing.T) {
	params := &url.Values{}
	got := CreatePhishUrl("https://example.com/lure", params)
	if got != "https://example.com/lure" {
		t.Fatalf("expected base URL to be returned unchanged, got %q", got)
	}
}

func TestCreatePhishUrlAppendsParam(t *testing.T) {
	params := &url.Values{}
	params.Set("rid", "abc123")
	got := CreatePhishUrl("https://example.com/lure", params)
	if got == "https://example.com/lure" {
		t.Fatal("expected link to be modified")
	}
	if !strings.Contains(got, "?user_id=") {
		t.Fatalf("expected recipient parameter to be appended, got %q", got)
	}

	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("expected URL to parse, got error: %v", err)
	}
	keyVal := u.Query().Get(RecipientParameter)
	if keyVal == "" {
		t.Fatal("expected recipient parameter value to be present")
	}
	if len(keyVal) <= 8 {
		t.Fatalf("expected encrypted value longer than the 8-char RC4 key, got %d chars", len(keyVal))
	}
}

func TestCreatePhishUrlRoundTrip(t *testing.T) {
	cases := []struct {
		key string
		val string
	}{
		{"rid", "REPLACE_ME"},
		{"rid", strings.Repeat("A", 64)},
		{"user_id", "victim@example.com"},
		{"foo", "a=b&c=d"},
	}
	for _, tc := range cases {
		params := &url.Values{}
		params.Set(tc.key, tc.val)
		got := CreatePhishUrl("https://host/path", params)
		if !strings.Contains(got, "?user_id=") {
			t.Fatalf("case %q: expected user_id param", tc.key)
		}
	}
}

func TestGenRandomString(t *testing.T) {
	for _, n := range []int{0, 1, 8, 32} {
		got := GenRandomString(n)
		if len(got) != n {
			t.Fatalf("GenRandomString(%d) returned length %d", n, len(got))
		}
	}
}

func TestGenRandomAlphanumString(t *testing.T) {
	got := GenRandomAlphanumString(8)
	if len(got) != 8 {
		t.Fatalf("expected length 8, got %d", len(got))
	}
}

func TestDecodeParamsRoundTrip(t *testing.T) {
	cases := []struct {
		key string
		val string
	}{
		{"rid", "abc123"},
		{"user_id", "victim@example.com"},
		{"email", "foo bar+baz@x.test"},
		{"rid", strings.Repeat("A", 256)},
	}
	for _, tc := range cases {
		params := &url.Values{}
		params.Set(tc.key, tc.val)
		u := CreatePhishUrl("https://host/path", params)

		parsed, err := url.Parse(u)
		if err != nil {
			t.Fatalf("case %q: parse: %v", tc.key, err)
		}
		encoded := parsed.Query().Get(RecipientParameter)
		if encoded == "" {
			t.Fatalf("case %q: missing recipient parameter", tc.key)
		}
		got, err := DecodeParams(encoded)
		if err != nil {
			t.Fatalf("case %q: decode: %v", tc.key, err)
		}
		if got.Get(tc.key) != tc.val {
			t.Fatalf("case %q: decoded %q, want %q", tc.key, got.Get(tc.key), tc.val)
		}
	}
}

func TestDecodeParamsRejectsCorrupted(t *testing.T) {
	params := &url.Values{}
	params.Set("rid", "abc123")
	u := CreatePhishUrl("https://host/path", params)
	parsed, _ := url.Parse(u)
	encoded := parsed.Query().Get(RecipientParameter)

	blob, err := base64.RawURLEncoding.DecodeString(encoded[8:])
	if err != nil {
		t.Fatalf("decode blob: %v", err)
	}
	blob[len(blob)-1] ^= 0xff
	corrupted := encoded[:8] + base64.RawURLEncoding.EncodeToString(blob)

	if _, err := DecodeParams(corrupted); err != ErrChecksum {
		t.Fatalf("expected ErrChecksum, got %v", err)
	}
}

func TestDecodeParamsRejectsShortValue(t *testing.T) {
	if _, err := DecodeParams("short"); err != ErrNotEncrypted {
		t.Fatalf("expected ErrNotEncrypted, got %v", err)
	}
	if _, err := DecodeParams(""); err != ErrNotEncrypted {
		t.Fatalf("expected ErrNotEncrypted for empty value, got %v", err)
	}
}