package panel

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kgretzky/evilginx2/core"
	"github.com/kgretzky/evilginx2/database"

	"evilgophish/internal/config"
)

const testPhishletYAML = `author: 'test'
min_ver: '2.3.0'
proxy_hosts:
  - {phish_sub: 'phish', orig_sub: 'www', domain: 'example.com', session: true, is_landing: true}
sub_filters: []
auth_tokens:
  - domain: '.www.example.com'
    keys: ['session']
credentials:
  username:
    key: 'username'
    search: '(.*)'
    type: 'post'
  password:
    key: 'password'
    search: '(.*)'
    type: 'post'
login:
  domain: 'www.example.com'
  path: '/login'
`

// newTestConfig builds a Config backed by a minimal phishlet with a hostname
// configured. It uses only the core config machinery, avoiding the engine's
// sqlite artifacts so Windows can clean up the temp directory.
func newTestConfig(t *testing.T) *core.Config {
	t.Helper()
	dir := t.TempDir()
	cfg, err := core.NewConfig(dir, "")
	if err != nil {
		t.Fatalf("building test config: %v", err)
	}
	yamlPath := filepath.Join(dir, "testsite.yaml")
	if err := os.WriteFile(yamlPath, []byte(testPhishletYAML), 0o600); err != nil {
		t.Fatalf("writing test phishlet: %v", err)
	}
	pl, err := core.NewPhishlet("testsite", yamlPath, nil, cfg)
	if err != nil {
		t.Fatalf("loading test phishlet: %v", err)
	}
	cfg.AddPhishlet("testsite", pl)
	cfg.SetBaseDomain("example.com")
	if !cfg.SetSiteHostname("testsite", "phish.example.com") {
		t.Fatalf("setting hostname for testsite")
	}
	if err := cfg.SetSiteEnabled("testsite"); err != nil {
		t.Fatalf("enabling testsite: %v", err)
	}
	return cfg
}

// fakeSessions returns two captured sessions: one with credentials and
// tokens, one bare.
func fakeSessions() ([]*database.Session, error) {
	return []*database.Session{
		{
			Id:         1,
			Phishlet:   "testsite",
			LandingURL: "https://phish.example.com/login",
			Username:   "victim",
			Password:   "s3cret",
			CookieTokens: map[string]map[string]*database.CookieToken{
				"example.com": {"sess": {Name: "sess", Value: "abc", Path: "/"}},
			},
			BodyTokens: map[string]string{"tok": "v"},
			RemoteAddr: "9.9.9.9",
			CreateTime: 1700000000,
			UpdateTime: 1700000100,
		},
		{
			Id:         2,
			Phishlet:   "testsite",
			LandingURL: "https://phish.example.com/",
			RemoteAddr: "8.8.8.8",
			CreateTime: 1700000200,
			UpdateTime: 1700000300,
		},
	}, nil
}

// fakeCerts pretends the fixture hostname has a certificate expiring in 2030.
func fakeCerts(host string, port int) (certResult, error) {
	if host == "phish.example.com" {
		return certResult{Expiry: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}, nil
	}
	return certResult{Err: "no certificate"}, nil
}

func TestOverviewRenders(t *testing.T) {
	h := http.StripPrefix("/evilginx", New(newTestConfig(t), WithSessions(fakeSessions)))
	req := httptest.NewRequest(http.MethodGet, "/evilginx", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"Black Cat", "How the combination works",
		`href="/evilginx/phishlets"`, `href="/evilginx/domain"`,
		`href="/evilginx/sessions"`, `href="/evilginx/lures"`,
		"Sessions (2)",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("response missing %q", want)
		}
	}
}

// TestPanelUsesUnifiedShell locks the single-tool refactor: every panel page
// must render inside the shared Black Cat shell (same brand bar, same unified
// menu, same stylesheets as the main dashboard) with no trace of the legacy
// standalone "Evilginx Panel" header or its duplicate tab row.
func TestPanelUsesUnifiedShell(t *testing.T) {
	h := http.StripPrefix("/evilginx", New(newTestConfig(t), WithSessions(fakeSessions)))
	paths := []string{"/evilginx", "/evilginx/phishlets", "/evilginx/domain", "/evilginx/sessions", "/evilginx/lures", "/evilginx/spear", "/evilginx/spear/new"}
	for _, path := range paths {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: expected %d, got %d", path, http.StatusOK, rec.Code)
		}
		body := rec.Body.String()
		for _, want := range []string{
			`class="navbar navbar-inverse navbar-fixed-top bc-brandbar"`,
			`class="bc-topnav"`,
			`href="/css/blackcat.css"`,
			`src="/images/blackcat.svg"`,
			`href="/logout"`,
			`href="/campaigns"`,
			`href="/evilginx/"`,
			`replaceState`,
		} {
			if !strings.Contains(body, want) {
				t.Errorf("%s: response missing unified shell markup %q", path, want)
			}
		}
		for _, gone := range []string{"Evilginx Panel", `nav class="tabs"`, `class="back"`, `class="bc-cat"`} {
			if strings.Contains(body, gone) {
				t.Errorf("%s: response still contains legacy standalone markup %q", path, gone)
			}
		}
	}
}

func TestPhishletsPageRenders(t *testing.T) {
	h := http.StripPrefix("/evilginx", New(newTestConfig(t)))
	req := httptest.NewRequest(http.MethodGet, "/evilginx/phishlets", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"testsite", "phish.example.com", "enabled", `action="/evilginx/phishlets"`} {
		if !strings.Contains(body, want) {
			t.Errorf("response missing %q", want)
		}
	}
}

func TestDomainPageRenders(t *testing.T) {
	h := http.StripPrefix("/evilginx", New(newTestConfig(t), WithCertLookup(fakeCerts)))
	req := httptest.NewRequest(http.MethodGet, "/evilginx/domain", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"Server settings", "example.com", "phish.example.com",
		"2030-01-01", `action="/evilginx/domain"`, "Sync certificates now",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("response missing %q", want)
		}
	}
}

func TestDomainSyncFiresOnChange(t *testing.T) {
	done := make(chan struct{}, 1)
	h := http.StripPrefix("/evilginx", New(newTestConfig(t),
		WithOnChange(func() { done <- struct{}{} }),
		WithCertLookup(fakeCerts),
	))

	rec := postForm(t, h, "/evilginx/domain", url.Values{"action": {"sync"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "background") {
		t.Errorf("expected a background-sync message")
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("expected the onChange callback to fire for sync")
	}
}

func TestSessionsPageRenders(t *testing.T) {
	h := http.StripPrefix("/evilginx", New(newTestConfig(t), WithSessions(fakeSessions)))
	req := httptest.NewRequest(http.MethodGet, "/evilginx/sessions", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"Captured loot", "victim", "s3cret", "full JSON",
		"https://phish.example.com/login", "9.9.9.9",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("response missing %q", want)
		}
	}
}

func TestSessionsUnavailable(t *testing.T) {
	h := http.StripPrefix("/evilginx", New(newTestConfig(t)))
	req := httptest.NewRequest(http.MethodGet, "/evilginx/sessions", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Session store unavailable") {
		t.Errorf("expected an explanation when no session provider is configured")
	}
}

func TestLuresPageRenders(t *testing.T) {
	h := http.StripPrefix("/evilginx", New(newTestConfig(t)))
	req := httptest.NewRequest(http.MethodGet, "/evilginx/lures", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"Generate phishing URL", "Create lure", `action="/evilginx/lures"`} {
		if !strings.Contains(body, want) {
			t.Errorf("response missing %q", want)
		}
	}
}

func TestPhishURLGeneration(t *testing.T) {
	h := http.StripPrefix("/evilginx", New(newTestConfig(t)))
	req := httptest.NewRequest(http.MethodGet, "/evilginx/phishurl?p=testsite&rid=abc123&extra=fname=Test+User", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "https://phish.phish.example.com/") {
		t.Errorf("generated URL missing base, got: %s", body)
	}
	if !strings.Contains(body, "user_id=") {
		t.Errorf("generated URL missing encrypted user_id parameter")
	}
}

func TestPhishURLPortTolerance(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.SetPortTolerance(true)
	cfg.SetHttpsPort(8443)
	h := http.StripPrefix("/evilginx", New(cfg))
	req := httptest.NewRequest(http.MethodGet, "/evilginx/phishurl?p=testsite&rid=abc123", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "https://phish.phish.example.com:8443/") {
		t.Errorf("port tolerance: generated URL missing :8443, got: %s", body)
	}
	if !strings.Contains(body, "user_id=") {
		t.Errorf("generated URL missing encrypted user_id parameter")
	}
}

func TestPhishURLPortToleranceOff(t *testing.T) {
	// With port tolerance disabled, the standard 443 default must not add a port.
	cfg := newTestConfig(t)
	cfg.SetPortTolerance(false)
	cfg.SetHttpsPort(443)
	h := http.StripPrefix("/evilginx", New(cfg))
	req := httptest.NewRequest(http.MethodGet, "/evilginx/phishurl?p=testsite&rid=abc123", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "https://phish.phish.example.com/") {
		t.Errorf("expected generated URL without a port suffix, got: %s", body)
	}
	if strings.Contains(body, "phish.example.com:") {
		t.Errorf("expected no port in URL when tolerance is off, got: %s", body)
	}
}

func TestPhishURLRequiresRid(t *testing.T) {
	h := http.StripPrefix("/evilginx", New(newTestConfig(t)))
	req := httptest.NewRequest(http.MethodGet, "/evilginx/phishurl?p=testsite", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "rid") {
		t.Errorf("expected a helpful error mentioning rid")
	}
}

func TestPhishURLRequiresHostname(t *testing.T) {
	dir := t.TempDir()
	cfg, err := core.NewConfig(dir, "")
	if err != nil {
		t.Fatalf("building test config: %v", err)
	}
	yamlPath := filepath.Join(dir, "testsite.yaml")
	if err := os.WriteFile(yamlPath, []byte(testPhishletYAML), 0o600); err != nil {
		t.Fatalf("writing test phishlet: %v", err)
	}
	pl, err := core.NewPhishlet("testsite", yamlPath, nil, cfg)
	if err != nil {
		t.Fatalf("loading test phishlet: %v", err)
	}
	cfg.AddPhishlet("testsite", pl)

	h := http.StripPrefix("/evilginx", New(cfg))
	req := httptest.NewRequest(http.MethodGet, "/evilginx/phishurl?p=testsite&rid=abc123", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "no hostname configured") {
		t.Errorf("expected a helpful error about the missing hostname")
	}
}

// postForm sends a url-encoded POST to the given panel path.
func postForm(t *testing.T, h http.Handler, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestSettingsUpdatesDomainAndIP(t *testing.T) {
	cfg := newTestConfig(t)
	h := http.StripPrefix("/evilginx", New(cfg))

	rec := postForm(t, h, "/evilginx/domain", url.Values{"action": {"save"}, "domain": {"evil.example"}, "external_ip": {"1.2.3.4"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Server settings updated") {
		t.Errorf("expected a success message")
	}
	if got := cfg.GetBaseDomain(); got != "evil.example" {
		t.Errorf("expected base domain evil.example, got %q", got)
	}
	if got := cfg.GetServerExternalIP(); got != "1.2.3.4" {
		t.Errorf("expected external IP 1.2.3.4, got %q", got)
	}
}

func TestPhishletSetHostname(t *testing.T) {
	cfg := newTestConfig(t)
	h := http.StripPrefix("/evilginx", New(cfg))

	rec := postForm(t, h, "/evilginx/phishlets", url.Values{
		"site":     {"testsite"},
		"action":   {"hostname"},
		"hostname": {"new.example.com"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "new.example.com") {
		t.Errorf("expected the new hostname in the response")
	}
	hostname, ok := cfg.GetSiteDomain("testsite")
	if !ok || hostname != "new.example.com" {
		t.Errorf("expected hostname new.example.com, got %q (ok=%v)", hostname, ok)
	}
}

func TestPhishletEnableDisable(t *testing.T) {
	cfg := newTestConfig(t)
	fired := false
	h := http.StripPrefix("/evilginx", New(cfg, WithOnChange(func() { fired = true })))

	rec := postForm(t, h, "/evilginx/phishlets", url.Values{"site": {"testsite"}, "action": {"disable"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "disabled") {
		t.Errorf("expected a disable confirmation")
	}
	if len(cfg.GetEnabledSites()) != 0 {
		t.Errorf("expected testsite to be disabled")
	}
	if !fired {
		t.Errorf("expected the onChange callback to fire after a mutation")
	}
	fired = false

	rec = postForm(t, h, "/evilginx/phishlets", url.Values{"site": {"testsite"}, "action": {"enable"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	sites := cfg.GetEnabledSites()
	if len(sites) != 1 || sites[0] != "testsite" {
		t.Errorf("expected testsite to be enabled, got %v", sites)
	}
	if !fired {
		t.Errorf("expected the onChange callback to fire after enable")
	}
}

func TestPhishletEnableRequiresHostname(t *testing.T) {
	dir := t.TempDir()
	cfg, err := core.NewConfig(dir, "")
	if err != nil {
		t.Fatalf("building test config: %v", err)
	}
	yamlPath := filepath.Join(dir, "testsite.yaml")
	if err := os.WriteFile(yamlPath, []byte(testPhishletYAML), 0o600); err != nil {
		t.Fatalf("writing test phishlet: %v", err)
	}
	pl, err := core.NewPhishlet("testsite", yamlPath, nil, cfg)
	if err != nil {
		t.Fatalf("loading test phishlet: %v", err)
	}
	cfg.AddPhishlet("testsite", pl)

	h := http.StripPrefix("/evilginx", New(cfg))
	rec := postForm(t, h, "/evilginx/phishlets", url.Values{"site": {"testsite"}, "action": {"enable"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "before enabling") {
		t.Errorf("expected a helpful error when enabling without a hostname")
	}
}

func TestLuresCreateAndDelete(t *testing.T) {
	cfg := newTestConfig(t)
	fired := false
	h := http.StripPrefix("/evilginx", New(cfg, WithOnChange(func() { fired = true })))

	rec := postForm(t, h, "/evilginx/lures", url.Values{
		"phishlet": {"testsite"},
		"path":     {"/lure-a"},
		"hostname": {"links.example.com"},
		"redirect": {"https://real.example/login"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Created lure 0") {
		t.Errorf("expected a create confirmation naming lure 0")
	}
	if !fired {
		t.Errorf("expected the onChange callback to fire after lure creation")
	}
	lures := cfg.GetLures()
	if len(lures) != 1 {
		t.Fatalf("expected 1 lure, got %d", len(lures))
	}
	if lures[0].Phishlet != "testsite" || lures[0].Path != "/lure-a" ||
		lures[0].Hostname != "links.example.com" || lures[0].RedirectUrl != "https://real.example/login" {
		t.Errorf("unexpected lure: %+v", lures[0])
	}

	rec = postForm(t, h, "/evilginx/lures/delete", url.Values{"id": {"0"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	if len(cfg.GetLures()) != 0 {
		t.Errorf("expected the lure to be deleted")
	}
}

func TestLuresCreateDefaultsPath(t *testing.T) {
	cfg := newTestConfig(t)
	h := http.StripPrefix("/evilginx", New(cfg))

	rec := postForm(t, h, "/evilginx/lures", url.Values{"phishlet": {"testsite"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	lures := cfg.GetLures()
	if len(lures) != 1 {
		t.Fatalf("expected 1 lure, got %d", len(lures))
	}
	if !strings.HasPrefix(lures[0].Path, "/") || len(lures[0].Path) < 2 {
		t.Errorf("expected a generated path starting with /, got %q", lures[0].Path)
	}
}

func TestPhishURLWithHostOverride(t *testing.T) {
	cfg := newTestConfig(t)
	h := http.StripPrefix("/evilginx", New(cfg))

	req := httptest.NewRequest(http.MethodGet, "/evilginx/phishurl?p=testsite&path=/lure-a&host=links.example.com&rid=abc123", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "https://links.example.com/lure-a") {
		t.Errorf("expected the host override to be used in the URL, got: %s", body)
	}
}

func TestPhishURLAutoCreatesLure(t *testing.T) {
	cfg := newTestConfig(t)
	fired := false
	h := http.StripPrefix("/evilginx", New(cfg, WithOnChange(func() { fired = true })))

	req := httptest.NewRequest(http.MethodGet, "/evilginx/phishurl?p=testsite&path=/auto&rid=abc123", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	if !fired {
		t.Errorf("expected an onChange callback when a lure is auto-created")
	}
	lures := cfg.GetLures()
	if len(lures) != 1 {
		t.Fatalf("expected 1 auto-created lure, got %d", len(lures))
	}
	if lures[0].Phishlet != "testsite" || lures[0].Path != "/auto" {
		t.Errorf("unexpected auto-created lure: %+v", lures[0])
	}
	if lures[0].Hostname != "" {
		t.Errorf("expected an empty lure hostname (served from the landing phish host), got %q", lures[0].Hostname)
	}
	if !strings.Contains(rec.Body.String(), "Auto-created a lure") {
		t.Errorf("expected a message about the auto-created lure")
	}
}

func TestPhishURLKeepsExistingLure(t *testing.T) {
	cfg := newTestConfig(t)
	fired := false
	h := http.StripPrefix("/evilginx", New(cfg, WithOnChange(func() { fired = true })))

	if rec := postForm(t, h, "/evilginx/lures", url.Values{"phishlet": {"testsite"}, "path": {"/exists"}, "hostname": {"phish.example.com"}}); rec.Code != http.StatusOK {
		t.Fatalf("creating lure: expected %d, got %d", http.StatusOK, rec.Code)
	}
	fired = false

	req := httptest.NewRequest(http.MethodGet, "/evilginx/phishurl?p=testsite&path=/exists&rid=abc123", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	if fired {
		t.Errorf("expected no onChange callback when a matching lure already exists")
	}
	if len(cfg.GetLures()) != 1 {
		t.Errorf("expected the existing lure to be kept, got %d lures", len(cfg.GetLures()))
	}
}

func TestPhishURLDoesNotCreateLureOnError(t *testing.T) {
	cfg := newTestConfig(t)
	h := http.StripPrefix("/evilginx", New(cfg))

	req := httptest.NewRequest(http.MethodGet, "/evilginx/phishurl?p=testsite&path=/nope", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	if len(cfg.GetLures()) != 0 {
		t.Errorf("expected no lure to be created when URL generation fails")
	}
}

func TestLuresPageGetUrlCarriesRid(t *testing.T) {
	cfg := newTestConfig(t)
	h := http.StripPrefix("/evilginx", New(cfg))

	if rec := postForm(t, h, "/evilginx/lures", url.Values{"phishlet": {"testsite"}, "path": {"/lure-a"}}); rec.Code != http.StatusOK {
		t.Fatalf("creating lure: expected %d, got %d", http.StatusOK, rec.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/evilginx/lures", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	body := rec.Body.String()
	idx := strings.Index(body, `phishurl?p=testsite&amp;path=%2flure-a&amp;rid=`)
	if idx < 0 {
		t.Fatalf("expected the get URL link to carry a rid, got: %s", body)
	}
	rest := body[idx+len(`phishurl?p=testsite&amp;path=/lure-a&amp;rid=`):]
	if rest == "" || strings.HasPrefix(rest, `"`) {
		t.Errorf("expected a non-empty rid in the get URL link")
	}
}

// ---------------------------------------------------------------------------
// Spear flow: Target -> Channel -> Prompt -> Review & Launch.
// ---------------------------------------------------------------------------

// spearTestHandler builds a panel handler with enrichment stubbed out.
func spearTestHandler(t *testing.T, runner spearRunnerFunc) *Handler {
	t.Helper()
	hh, ok := New(newTestConfig(t)).(*Handler)
	if !ok {
		t.Fatal("panel New did not return *Handler")
	}
	if runner != nil {
		hh.spearRun = runner
	}
	return hh
}

// enableSpearStub points the handler at a scratch auditor script so the
// wrapper path resolves, without ever executing Python (runner is stubbed).
func enableSpearStub(t *testing.T, hh *Handler) {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"phishlet_harvester.py", "spear_enrich.py"} {
		if err := os.WriteFile(filepath.Join(dir, name),
			[]byte("# stub"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	hh.audit = config.SiteAuditorConfig{
		Enabled: true,
		Python:  "python",
		Script:  filepath.Join(dir, "phishlet_harvester.py"),
		Timeout: 30,
	}
}

func spearFixtureReport() spearReport {
	return spearReport{
		LinkedIn: "https://www.linkedin.com/in/jane-doe",
		Profile: map[string]string{
			"Name": "Jane Doe", "Current_Position": "Engineer",
			"Company": "Acme", "Email": "jane@acme.example",
		},
		Target: map[string]string{
			"first_name": "Jane", "last_name": "Doe",
			"email": "jane@acme.example", "position": "Engineer at Acme",
		},
		Channel:       "mail",
		PromptDefault: "default prompt",
		PromptUsed:    "default prompt",
		Subject:       "Hello Jane",
		Body:          "Hi Jane,\n\nSee {{URL}}\n",
		Generator:     "template",
		Notes:         []string{"note"},
	}
}

func TestSpearPageRendersDisabled(t *testing.T) {
	h := http.StripPrefix("/evilginx", New(newTestConfig(t)))
	req := httptest.NewRequest(http.MethodGet, "/evilginx/spear", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"Spear Phishing", "New Spear Phishing", "without admin API access"} {
		if !strings.Contains(body, want) {
			t.Errorf("response missing %q", want)
		}
	}
}

func TestSpearWizardRendersDisabled(t *testing.T) {
	h := http.StripPrefix("/evilginx", New(newTestConfig(t)))
	req := httptest.NewRequest(http.MethodGet, "/evilginx/spear/new", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"Spear Phishing", "not configured", "spear-steps"} {
		if !strings.Contains(body, want) {
			t.Errorf("response missing %q", want)
		}
	}
}

func TestSpearChannelPreselect(t *testing.T) {
	hh := spearTestHandler(t, nil)
	enableSpearStub(t, hh)
	h := http.StripPrefix("/evilginx", hh)
	req := httptest.NewRequest(http.MethodGet, "/evilginx/spear/new?channel=sms", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `<option value="sms" selected>`) {
		t.Errorf("expected the SMS channel preselected from the query")
	}
}

func TestSpearEnrichValidation(t *testing.T) {
	hh := spearTestHandler(t, nil)
	enableSpearStub(t, hh)
	h := http.StripPrefix("/evilginx", hh)

	rec := postForm(t, h, "/evilginx/spear/enrich",
		url.Values{"linkedin": {""}, "channel": {"mail"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "valid LinkedIn") {
		t.Errorf("expected a LinkedIn validation error")
	}

	rec = postForm(t, h, "/evilginx/spear/enrich",
		url.Values{"linkedin": {"https://example.com/nobody"}, "channel": {"mail"}})
	if !strings.Contains(rec.Body.String(), "valid LinkedIn") {
		t.Errorf("expected a LinkedIn validation error for non-LinkedIn URLs")
	}
}

func TestSpearJobsPolling(t *testing.T) {
	hh := spearTestHandler(t, nil)
	h := http.StripPrefix("/evilginx", hh)
	hh.setSpearJob(&spearJob{id: "job1", kind: "enrich",
		status: "running", created: time.Now()})

	req := httptest.NewRequest(http.MethodGet, "/evilginx/spear/jobs?job=job1", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var st struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.Status != "running" {
		t.Errorf("expected running, got %q", st.Status)
	}

	hh.setSpearJob(&spearJob{id: "job1", kind: "enrich",
		status: "done", report: spearFixtureReport(), created: time.Now()})
	req = httptest.NewRequest(http.MethodGet, "/evilginx/spear/jobs?job=job1", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.Status != "done" {
		t.Errorf("expected done, got %q", st.Status)
	}

	req = httptest.NewRequest(http.MethodGet, "/evilginx/spear/jobs?job=nope", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.Status != "missing" {
		t.Errorf("expected missing, got %q", st.Status)
	}
}

func waitSpearJob(t *testing.T, h http.Handler, id string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		req := httptest.NewRequest(http.MethodGet,
			"/evilginx/spear/jobs?job="+id, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		var st struct {
			Status string `json:"status"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
			t.Fatal(err)
		}
		if st.Status == "done" || st.Status == "error" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("job %s did not finish in time (status %q)", id, st.Status)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestSpearEnrichRunsWithStub(t *testing.T) {
	hh := spearTestHandler(t, nil)
	enableSpearStub(t, hh)
	hh.spearRun = func(ctx context.Context, python, script string,
		args []string) (spearReport, string, error) {
		time.Sleep(50 * time.Millisecond)
		rep := spearFixtureReport()
		rep.Subject, rep.Body = "", ""
		return rep, "", nil
	}
	h := http.StripPrefix("/evilginx", hh)

	rec := postForm(t, h, "/evilginx/spear/enrich",
		url.Values{
			"linkedin": {"https://www.linkedin.com/in/jane-doe"},
			"channel":  {"mail"},
			"sender":   {"Security Team"},
		})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Working on it") {
		t.Errorf("expected the running banner while enriching")
	}
	var jobID string
	for id := range hh.spearJobs {
		jobID = id
	}
	if jobID == "" {
		t.Fatal("expected an enrich job to be created")
	}
	waitSpearJob(t, h, jobID)

	req := httptest.NewRequest(http.MethodGet,
		"/evilginx/spear/new?job="+jobID, nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	body := rec.Body.String()
	for _, want := range []string{"Jane Doe", "default prompt", "Generate message", "spear-steps", "spear-sec-3", "data-goto"} {
		if !strings.Contains(body, want) {
			t.Errorf("enrich result page missing %q", want)
		}
	}
	if strings.Contains(body, "Working on it") {
		t.Errorf("running banner must disappear once enrichment is done")
	}
}

func TestSpearLangPassthrough(t *testing.T) {
	var gotArgs []string
	hh := spearTestHandler(t, nil)
	enableSpearStub(t, hh)
	hh.spearRun = func(ctx context.Context, python, script string,
		args []string) (spearReport, string, error) {
		gotArgs = append([]string{}, args...)
		rep := spearFixtureReport()
		rep.Subject, rep.Body = "", ""
		return rep, "", nil
	}
	h := http.StripPrefix("/evilginx", hh)

	rec := postForm(t, h, "/evilginx/spear/enrich",
		url.Values{"linkedin": {"https://www.linkedin.com/in/jane-doe"},
			"channel": {"sms"}, "lang": {"ar"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	var jobID string
	for id, j := range hh.spearJobs {
		jobID = id
		if j.lang != "ar" {
			t.Errorf("expected job lang ar, got %q", j.lang)
		}
	}
	waitSpearJob(t, h, jobID)
	found := false
	for i := 0; i < len(gotArgs)-1; i++ {
		if gotArgs[i] == "--lang" && gotArgs[i+1] == "ar" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected --lang ar passed to the runner, got %v", gotArgs)
	}
	req := httptest.NewRequest(http.MethodGet, "/evilginx/spear/new?job="+jobID, nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	body := rec.Body.String()
	for _, want := range []string{`<option value="ar" selected>`, `id="spear_lang_wrap"`} {
		if !strings.Contains(body, want) {
			t.Errorf("result page missing %q", want)
		}
	}

	rec = postForm(t, h, "/evilginx/spear/enrich",
		url.Values{"linkedin": {"https://www.linkedin.com/in/jane-doe"},
			"channel": {"sms"}, "lang": {"xx"}})
	for _, j := range hh.spearJobs {
		if j.id != jobID && j.lang != "en" {
			t.Errorf("expected invalid lang to default to en, got %q", j.lang)
		}
	}
}

func TestSpearGenerateNeedsEnrich(t *testing.T) {
	hh := spearTestHandler(t, nil)
	enableSpearStub(t, hh)
	h := http.StripPrefix("/evilginx", hh)

	rec := postForm(t, h, "/evilginx/spear/generate",
		url.Values{"job": {"nope"}, "prompt": {"hello"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "finished enrichment") {
		t.Errorf("expected a generate precondition error")
	}
}

// spearAPIStub records platform API calls and returns canned objects.
type spearAPIStub struct {
	t     *testing.T
	calls []struct {
		method string
		path   string
		body   string
	}
}

func (s *spearAPIStub) handler() http.Handler {
	mux := http.NewServeMux()
	record := func(w http.ResponseWriter, r *http.Request, code int, resp string) {
		raw, _ := io.ReadAll(r.Body)
		s.calls = append(s.calls, struct {
			method string
			path   string
			body   string
		}{r.Method, r.URL.Path, string(raw)})
		w.WriteHeader(code)
		_, _ = w.Write([]byte(resp))
	}
	mux.HandleFunc("/api/smtp/", func(w http.ResponseWriter, r *http.Request) {
		record(w, r, http.StatusOK, `[{"name":"Relay"}]`)
	})
	mux.HandleFunc("/api/sms/", func(w http.ResponseWriter, r *http.Request) {
		record(w, r, http.StatusOK, `[{"name":"Twilio"}]`)
	})
	mux.HandleFunc("/api/groups/", func(w http.ResponseWriter, r *http.Request) {
		record(w, r, http.StatusCreated, `{"id":7,"name":"Spear - Jane Doe"}`)
	})
	mux.HandleFunc("/api/templates/", func(w http.ResponseWriter, r *http.Request) {
		record(w, r, http.StatusCreated, `{"id":8,"name":"Spear - Jane Doe"}`)
	})
	mux.HandleFunc("/api/campaigns/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			record(w, r, http.StatusOK, `[
				{"id":1,"name":"Spear - A","created_date":"2026-09-18T10:00:00Z","status":"In progress","smtp":{"id":5},"sms":{"id":0}},
				{"id":2,"name":"Bulk Mail","created_date":"2026-09-17T10:00:00Z","status":"In progress","smtp":{"id":5},"sms":{"id":0}},
				{"id":3,"name":"Spear - B","created_date":"2026-09-16T10:00:00Z","status":"Completed","smtp":{"id":0},"sms":{"id":6}}
			]`)
			return
		}
		record(w, r, http.StatusCreated, `{"id":9,"name":"Spear Test"}`)
	})
	mux.HandleFunc("/api/sms_campaigns/", func(w http.ResponseWriter, r *http.Request) {
		record(w, r, http.StatusCreated, `{"id":10,"name":"Spear SMS"}`)
	})
	return mux
}

func (s *spearAPIStub) find(method, path string) string {
	for _, c := range s.calls {
		if c.method == method && c.path == path {
			return c.body
		}
	}
	return ""
}

func TestSpearProfileEdit(t *testing.T) {
	hh := spearTestHandler(t, nil)
	enableSpearStub(t, hh)
	// Blank captured profile (dead provider) + a stale generate result.
	rep := spearFixtureReport()
	rep.Profile = map[string]string{}
	rep.Target = map[string]string{}
	hh.setSpearJob(&spearJob{id: "e9", kind: "enrich",
		status: "done", report: rep, created: time.Now()})
	hh.setSpearJob(&spearJob{id: "g9", kind: "generate", reportID: "e9",
		status: "done", report: spearFixtureReport(), created: time.Now()})
	h := http.StripPrefix("/evilginx", hh)

	rec := postForm(t, h, "/evilginx/spear/profile",
		url.Values{"job": {"e9"}, "name": {"Omar Sherif"},
			"position": {"Analyst"}, "company": {"Acme"},
			"location": {"Cairo"}, "industry": {"Tech"},
			"email": {"omar@example.com"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Profile updated") {
		t.Errorf("expected a save confirmation, got: %.500s", body)
	}
	ej := hh.getSpearJob("e9")
	if ej == nil {
		t.Fatal("enrich job disappeared")
	}
	for k, want := range map[string]string{
		"Name": "Omar Sherif", "Company": "Acme", "Email": "omar@example.com",
	} {
		if ej.report.Profile[k] != want {
			t.Errorf("profile %s = %q, want %q", k, ej.report.Profile[k], want)
		}
	}
	for k, want := range map[string]string{
		"first_name": "Omar", "last_name": "Sherif",
		"email": "omar@example.com", "position": "Analyst at Acme",
	} {
		if ej.report.Target[k] != want {
			t.Errorf("target %s = %q, want %q", k, ej.report.Target[k], want)
		}
	}
	if hh.getSpearJob("g9") != nil {
		t.Errorf("stale generate job must be dropped after a profile edit")
	}
	if !strings.Contains(body, "Omar Sherif") {
		t.Errorf("expected the updated profile rendered back")
	}
}

func TestSpearListFiltersAndSplits(t *testing.T) {
	stub := &spearAPIStub{t: t}
	srv := httptest.NewServer(stub.handler())
	defer srv.Close()

	hh := spearTestHandler(t, nil)
	hh.apiBase = srv.URL
	hh.apiKeyFunc = func() (string, error) { return "test-key", nil }
	h := http.StripPrefix("/evilginx", hh)

	req := httptest.NewRequest(http.MethodGet, "/evilginx/spear", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"New Spear Phishing", "Spear - A", "Spear - B",
		"/campaigns/1", "/sms_campaigns/3",
		"Active Campaigns", "Archived Campaigns",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("list page missing %q", want)
		}
	}
	if strings.Contains(body, "Bulk Mail") {
		t.Errorf("non-spear campaigns must be filtered out")
	}
}

func TestSpearLaunchPrefixesName(t *testing.T) {
	stub := &spearAPIStub{t: t}
	srv := httptest.NewServer(stub.handler())
	defer srv.Close()

	hh := spearTestHandler(t, nil)
	enableSpearStub(t, hh)
	hh.apiBase = srv.URL
	hh.apiKeyFunc = func() (string, error) { return "test-key", nil }
	hh.setSpearJob(&spearJob{id: "gen1", kind: "generate",
		status: "done", report: spearFixtureReport(), created: time.Now()})
	h := http.StripPrefix("/evilginx", hh)

	rec := postForm(t, h, "/evilginx/spear/launch",
		url.Values{"job": {"gen1"}, "campaign": {"Q3 Finance"},
			"url": {"https://login.example.com/x"}, "profile": {"Relay"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	campBody := stub.find("POST", "/api/campaigns/")
	if !strings.Contains(campBody, `"name":"Spear - Q3 Finance"`) {
		t.Errorf("expected the campaign name auto-prefixed, got: %s", campBody)
	}
}

func TestSpearLaunchValidation(t *testing.T) {
	hh := spearTestHandler(t, nil)
	enableSpearStub(t, hh)
	hh.setSpearJob(&spearJob{id: "gen1", kind: "generate",
		status: "done", report: spearFixtureReport(), created: time.Now()})
	h := http.StripPrefix("/evilginx", hh)

	rec := postForm(t, h, "/evilginx/spear/launch",
		url.Values{"job": {"gen1"}, "campaign": {""},
			"url":     {"https://login.example.com/x"},
			"profile": {"Relay"}})
	if !strings.Contains(rec.Body.String(), "Give the campaign a name") {
		t.Errorf("expected a campaign-name validation error")
	}

	smsRep := spearFixtureReport()
	smsRep.Channel = "sms"
	hh.setSpearJob(&spearJob{id: "gen2", kind: "generate",
		status: "done", report: smsRep, created: time.Now()})
	rec = postForm(t, h, "/evilginx/spear/launch",
		url.Values{"job": {"gen2"}, "campaign": {"Spear SMS"},
			"url": {"https://login.example.com/x"}, "profile": {"Twilio"}})
	if !strings.Contains(rec.Body.String(), "phone number") {
		t.Errorf("expected a phone validation error for SMS")
	}
}

func TestSpearLaunchSuccess(t *testing.T) {
	stub := &spearAPIStub{t: t}
	srv := httptest.NewServer(stub.handler())
	defer srv.Close()

	hh := spearTestHandler(t, nil)
	enableSpearStub(t, hh)
	hh.apiBase = srv.URL
	hh.apiKeyFunc = func() (string, error) { return "test-key", nil }
	hh.setSpearJob(&spearJob{id: "gen1", kind: "generate",
		status: "done", report: spearFixtureReport(), created: time.Now()})
	h := http.StripPrefix("/evilginx", hh)

	rec := postForm(t, h, "/evilginx/spear/launch",
		url.Values{"job": {"gen1"}, "campaign": {"Spear Test"},
			"url": {"https://login.example.com/x"}, "profile": {"Relay"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "/campaigns/9") {
		t.Errorf("expected a link to the launched campaign, got: %.500s", body)
	}
	groupBody := stub.find("POST", "/api/groups/")
	for _, want := range []string{"Spear - Jane Doe", "jane@acme.example", "Jane", "Engineer at Acme"} {
		if !strings.Contains(groupBody, want) {
			t.Errorf("group payload missing %q: %s", want, groupBody)
		}
	}
	tplBody := stub.find("POST", "/api/templates/")
	for _, want := range []string{"Hello Jane", "{{.URL}}"} {
		if !strings.Contains(tplBody, want) {
			t.Errorf("template payload missing %q: %s", want, tplBody)
		}
	}
	campBody := stub.find("POST", "/api/campaigns/")
	for _, want := range []string{"Spear Test", "Relay", "Spear - Jane Doe", "launch_date"} {
		if !strings.Contains(campBody, want) {
			t.Errorf("campaign payload missing %q: %s", want, campBody)
		}
	}
}

func TestSpearLaunchSMSSuccess(t *testing.T) {
	stub := &spearAPIStub{t: t}
	srv := httptest.NewServer(stub.handler())
	defer srv.Close()

	hh := spearTestHandler(t, nil)
	enableSpearStub(t, hh)
	hh.apiBase = srv.URL
	hh.apiKeyFunc = func() (string, error) { return "test-key", nil }
	rep := spearFixtureReport()
	rep.Channel = "sms"
	hh.setSpearJob(&spearJob{id: "gen2", kind: "generate",
		status: "done", report: rep, created: time.Now()})
	h := http.StripPrefix("/evilginx", hh)

	rec := postForm(t, h, "/evilginx/spear/launch",
		url.Values{"job": {"gen2"}, "campaign": {"Spear SMS"},
			"url": {"https://login.example.com/x"}, "profile": {"Twilio"},
			"phone": {"+12025550134"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "/sms_campaigns/10") {
		t.Errorf("expected a link to the launched SMS campaign, got: %.500s", body)
	}
	groupBody := stub.find("POST", "/api/groups/")
	if !strings.Contains(groupBody, "+12025550134") {
		t.Errorf("expected the phone in the group payload: %s", groupBody)
	}
	campBody := stub.find("POST", "/api/sms_campaigns/")
	if !strings.Contains(campBody, "Twilio") {
		t.Errorf("expected the SMS profile in the campaign payload: %s", campBody)
	}
}

func TestSpearRefinePromptPreservesVars(t *testing.T) {
	rep := spearFixtureReport()
	rep.Subject = "Hello {{.FirstName}}"
	rep.Body = "Hi {{.FirstName}},\n\nSee {{URL}}\n"
	p := spearRefinePrompt(rep, "mail", "make it shorter")
	for _, want := range []string{
		"make it shorter", "Hello {{.FirstName}}", "{{URL}}",
		"{{.FirstName}}", "SUBJECT:",
	} {
		if !strings.Contains(p, want) {
			t.Errorf("refine prompt missing %q: %.500s", want, p)
		}
	}
	sms := spearRefinePrompt(rep, "sms", "translate to Arabic")
	for _, want := range []string{"300", "{{URL}}", "translate to Arabic"} {
		if !strings.Contains(sms, want) {
			t.Errorf("sms refine prompt missing %q: %.500s", want, sms)
		}
	}
}

func TestSpearRefineNeedsMessage(t *testing.T) {
	hh := spearTestHandler(t, nil)
	enableSpearStub(t, hh)
	h := http.StripPrefix("/evilginx", hh)

	rec := postForm(t, h, "/evilginx/spear/refine",
		url.Values{"job": {"nope"}, "instruction": {"shorter"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "finished message") {
		t.Errorf("expected a refine precondition error")
	}
}

func TestSpearRefineEmptyInstruction(t *testing.T) {
	hh := spearTestHandler(t, nil)
	enableSpearStub(t, hh)
	hh.setSpearJob(&spearJob{id: "gen1", kind: "generate",
		status: "done", report: spearFixtureReport(), created: time.Now()})
	h := http.StripPrefix("/evilginx", hh)

	rec := postForm(t, h, "/evilginx/spear/refine",
		url.Values{"job": {"gen1"}, "instruction": {"  "}})
	if !strings.Contains(rec.Body.String(), "Write what the LLM should change") {
		t.Errorf("expected an empty-instruction error")
	}
	if len(hh.spearJobs) != 1 {
		t.Errorf("empty instruction must not create a job, have %d", len(hh.spearJobs))
	}
}

func TestSpearRefineRunsRunner(t *testing.T) {
	var gotPrompt string
	runner := func(ctx context.Context, python, script string,
		args []string) (spearReport, string, error) {
		for i, a := range args {
			if a == "--prompt-file" && i+1 < len(args) {
				raw, err := os.ReadFile(args[i+1])
				if err != nil {
					t.Errorf("could not read staged prompt: %v", err)
				}
				gotPrompt = string(raw)
			}
		}
		rep := spearFixtureReport()
		rep.Subject = "Shorter hello"
		rep.Body = "Hi Jane, quick check: {{URL}}"
		rep.Generator = "groq"
		return rep, "", nil
	}
	hh := spearTestHandler(t, runner)
	enableSpearStub(t, hh)
	hh.setSpearJob(&spearJob{id: "e1", kind: "enrich",
		status: "done", report: spearFixtureReport(), created: time.Now()})
	hh.setSpearJob(&spearJob{id: "gen1", kind: "generate", reportID: "e1",
		status: "done", report: spearFixtureReport(), created: time.Now()})
	h := http.StripPrefix("/evilginx", hh)

	rec := postForm(t, h, "/evilginx/spear/refine",
		url.Values{"job": {"gen1"}, "instruction": {"make it shorter"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Working on it") {
		t.Errorf("expected the running banner, got: %.300s", rec.Body.String())
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		done := false
		for _, j := range hh.spearJobs {
			if j.kind == "generate" && j.status == "done" &&
				j.report.Generator == "groq" && j.report.Subject == "Shorter hello" {
				done = true
			}
		}
		if done || time.Now().After(deadline) {
			if !done {
				t.Fatal("refined job never finished")
			}
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !strings.Contains(gotPrompt, "make it shorter") {
		t.Errorf("runner prompt missing the instruction: %.300s", gotPrompt)
	}
	if !strings.Contains(gotPrompt, "Hello Jane") {
		t.Errorf("runner prompt missing the current message: %.300s", gotPrompt)
	}
}

func TestSpearPicksHiddenForSMS(t *testing.T) {
	hh := spearTestHandler(t, nil)
	enableSpearStub(t, hh)
	rep := spearFixtureReport()
	rep.Channel = "sms"
	hh.setSpearJob(&spearJob{id: "e1", kind: "enrich", channel: "sms",
		status: "done", report: rep, created: time.Now()})
	h := http.StripPrefix("/evilginx", hh)

	req := httptest.NewRequest(http.MethodGet, "/evilginx/spear/new?job=e1", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	if strings.Contains(rec.Body.String(), "Suggested branded templates") {
		t.Errorf("mail-only library picker must stay hidden on the SMS channel")
	}
}

func TestSpearGenerateStaysOnStep3(t *testing.T) {
	hh := spearTestHandler(t, nil)
	enableSpearStub(t, hh)
	hh.setSpearJob(&spearJob{id: "e1", kind: "enrich",
		status: "done", report: spearFixtureReport(), created: time.Now()})
	h := http.StripPrefix("/evilginx", hh)

	rec := postForm(t, h, "/evilginx/spear/generate",
		url.Values{"job": {"e1"}, "prompt": {"my custom prompt"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	body := rec.Body.String()
	// Must stay on step 3 with context instead of flashing back to step 1.
	if !strings.Contains(body, "init = 'spear-sec-3'") {
		t.Errorf("expected the page pinned to step 3 while running")
	}
	if !strings.Contains(body, "my custom prompt") {
		t.Errorf("expected the submitted prompt preserved, got: %.500s", body)
	}
	if !strings.Contains(body, "Working on the message") {
		t.Errorf("expected an inline progress banner on step 3")
	}
	// Pills must not collapse: profile stays done.
	if !strings.Contains(body, "spear-step done") {
		t.Errorf("expected progress pills preserved during run")
	}
}

func TestSpearRefineStaysOnStep3(t *testing.T) {
	hh := spearTestHandler(t, nil)
	enableSpearStub(t, hh)
	hh.setSpearJob(&spearJob{id: "gen1", kind: "generate",
		status: "done", report: spearFixtureReport(), created: time.Now()})
	h := http.StripPrefix("/evilginx", hh)

	rec := postForm(t, h, "/evilginx/spear/refine",
		url.Values{"job": {"gen1"}, "instruction": {"shorter"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "init = 'spear-sec-3'") {
		t.Errorf("expected the page pinned to step 3 while refining")
	}
	// Old finished message must stay visible (no flash to step 1).
	if !strings.Contains(body, "Hello Jane") {
		t.Errorf("expected the previous result preserved during refine, got: %.500s", body)
	}
}

func TestSpearLaunchWarnsMissingEmail(t *testing.T) {
	hh := spearTestHandler(t, nil)
	enableSpearStub(t, hh)
	rep := spearFixtureReport()
	rep.Target["email"] = ""
	hh.setSpearJob(&spearJob{id: "gen1", kind: "generate",
		status: "done", report: rep, created: time.Now()})
	h := http.StripPrefix("/evilginx", hh)

	req := httptest.NewRequest(http.MethodGet, "/evilginx/spear/new?job=gen1", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "add it in step 2") {
		t.Errorf("expected an early missing-email warning on the launch step")
	}
}

func TestSpearMessageSave(t *testing.T) {
	hh := spearTestHandler(t, nil)
	enableSpearStub(t, hh)
	hh.setSpearJob(&spearJob{id: "gen1", kind: "generate",
		status: "done", report: spearFixtureReport(), created: time.Now()})
	h := http.StripPrefix("/evilginx", hh)

	rec := postForm(t, h, "/evilginx/spear/message",
		url.Values{"job": {"gen1"}, "subject": {"New subject"},
			"body": {"Hi Jane,\n\nEdited {{URL}}\n"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Message updated") {
		t.Errorf("expected a save confirmation, got: %.500s", rec.Body.String())
	}
	got := hh.getSpearJob("gen1")
	if got.report.Subject != "New subject" || !strings.Contains(got.report.Body, "Edited {{URL}}") {
		t.Errorf("job report not updated: %+v", got.report)
	}
	if !strings.Contains(rec.Body.String(), `value="New subject"`) {
		t.Errorf("expected the edited subject rendered back in the form")
	}
}

func TestSpearMessageSaveValidation(t *testing.T) {
	hh := spearTestHandler(t, nil)
	enableSpearStub(t, hh)
	hh.setSpearJob(&spearJob{id: "gen1", kind: "generate",
		status: "done", report: spearFixtureReport(), created: time.Now()})
	h := http.StripPrefix("/evilginx", hh)

	rec := postForm(t, h, "/evilginx/spear/message",
		url.Values{"job": {"gen1"}, "subject": {"S"}, "body": {"no link here"}})
	if !strings.Contains(rec.Body.String(), "{{URL}}") {
		t.Errorf("expected a missing-placeholder error, got: %.300s", rec.Body.String())
	}
	rec = postForm(t, h, "/evilginx/spear/message",
		url.Values{"job": {"gen1"}, "subject": {"  "}, "body": {"Hi {{URL}}"}})
	if !strings.Contains(rec.Body.String(), "Subject is empty") {
		t.Errorf("expected an empty-subject error, got: %.300s", rec.Body.String())
	}
	rec = postForm(t, h, "/evilginx/spear/message",
		url.Values{"job": {"nope"}, "subject": {"S"}, "body": {"Hi {{URL}}"}})
	if !strings.Contains(rec.Body.String(), "finished message") {
		t.Errorf("expected a precondition error, got: %.300s", rec.Body.String())
	}
	// Failed saves must not touch the stored message.
	if got := hh.getSpearJob("gen1"); got.report.Subject != "Hello Jane" {
		t.Errorf("failed save mutated the report: %+v", got.report)
	}
}

func TestSpearMessageSaveClearsLibraryHTML(t *testing.T) {
	hh := spearTestHandler(t, nil)
	enableSpearStub(t, hh)
	rep := spearFixtureReport()
	rep.HTML = "<html>branded</html>"
	hh.setSpearJob(&spearJob{id: "gen1", kind: "generate",
		status: "done", report: rep, created: time.Now()})
	h := http.StripPrefix("/evilginx", hh)

	rec := postForm(t, h, "/evilginx/spear/message",
		url.Values{"job": {"gen1"}, "subject": {"S"}, "body": {"Hi {{URL}}"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	got := hh.getSpearJob("gen1")
	if got.report.HTML != "" {
		t.Errorf("hand edit must drop stale branded HTML")
	}
	found := false
	for _, n := range got.report.Notes {
		if strings.Contains(n, "branded library layout") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a layout-replaced note, got: %v", got.report.Notes)
	}
}

func TestSpearLaunchBlocksDeadAssets(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer dead.Close()
	stub := &spearAPIStub{t: t}
	srv := httptest.NewServer(stub.handler())
	defer srv.Close()

	hh := spearTestHandler(t, nil)
	enableSpearStub(t, hh)
	hh.apiBase = srv.URL
	hh.apiKeyFunc = func() (string, error) { return "test-key", nil }
	rep := spearFixtureReport()
	rep.HTML = `<html><body><img src="` + dead.URL + `/logo.png">{{.URL}}{{.Tracker}}</body></html>`
	hh.setSpearJob(&spearJob{id: "gen1", kind: "generate",
		status: "done", report: rep, created: time.Now()})
	h := http.StripPrefix("/evilginx", hh)

	rec := postForm(t, h, "/evilginx/spear/launch",
		url.Values{"job": {"gen1"}, "campaign": {"Bad Assets"},
			"url": {"https://login.example.com/x"}, "profile": {"Relay"}})
	body := rec.Body.String()
	if !strings.Contains(body, "Pre-launch check failed") || !strings.Contains(body, "dead template assets") {
		t.Errorf("expected a dead-asset block, got: %.500s", body)
	}
	if got := stub.find("POST", "/api/groups/"); got != "" {
		t.Errorf("blocked launch must not create a group, got: %s", got)
	}
}

func TestSpearLaunchAllowsHealthyAssets(t *testing.T) {
	alive := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte{0x89, 0x50, 0x4e, 0x47})
	}))
	defer alive.Close()
	stub := &spearAPIStub{t: t}
	srv := httptest.NewServer(stub.handler())
	defer srv.Close()

	hh := spearTestHandler(t, nil)
	enableSpearStub(t, hh)
	hh.apiBase = srv.URL
	hh.apiKeyFunc = func() (string, error) { return "test-key", nil }
	rep := spearFixtureReport()
	rep.HTML = `<html><body><img src="` + alive.URL + `/logo.png">{{.URL}}{{.Tracker}}</body></html>`
	hh.setSpearJob(&spearJob{id: "gen1", kind: "generate",
		status: "done", report: rep, created: time.Now()})
	h := http.StripPrefix("/evilginx", hh)

	rec := postForm(t, h, "/evilginx/spear/launch",
		url.Values{"job": {"gen1"}, "campaign": {"Good Assets"},
			"url": {"https://login.example.com/x"}, "profile": {"Relay"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	if tpl := stub.find("POST", "/api/templates/"); !strings.Contains(tpl, alive.URL+"/logo.png") {
		t.Errorf("expected the logo URL in the template payload: %.300s", tpl)
	}
}

func TestSpearLaunchRequiresTracker(t *testing.T) {
	stub := &spearAPIStub{t: t}
	srv := httptest.NewServer(stub.handler())
	defer srv.Close()

	hh := spearTestHandler(t, nil)
	enableSpearStub(t, hh)
	hh.apiBase = srv.URL
	hh.apiKeyFunc = func() (string, error) { return "test-key", nil }
	rep := spearFixtureReport()
	rep.HTML = `<html><body>No tracker here {{.URL}}</body></html>`
	hh.setSpearJob(&spearJob{id: "gen1", kind: "generate",
		status: "done", report: rep, created: time.Now()})
	h := http.StripPrefix("/evilginx", hh)

	rec := postForm(t, h, "/evilginx/spear/launch",
		url.Values{"job": {"gen1"}, "campaign": {"No Tracker"},
			"url": {"https://login.example.com/x"}, "profile": {"Relay"}})
	if !strings.Contains(rec.Body.String(), "{{.Tracker}}") {
		t.Errorf("expected a missing-tracker block, got: %.300s", rec.Body.String())
	}
	if got := stub.find("POST", "/api/groups/"); got != "" {
		t.Errorf("blocked launch must not create a group, got: %s", got)
	}
}

func TestSpearEnrichPassesRefresh(t *testing.T) {
	var mu sync.Mutex
	var calls [][]string
	runner := func(ctx context.Context, python, script string,
		args []string) (spearReport, string, error) {
		mu.Lock()
		calls = append(calls, args)
		mu.Unlock()
		return spearFixtureReport(), "", nil
	}
	nCalls := func() int {
		mu.Lock()
		defer mu.Unlock()
		return len(calls)
	}
	has := func(args []string, flag string) bool {
		for _, a := range args {
			if a == flag {
				return true
			}
		}
		return false
	}
	at := func(i int) []string {
		mu.Lock()
		defer mu.Unlock()
		return calls[i]
	}
	waitFor := func(n int) bool {
		deadline := time.Now().Add(10 * time.Second)
		for nCalls() < n {
			if time.Now().After(deadline) {
				return false
			}
			time.Sleep(50 * time.Millisecond)
		}
		return true
	}

	hh := spearTestHandler(t, runner)
	enableSpearStub(t, hh)
	h := http.StripPrefix("/evilginx", hh)
	rec := postForm(t, h, "/evilginx/spear/enrich",
		url.Values{"linkedin": {"https://www.linkedin.com/in/jane-doe"},
			"channel": {"mail"}, "refresh": {"1"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	if !waitFor(1) {
		t.Fatal("runner never invoked")
	}
	if !has(at(0), "--refresh") {
		t.Errorf("expected --refresh in runner args: %v", at(0))
	}

	// Without the checkbox the flag must stay out (quota-saving default).
	hh2 := spearTestHandler(t, runner)
	enableSpearStub(t, hh2)
	h2 := http.StripPrefix("/evilginx", hh2)
	postForm(t, h2, "/evilginx/spear/enrich",
		url.Values{"linkedin": {"https://www.linkedin.com/in/jane-doe"},
			"channel": {"mail"}})
	if !waitFor(2) {
		t.Fatal("second runner never invoked")
	}
	if has(at(1), "--refresh") {
		t.Errorf("unexpected --refresh without the checkbox: %v", at(1))
	}
}

func TestSpearLibraryAllGrouped(t *testing.T) {
	if _, ok := spearLibraryRoot(); !ok {
		t.Skip("template library absent")
	}
	rep := spearFixtureReport()
	all, err := spearLibraryAll(rep.Profile, rep.Target)
	if err != nil {
		t.Fatalf("library error: %v", err)
	}
	if len(all) < 4 {
		t.Fatalf("expected the full library, got %d", len(all))
	}
	groups := spearLibGroups(all, nil)
	if len(groups) == 0 {
		t.Fatal("expected optgroups")
	}
	wantOrder := []string{"Jobs & hiring", "Finance & billing", "Courses & labs", "General"}
	seen := map[string]bool{}
	last := -1
	for _, g := range groups {
		idx := -1
		for i, w := range wantOrder {
			if g.Title == w {
				idx = i
			}
		}
		if idx < 0 {
			t.Errorf("unexpected group %q", g.Title)
			continue
		}
		if seen[g.Title] {
			t.Errorf("duplicate group %q", g.Title)
		}
		seen[g.Title] = true
		if idx < last {
			t.Errorf("groups out of order at %q", g.Title)
		}
		last = idx
		for _, it := range g.Items {
			if it.Brand == "" || it.Option == "" {
				t.Errorf("group item missing brand/option label")
				break
			}
		}
	}
	// Every top pick must exist in the full list (same scoring source).
	picks, err := spearPicksFor(rep.Profile, rep.Target)
	if err != nil || len(picks) == 0 {
		t.Fatalf("picks error: %v", err)
	}
	brands := map[string]bool{}
	for _, p := range all {
		brands[p.Brand] = true
	}
	for _, p := range picks {
		if !brands[p.Brand] {
			t.Errorf("top pick %q missing from the full list", p.Brand)
		}
	}
	if len(all) < len(picks) {
		t.Errorf("full list smaller than the top picks")
	}
}

func TestSpearFullListRenders(t *testing.T) {
	if _, ok := spearLibraryRoot(); !ok {
		t.Skip("template library absent")
	}
	hh := spearTestHandler(t, nil)
	enableSpearStub(t, hh)
	hh.setSpearJob(&spearJob{id: "e1", kind: "enrich",
		status: "done", report: spearFixtureReport(), created: time.Now()})
	h := http.StripPrefix("/evilginx", hh)

	req := httptest.NewRequest(http.MethodGet, "/evilginx/spear/new?job=e1", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Or browse the full library") {
		t.Errorf("expected the full-library dropdown")
	}
	if !strings.Contains(body, "All templates (") {
		t.Errorf("expected the template count on the dropdown label")
	}
	if !strings.Contains(body, "<optgroup") || !strings.Contains(body, "Use selected") {
		t.Errorf("expected grouped options with a use button")
	}
}

func TestSpearWizardAccordionMarkup(t *testing.T) {
	hh := spearTestHandler(t, nil)
	enableSpearStub(t, hh)
	hh.setSpearJob(&spearJob{id: "gen1", kind: "generate",
		status: "done", report: spearFixtureReport(), created: time.Now()})
	h := http.StripPrefix("/evilginx", hh)

	req := httptest.NewRequest(http.MethodGet, "/evilginx/spear/new?job=gen1", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	body := rec.Body.String()
	// Modal shell (frontend-only contract).
	for _, want := range []string{
		`class="spm-overlay"`, `class="spm-modal"`, `role="dialog"`,
		`aria-modal="true"`, `class="spm-close"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("wizard missing modal markup %q", want)
		}
	}
	// Four accordion items, heads wired to bodies.
	for _, sec := range []string{"spear-sec-1", "spear-sec-2", "spear-sec-3", "spear-sec-4"} {
		if !strings.Contains(body, `data-acc="`+sec+`"`) {
			t.Errorf("missing accordion item %s", sec)
		}
		if !strings.Contains(body, `data-acc-head="`+sec+`"`) {
			t.Errorf("missing accordion header %s", sec)
		}
		if !strings.Contains(body, `id="`+sec+`"`) {
			t.Errorf("missing accordion body id %s", sec)
		}
	}
	// Next chain 1->2->3->4, nothing else submits it.
	if n := strings.Count(body, "data-acc-next="); n != 3 {
		t.Errorf("expected 3 Next buttons, got %d", n)
	}
	for _, want := range []string{
		`data-acc-next="spear-sec-2"`, `data-acc-next="spear-sec-3"`,
		`data-acc-next="spear-sec-4"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing progression %s", want)
		}
	}
	// Old flat layout must be gone; backend bindings intact.
	if strings.Contains(body, `<section class="spear-sec"`) {
		t.Errorf("flat multi-step sections must be replaced by the accordion")
	}
	for _, want := range []string{
		`action="/evilginx/spear/enrich"`, `action="/evilginx/spear/profile"`,
		`action="/evilginx/spear/generate"`, `action="/evilginx/spear/launch"`,
		`name="csrf_token"`, `name="job"`, `spear-steps`, `data-goto`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("wizard lost binding/markup %q", want)
		}
	}
}

func TestSpearSigRefreshStartAndReuse(t *testing.T) {
	hh := spearTestHandler(t, nil)
	enableSpearStub(t, hh)
	called := 0
	hh.sigRun = func(ctx context.Context, python, dir string, accounts int) (int, int, int, string, error) {
		called++
		time.Sleep(500 * time.Millisecond)
		return 10, 12, 100, "", nil
	}
	hh.setSpearJob(&spearJob{id: "e1", kind: "enrich",
		status: "done", report: spearFixtureReport(), created: time.Now()})
	h := http.StripPrefix("/evilginx", hh)

	rec := postForm(t, h, "/evilginx/spear/signatures/refresh",
		url.Values{"job": {"e1"}, "accounts": {"9"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	if len(hh.sigJobs) != 1 {
		t.Fatalf("expected 1 refresh job, have %d", len(hh.sigJobs))
	}
	var id string
	var accounts int
	for k, j := range hh.sigJobs {
		id, accounts = k, j.accounts
	}
	if accounts != 5 {
		t.Errorf("accounts must clamp to 5, got %d", accounts)
	}
	if !strings.Contains(rec.Body.String(), id) {
		t.Errorf("expected the job id rendered for polling")
	}
	// Second POST while running must reuse, not duplicate.
	rec = postForm(t, h, "/evilginx/spear/signatures/refresh",
		url.Values{"accounts": {"1"}})
	if len(hh.sigJobs) != 1 {
		t.Fatalf("single-flight broken: %d jobs", len(hh.sigJobs))
	}
	if !strings.Contains(rec.Body.String(), "already running") {
		t.Errorf("expected an already-running note")
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		hh.sigMu.Lock()
		done := hh.sigJobs[id].status == "done"
		hh.sigMu.Unlock()
		if done {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if called != 1 {
		t.Errorf("runner must run exactly once, ran %d", called)
	}
}

func TestSpearSigStatus(t *testing.T) {
	hh := spearTestHandler(t, nil)
	h := http.StripPrefix("/evilginx", hh)

	req := httptest.NewRequest(http.MethodGet, "/evilginx/spear/signatures/status?job=nope", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), `"status":"missing"`) {
		t.Errorf("expected missing status, got: %.200s", rec.Body.String())
	}

	hh.sigJobs["s1"] = &sigRefreshJob{id: "s1", accounts: 2, status: "done",
		sigBefore: 10, sigAfter: 13, templates: 100, created: time.Now()}
	req = httptest.NewRequest(http.MethodGet, "/evilginx/spear/signatures/status?job=s1", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	for _, want := range []string{`"status":"done"`, `"sig_new":3`, `"templates":100`} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("status missing %s: %.300s", want, rec.Body.String())
		}
	}
}

func TestSpearSigDoneRenders(t *testing.T) {
	hh := spearTestHandler(t, nil)
	enableSpearStub(t, hh)
	hh.setSpearJob(&spearJob{id: "e1", kind: "enrich",
		status: "done", report: spearFixtureReport(), created: time.Now()})
	hh.sigJobs["s1"] = &sigRefreshJob{id: "s1", accounts: 3, status: "done",
		sigBefore: 10, sigAfter: 10, templates: 226, created: time.Now()}
	h := http.StripPrefix("/evilginx", hh)

	req := httptest.NewRequest(http.MethodGet, "/evilginx/spear/new?job=e1&sigjob=s1", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Library refreshed: 10 signatures (0 new)") {
		t.Errorf("expected the refresh summary, got: %.500s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Refresh library") {
		t.Errorf("expected the refresh button in the picker")
	}
}

func TestSigNewBrandsDiff(t *testing.T) {
	added := diffNew([]string{"alpha", "beta"}, []string{"alpha", "Beta", "gamma", "alpha"})
	if len(added) != 1 || added[0] != "gamma" {
		t.Errorf("case-insensitive diff wrong: %v", added)
	}
	if len(diffNew(nil, nil)) != 0 {
		t.Errorf("empty diff must stay empty")
	}
}

func TestWriteLoadLastNew(t *testing.T) {
	dir := t.TempDir()
	if got := loadLastNew(dir); len(got) != 0 {
		t.Fatalf("missing file must load empty, got %v", got)
	}
	writeLastNew(dir, []string{"Acme", "Beta"})
	got := loadLastNew(dir)
	if !got["acme"] || !got["beta"] || len(got) != 2 {
		t.Errorf("roundtrip wrong: %v", got)
	}
	// Corrupt file must not break the picker.
	os.WriteFile(filepath.Join(dir, lastNewFileName), []byte("{nope"), 0o644)
	if got := loadLastNew(dir); len(got) != 0 {
		t.Errorf("corrupt file must load empty, got %v", got)
	}
	// Missing dir must not error.
	writeLastNew(filepath.Join(dir, "nope"), []string{"x"})
}

func TestSpearLibGroupsMarksNew(t *testing.T) {
	all := []spearPick{
		{Brand: "acme", Display: "Acme", Domain: "acme.com", Subject: "Hi", Group: "job", Score: 5},
		{Brand: "old", Display: "Old", Domain: "old.com", Subject: "Hello", Group: "generic", Score: 9},
	}
	groups := spearLibGroups(all, map[string]bool{"acme": true})
	var acme, old *spearPick
	for _, g := range groups {
		for i := range g.Items {
			switch g.Items[i].Brand {
			case "acme":
				acme = &g.Items[i]
			case "old":
				old = &g.Items[i]
			}
		}
	}
	if acme == nil || old == nil {
		t.Fatal("items lost in grouping")
	}
	if !acme.IsNew || !strings.HasPrefix(acme.Option, "★ NEW") {
		t.Errorf("new brand not badged: %+v", acme)
	}
	if old.IsNew || strings.Contains(old.Option, "NEW") {
		t.Errorf("old brand wrongly badged: %+v", old)
	}
}

func TestSpearLibraryBrandValidation(t *testing.T) {
	for _, bad := range []string{"", "../secret", "a/b", "A B", "x$y"} {
		if got := cleanSpearBrand(bad); got != "" {
			t.Errorf("cleanSpearBrand(%q) = %q, want empty", bad, got)
		}
	}
	if got := cleanSpearBrand("Banque-Misr_2.0"); got != "banque-misr_2.0" {
		t.Errorf("cleanSpearBrand normalized = %q", got)
	}

	hh := spearTestHandler(t, nil)
	enableSpearStub(t, hh)
	hh.setSpearJob(&spearJob{id: "gen1", kind: "generate",
		status: "done", report: spearFixtureReport(), created: time.Now()})
	h := http.StripPrefix("/evilginx", hh)

	rec := postForm(t, h, "/evilginx/spear/library",
		url.Values{"job": {"gen1"}, "brand": {"../etc"}})
	if !strings.Contains(rec.Body.String(), "Invalid template brand") {
		t.Errorf("expected brand validation error, got: %.300s", rec.Body.String())
	}
}
