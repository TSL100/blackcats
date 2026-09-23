package config

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	dir, err := ioutil.TempDir("", "evilgophish-config")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "config.json")
	if err := ioutil.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadDefaults(t *testing.T) {
	path := writeTempConfig(t, `{
		"admin_server": {"listen_url": "127.0.0.1:3333", "use_tls": true},
		"phish_server": {"listen_url": "127.0.0.1:8080"},
		"db_name": "sqlite3",
		"db_path": "gophish.db"
	}`)
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Gophish.AdminConf.ListenURL != "127.0.0.1:3333" {
		t.Errorf("gophish admin listen: %q", c.Gophish.AdminConf.ListenURL)
	}
	if !c.FeedServer.Enabled {
		t.Error("feed server should default to enabled")
	}
	if c.FeedServer.ListenURL != DefaultFeedListenURL {
		t.Errorf("feed listen: %q", c.FeedServer.ListenURL)
	}
	if c.Proxy.Enabled {
		t.Error("proxy should default to disabled")
	}
	if c.Proxy.GophishDB != "gophish.db" {
		t.Errorf("proxy gophish_db: %q", c.Proxy.GophishDB)
	}
	if c.Proxy.HttpsPort != DefaultProxyHttpsPort || c.Proxy.DnsPort != DefaultProxyDnsPort {
		t.Errorf("proxy ports: %d/%d", c.Proxy.HttpsPort, c.Proxy.DnsPort)
	}
}

func TestLoadExplicitSections(t *testing.T) {
	path := writeTempConfig(t, `{
		"admin_server": {"listen_url": "127.0.0.1:3333"},
		"phish_server": {"listen_url": "127.0.0.1:8080"},
		"db_path": "custom.db",
		"proxy": {
			"enabled": true,
			"phishlets_dir": "/etc/phishlets",
			"gophish_db": "overridden.db",
			"https_port": 8443,
			"external_ip": "1.2.3.4"
		},
		"feed_server": {
			"enabled": false,
			"listen_url": "0.0.0.0:9000",
			"static_dir": "/srv/feed"
		}
	}`)
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Proxy.Enabled {
		t.Error("proxy should be enabled")
	}
	if c.Proxy.GophishDB != "overridden.db" {
		t.Errorf("proxy gophish_db: %q", c.Proxy.GophishDB)
	}
	if c.Proxy.HttpsPort != 8443 {
		t.Errorf("proxy https_port: %d", c.Proxy.HttpsPort)
	}
	if c.Proxy.ExternalIP != "1.2.3.4" {
		t.Errorf("proxy external ip: %q", c.Proxy.ExternalIP)
	}
	if c.FeedServer.Enabled {
		t.Error("feed server should be disabled")
	}
}

func TestResolveStaticDir(t *testing.T) {
	dir, err := ioutil.TempDir("", "evilgophish-static")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	confDir := filepath.Join(dir, "conf")
	if err := os.MkdirAll(confDir, 0o700); err != nil {
		t.Fatal(err)
	}
	sibling := filepath.Join(dir, "evilfeed", "app")
	if err := os.MkdirAll(sibling, 0o700); err != nil {
		t.Fatal(err)
	}

	f := FeedServerConfig{}
	if got := f.ResolveStaticDir(confDir); got != sibling {
		t.Errorf("resolved %q, want %q", got, sibling)
	}

	explicit := filepath.Join(dir, "explicit")
	f.StaticDir = explicit
	if got := f.ResolveStaticDir(confDir); got != explicit {
		t.Errorf("resolved %q, want explicit %q", got, explicit)
	}
}

func TestResolveProxyDirs(t *testing.T) {
	dir, err := ioutil.TempDir("", "evilgophish-proxy")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	base := filepath.Join(dir, "gophish")
	if err := os.MkdirAll(base, 0o700); err != nil {
		t.Fatal(err)
	}
	evilginxDir := filepath.Join(dir, "evilginx3")
	if err := os.MkdirAll(filepath.Join(evilginxDir, "phishlets"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "redirectors"), 0o700); err != nil {
		t.Fatal(err)
	}

	p := ProxyConfig{}
	if got := p.ResolveProxyPhishletsDir(base); got != filepath.Join(evilginxDir, "phishlets") {
		t.Errorf("phishlets resolved %q, want %q", got, filepath.Join(evilginxDir, "phishlets"))
	}
	if got := p.ResolveProxyRedirectorsDir(base); got != filepath.Join(dir, "redirectors") {
		t.Errorf("redirectors resolved %q, want %q", got, filepath.Join(dir, "redirectors"))
	}

	p.PhishletsDir = filepath.Join(dir, "custom_ph")
	p.RedirectorsDir = filepath.Join(dir, "custom_rd")
	if got := p.ResolveProxyPhishletsDir(base); got != p.PhishletsDir {
		t.Errorf("explicit phishlets: %q", got)
	}
	if got := p.ResolveProxyRedirectorsDir(base); got != p.RedirectorsDir {
		t.Errorf("explicit redirectors: %q", got)
	}
}