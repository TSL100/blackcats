// Package config provides the unified configuration for the evilgophish
// application. It is a superset of the existing gophish configuration:
// the gophish section is unchanged, and the additional "proxy" and
// "feed_server" sections drive the unified services.
package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/gophish/gophish/config"
)

const (
	// DefaultFeedListenURL is used when no feed listen address is configured.
	DefaultFeedListenURL = "localhost:1337"
	// DefaultProxyHttpsPort is used when no proxy https port is configured.
	DefaultProxyHttpsPort = 443
	// DefaultProxyDnsPort is used when no proxy dns port is configured.
	DefaultProxyDnsPort = 53
	// DefaultSiteAuditorTimeout is the default budget, in seconds, granted to
	// the harvester script for a single discovery+harvest run.
	DefaultSiteAuditorTimeout = 150
)

// ProxyConfig holds the evilginx2 engine settings used by the unified proxy.
type ProxyConfig struct {
	Enabled        bool   `json:"enabled"`
	Developer      bool   `json:"developer"`
	PhishletsDir   string `json:"phishlets_dir"`
	RedirectorsDir string `json:"redirectors_dir"`
	ConfigDir      string `json:"config_dir"`
	GophishDB      string `json:"gophish_db"`
	ExternalIP     string `json:"external_ip"`
	HttpsPort      int    `json:"https_port"`
	DnsPort        int    `json:"dns_port"`
	Turnstile      string `json:"turnstile"`
	// PortTolerance enables local testing on a non-443 HTTPS port. When true,
	// the panel embeds the configured HTTPS port in generated phishing URLs
	// (when it is not the standard 443) and the proxy hostname matching strips
	// a ":port" suffix from incoming Host values. This is only needed for
	// local/alternate-port setups; remove it (set false) for standard 443
	// production deployments.
	PortTolerance bool `json:"port_tolerance,omitempty"`
}

// FeedServerConfig holds the feed server settings.
type FeedServerConfig struct {
	Enabled   bool   `json:"enabled"`
	ListenURL string `json:"listen_url"`
	StaticDir string `json:"static_dir"`
}

// SiteAuditorConfig drives the "New Phishlet" auto-generation feature. It
// points at the standalone harvester script (tools/phishlet_harvester.py) and
// the Python interpreter used to run it.
type SiteAuditorConfig struct {
	Enabled  bool   `json:"enabled"`
	Python   string `json:"python"`
	Script   string `json:"script"`
	Timeout  int    `json:"timeout_seconds"`
}

// Config is the unified application configuration.
type Config struct {
	Gophish     *config.Config
	Proxy       ProxyConfig
	FeedServer  FeedServerConfig
	SiteAuditor SiteAuditorConfig
}

// Load reads the unified config.json and returns the parsed configuration.
// The gophish section is parsed by the gophish config loader unchanged.
func Load(path string) (*Config, error) {
	gophishConfig, err := config.LoadConfig(path)
	if err != nil {
		return nil, err
	}
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := &Config{Gophish: gophishConfig}
	c.Proxy = ProxyConfig{
		Enabled:    false,
		HttpsPort:  DefaultProxyHttpsPort,
		DnsPort:    DefaultProxyDnsPort,
		GophishDB:  gophishConfig.DBPath,
		ConfigDir:  filepath.Dir(path),
		ExternalIP: "127.0.0.1",
	}
	c.FeedServer = FeedServerConfig{
		Enabled:   true,
		ListenURL: DefaultFeedListenURL,
	}
	// The proxy/feed_server sections are optional.
	var extra struct {
		Proxy ProxyConfig `json:"proxy"`
		FeedServer struct {
			Enabled   *bool  `json:"enabled"`
			ListenURL string `json:"listen_url"`
			StaticDir string `json:"static_dir"`
		} `json:"feed_server"`
		SiteAuditor struct {
			Enabled *bool  `json:"enabled"`
			Python  string `json:"python"`
			Script  string `json:"script"`
			Timeout int    `json:"timeout_seconds"`
		} `json:"site_auditor"`
	}
	if err := json.Unmarshal(b, &extra); err != nil {
		return nil, fmt.Errorf("invalid config: %v", err)
	}
	if extra.Proxy.Enabled {
		c.Proxy.Enabled = true
	}
	if extra.Proxy.Developer {
		c.Proxy.Developer = true
	}
	if extra.Proxy.PhishletsDir != "" {
		c.Proxy.PhishletsDir = extra.Proxy.PhishletsDir
	}
	if extra.Proxy.RedirectorsDir != "" {
		c.Proxy.RedirectorsDir = extra.Proxy.RedirectorsDir
	}
	if extra.Proxy.ConfigDir != "" {
		c.Proxy.ConfigDir = extra.Proxy.ConfigDir
	}
	if extra.Proxy.GophishDB != "" {
		c.Proxy.GophishDB = extra.Proxy.GophishDB
	}
	if extra.Proxy.ExternalIP != "" {
		c.Proxy.ExternalIP = extra.Proxy.ExternalIP
	}
	if extra.Proxy.HttpsPort != 0 {
		c.Proxy.HttpsPort = extra.Proxy.HttpsPort
	}
	if extra.Proxy.DnsPort != 0 {
		c.Proxy.DnsPort = extra.Proxy.DnsPort
	}
	if extra.Proxy.Turnstile != "" {
		c.Proxy.Turnstile = extra.Proxy.Turnstile
	}
	if extra.Proxy.PortTolerance {
		c.Proxy.PortTolerance = true
	}
	if extra.FeedServer.Enabled != nil {
		c.FeedServer.Enabled = *extra.FeedServer.Enabled
	}
	if extra.FeedServer.ListenURL != "" {
		c.FeedServer.ListenURL = extra.FeedServer.ListenURL
	}
	if extra.FeedServer.StaticDir != "" {
		c.FeedServer.StaticDir = extra.FeedServer.StaticDir
	}
	c.SiteAuditor = SiteAuditorConfig{
		Enabled: true,
		Python:  "python",
		Timeout: DefaultSiteAuditorTimeout,
	}
	if extra.SiteAuditor.Enabled != nil {
		c.SiteAuditor.Enabled = *extra.SiteAuditor.Enabled
	}
	if extra.SiteAuditor.Python != "" {
		c.SiteAuditor.Python = extra.SiteAuditor.Python
	}
	if extra.SiteAuditor.Script != "" {
		c.SiteAuditor.Script = extra.SiteAuditor.Script
	}
	if extra.SiteAuditor.Timeout > 0 {
		c.SiteAuditor.Timeout = extra.SiteAuditor.Timeout
	}
	if c.SiteAuditor.Script == "" {
		c.SiteAuditor.Script = c.SiteAuditor.ResolveScript(filepath.Dir(path))
	}
	if _, err := os.Stat(c.SiteAuditor.Script); err != nil {
		c.SiteAuditor.Enabled = false
	}
	return c, nil
}

// ResolveStaticDir returns the feed dashboard static directory to serve.
// If not explicitly configured, existing conventional locations are tried
// relative to the config directory (both a sibling evilfeed/app checkout and
// the legacy cwd-relative layout), falling back to a bare "app" directory.
func (f *FeedServerConfig) ResolveStaticDir(configDir string) string {
	if f.StaticDir != "" {
		return f.StaticDir
	}
	candidates := []string{
		filepath.Join(configDir, "..", "evilfeed", "app"),
		filepath.Join(configDir, "evilfeed", "app"),
		filepath.Join(configDir, "app"),
	}
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && info.IsDir() {
			return c
		}
	}
	return filepath.Join(configDir, "app")
}

const (
	defaultProxyPhishletsDir   = "phishlets"
	defaultProxyRedirectorsDir = "redirectors"
)

// ResolveProxyPhishletsDir returns the phishlets directory to load. If not
// explicitly configured, conventional sibling/relative layouts are tried.
func (p *ProxyConfig) ResolveProxyPhishletsDir(configDir string) string {
	if p.PhishletsDir != "" {
		return p.PhishletsDir
	}
	candidates := []string{
		filepath.Join(configDir, "..", "evilginx3", defaultProxyPhishletsDir),
		filepath.Join(configDir, "..", defaultProxyPhishletsDir),
		filepath.Join(configDir, "evilginx3", defaultProxyPhishletsDir),
		filepath.Join(configDir, defaultProxyPhishletsDir),
	}
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && info.IsDir() {
			return c
		}
	}
	return filepath.Join(configDir, defaultProxyPhishletsDir)
}

// ResolveProxyRedirectorsDir returns the redirectors directory to use. If not
// explicitly configured, conventional sibling/relative layouts are tried.
func (p *ProxyConfig) ResolveProxyRedirectorsDir(configDir string) string {
	if p.RedirectorsDir != "" {
		return p.RedirectorsDir
	}
	candidates := []string{
		filepath.Join(configDir, "..", defaultProxyRedirectorsDir),
		filepath.Join(configDir, defaultProxyRedirectorsDir),
	}
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && info.IsDir() {
			return c
		}
	}
	return filepath.Join(configDir, defaultProxyRedirectorsDir)
}

const defaultSiteAuditorScript = "phishlet_harvester.py"

// ResolveScript returns the path to the site-auditor harvester script. If not
// explicitly configured, conventional locations relative to the config
// directory are tried, favouring this repository's tools/ directory.
func (s *SiteAuditorConfig) ResolveScript(configDir string) string {
	if s.Script != "" {
		return s.Script
	}
	candidates := []string{
		filepath.Join(configDir, "tools", defaultSiteAuditorScript),
		filepath.Join(configDir, "..", "tools", defaultSiteAuditorScript),
		filepath.Join(configDir, defaultSiteAuditorScript),
		filepath.Join(".", "tools", defaultSiteAuditorScript),
	}
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && !info.IsDir() {
			return c
		}
	}
	return filepath.Join(configDir, "tools", defaultSiteAuditorScript)
}