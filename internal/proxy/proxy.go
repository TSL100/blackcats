// Package proxy provides the evilginx proxy engine as a service for the
// unified evilgophish application. It wraps the extracted evilinx engine
// (github.com/kgretzky/evilginx2/engine) and maps the unified ProxyConfig
// onto it, so serve can start and stop the proxy programmatically.
package proxy

import (
	"fmt"

	"github.com/jinzhu/gorm"
	"github.com/kgretzky/evilginx2/engine"

	"evilgophish/internal/config"
)

// Service manages the lifecycle of the embedded evilginx proxy engine.
type Service struct {
	engine       *engine.Engine
	phishletsDir string
}

// New builds a proxy Service from the unified configuration. gpDB is the
// gophish database connection used by the rest of the process; when non-nil
// the proxy adopts it (sharing one connection), otherwise it opens the
// configured GophishDB path on its own. It returns (nil, nil) when the proxy
// is not enabled.
func New(cfg config.ProxyConfig, gpDB *gorm.DB) (*Service, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	opts := engine.Options{
		PhishletsDir:   cfg.PhishletsDir,
		RedirectorsDir: cfg.RedirectorsDir,
		ConfigDir:      cfg.ConfigDir,
		Turnstile:      cfg.Turnstile,
		GophishDB:      cfg.GophishDB,
		GPDB:           gpDB,
		HttpsPort:      cfg.HttpsPort,
		DnsPort:        cfg.DnsPort,
		ExternalIP:     cfg.ExternalIP,
		Developer:      cfg.Developer,
		PortTolerance:  cfg.PortTolerance,
	}
	eng, err := engine.New(opts)
	if err != nil {
		return nil, err
	}

	return &Service{engine: eng, phishletsDir: opts.PhishletsDir}, nil
}

// PhishletsDir returns the directory the engine scans for phishlet YAML
// files, which is where the panel writes newly created phishlets.
func (s *Service) PhishletsDir() string {
	return s.phishletsDir
}

// Start launches the proxy engine listeners.
func (s *Service) Start() error {
	return s.engine.Start()
}

// Shutdown gracefully stops the proxy engine listeners.
func (s *Service) Shutdown() {
	s.engine.Stop()
}

// SyncCertificates sets up TLS certificates for all enabled hostnames.
func (s *Service) SyncCertificates() {
	s.engine.Proxy.ManageCertificates(true)
}

// ListenURL returns the address the HTTPS proxy listens on.
func (s *Service) ListenURL() string {
	return fmt.Sprintf("%s:%d", s.engine.Cfg.GetServerBindIP(), s.engine.Cfg.GetHttpsPort())
}

// Domain returns the configured phishing base domain (empty until set).
func (s *Service) Domain() string {
	return s.engine.Cfg.GetBaseDomain()
}

// ExternalIP returns the configured external IPv4 address.
func (s *Service) ExternalIP() string {
	return s.engine.Cfg.GetServerExternalIP()
}

// Engine returns the underlying proxy engine, exposing the configuration and
// live state to the rest of the unified application (e.g. the admin panel).
func (s *Service) Engine() *engine.Engine {
	return s.engine
}