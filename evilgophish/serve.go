package main

import (
	"context"
	"errors"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	evilfeed "evilgophish/shared/feed"

	"github.com/gophish/gophish/controllers"
	"github.com/gophish/gophish/dialer"
	"github.com/gophish/gophish/imap"
	log "github.com/gophish/gophish/logger"
	"github.com/gophish/gophish/middleware"
	"github.com/gophish/gophish/models"
	"github.com/gophish/gophish/webhook"

	"evilgophish/internal/config"
	"evilgophish/internal/panel"
	"evilgophish/internal/proxy"
)

// serveMain runs the unified application: the gophish admin GUI (with the
// evilinx panel mounted under /evilginx when the proxy is enabled), the
// embedded proxy engine, and the live-feed server.
func serveMain(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	configPath := fs.String("config", "./config.json", "location of the unified config.json")
	feedListen := fs.String("feed-listen", "", "override feed server listen address")
	feedStatic := fs.String("feed-static", "", "override feed server static directory")
	proxyPhishlets := fs.String("proxy-phishlets", "", "override the phishlets directory")
	proxyRedirectors := fs.String("proxy-redirectors", "", "override the redirectors directory")
	proxyCfgDir := fs.String("proxy-cfg-dir", "", "override the evilinx config directory")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	gc := cfg.Gophish

	dialer.SetAllowedHosts(gc.AdminConf.AllowedInternalHosts)
	webhook.SetTransport(&http.Transport{
		DialContext: dialer.Dialer().DialContext,
	})

	if err := log.Setup(gc.Logging); err != nil {
		return err
	}

	if err := models.Setup(gc); err != nil {
		return err
	}
	if err := models.UnlockAllMailLogs(); err != nil {
		return err
	}

	proxySvc, err := startProxy(cfg, *configPath, proxyPhishlets, proxyRedirectors, proxyCfgDir)
	if err != nil {
		return err
	}

	adminOpts := []controllers.AdminServerOption{}
	if proxySvc != nil {
		// Mount the evilinx panel behind the admin login.
		eng := proxySvc.Engine()
		// Spear launch drives campaign creation through the local admin
		// API using an admin key resolved per launch (keys can be reset).
		adminScheme := "http"
		if gc.AdminConf.UseTLS {
			adminScheme = "https"
		}
		adminBase := adminScheme + "://" + gc.AdminConf.ListenURL
		adminKey := func() (string, error) {
			users, err := models.GetUsers()
			if err != nil {
				return "", err
			}
			for _, u := range users {
				if u.Role.Slug == models.RoleAdmin && u.ApiKey != "" {
					return u.ApiKey, nil
				}
			}
			return "", errors.New("no admin API key found")
		}
		adminOpts = append(adminOpts, controllers.WithMount("/evilginx", middleware.RequireLogin(panel.New(eng.Cfg,
			panel.WithOnChange(proxySvc.SyncCertificates),
			panel.WithSessions(eng.DB.ListSessions),
			panel.WithPhishletsDir(proxySvc.PhishletsDir()),
			panel.WithSiteAuditor(cfg.SiteAuditor),
			panel.WithAdminAPI(adminBase, adminKey),
		))))
	}
	adminServer := controllers.NewAdminServer(gc.AdminConf, adminOpts...)
	middleware.Store.Options.Secure = gc.AdminConf.UseTLS
	go adminServer.Start()

	imapMonitor := imap.NewMonitor()
	go imapMonitor.Start()

	var feedSrv *evilfeed.Server
	if cfg.FeedServer.Enabled {
		addr := cfg.FeedServer.ListenURL
		if *feedListen != "" {
			addr = *feedListen
		}
		static := cfg.FeedServer.ResolveStaticDir(filepath.Dir(*configPath))
		if *feedStatic != "" {
			static = *feedStatic
		}
		feedSrv = evilfeed.NewServer(addr, static)
		go func() {
			if err := feedSrv.Start(); err != nil {
				log.Errorf("feed server: %v", err)
			}
		}()
		log.Infof("feed server listening on %s (static: %s)", addr, static)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c
	log.Info("interrupt received... gracefully shutting down servers")

	if proxySvc != nil {
		proxySvc.Shutdown()
	}
	adminServer.Shutdown()
	imapMonitor.Shutdown()

	if feedSrv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		feedSrv.Shutdown(ctx)
	}

	return nil
}

// startProxy resolves the proxy configuration, applying any command-line
// overrides, and starts the embedded evilginx engine when enabled. The proxy
// adopts gophish's already-open database connection (models.DB), which is the
// single shared handle for both components.
func startProxy(cfg *config.Config, configPath string, phishlets, redirectors, cfgDir *string) (*proxy.Service, error) {
	if !cfg.Proxy.Enabled {
		return nil, nil
	}
	pc := cfg.Proxy
	if *phishlets != "" {
		pc.PhishletsDir = *phishlets
	}
	if *redirectors != "" {
		pc.RedirectorsDir = *redirectors
	}
	if *cfgDir != "" {
		pc.ConfigDir = *cfgDir
	}
	base := filepath.Dir(configPath)
	if pc.PhishletsDir == "" {
		pc.PhishletsDir = pc.ResolveProxyPhishletsDir(base)
	}
	if pc.RedirectorsDir == "" {
		pc.RedirectorsDir = pc.ResolveProxyRedirectorsDir(base)
	}
	svc, err := proxy.New(pc, models.DB())
	if err != nil {
		return nil, err
	}
	if err := svc.Start(); err != nil {
		return nil, err
	}
	svc.SyncCertificates()
	log.Infof("evilginx proxy listening on %s (domain: %q, external ip: %s)", svc.ListenURL(), svc.Domain(), svc.ExternalIP())
	return svc, nil
}
