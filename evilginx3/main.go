package main

import (
	"flag"
	"fmt"
	_log "log"
	"os"
	"os/user"
	"path/filepath"

	"github.com/fatih/color"
	"github.com/kgretzky/evilginx2/core"
	"github.com/kgretzky/evilginx2/engine"
	"github.com/kgretzky/evilginx2/log"
)

var phishlets_dir = flag.String("p", "", "Phishlets directory path")
var redirectors_dir = flag.String("t", "", "HTML redirector pages directory path")
var debug_log = flag.Bool("debug", false, "Enable debug output")
var developer_mode = flag.Bool("developer", false, "Enable developer mode (generates self-signed certificates for all hostnames)")
var cfg_dir = flag.String("c", "", "Configuration directory path")
var version_flag = flag.Bool("v", false, "Show version")
var gophish_db = flag.String("g", "", "Full path to gophish database")
var feed_enabled = flag.Bool("feed", false, "Enable live feed")
var turnstile = flag.String("turnstile", "", "Turnstile public/private key separated by \":\"")

func joinPath(base_path string, rel_path string) string {
	var ret string
	if filepath.IsAbs(rel_path) {
		ret = rel_path
	} else {
		ret = filepath.Join(base_path, rel_path)
	}
	return ret
}

func showAd() {
	lred := color.New(color.FgHiRed)
	lyellow := color.New(color.FgHiYellow)
	white := color.New(color.FgHiWhite)
	message := fmt.Sprintf("%s: %s %s", lred.Sprint("Evilginx Mastery Course"), lyellow.Sprint("https://academy.breakdev.org/evilginx-mastery"), white.Sprint("(learn how to create phishlets)"))
	log.Info("%s", message)
}

func main() {
	flag.Parse()
	if *gophish_db == "" {
		log.Fatal("you need to provide the full path to the gophish database: ./evilginx3 -g /opt/evilgophish/gophish/gophish.db")
		return
	}

	if *version_flag == true {
		log.Info("version: %s", core.VERSION)
		return
	}

	exe_path, _ := os.Executable()
	exe_dir := filepath.Dir(exe_path)

	core.Banner()
	showAd()

	_log.SetOutput(log.NullLogger().Writer())

	if *phishlets_dir == "" {
		*phishlets_dir = joinPath(exe_dir, "./phishlets")
		if _, err := os.Stat(*phishlets_dir); os.IsNotExist(err) {
			*phishlets_dir = "/usr/share/evilginx/phishlets/"
			if _, err := os.Stat(*phishlets_dir); os.IsNotExist(err) {
				log.Fatal("you need to provide the path to directory where your phishlets are stored: ./evilginx -p <phishlets_path>")
				return
			}
		}
	}
	if *redirectors_dir == "" {
		*redirectors_dir = joinPath(exe_dir, "./redirectors")
		if _, err := os.Stat(*redirectors_dir); os.IsNotExist(err) {
			*redirectors_dir = "/usr/share/evilginx/redirectors/"
			if _, err := os.Stat(*redirectors_dir); os.IsNotExist(err) {
				*redirectors_dir = joinPath(exe_dir, "./redirectors")
			}
		}
	}
	if _, err := os.Stat(*phishlets_dir); os.IsNotExist(err) {
		log.Fatal("provided phishlets directory path does not exist: %s", *phishlets_dir)
		return
	}
	if _, err := os.Stat(*redirectors_dir); os.IsNotExist(err) {
		os.MkdirAll(*redirectors_dir, os.FileMode(0700))
	}

	log.DebugEnable(*debug_log)
	if *debug_log {
		log.Info("debug output enabled")
	}

	log.Info("loading phishlets from: %s", *phishlets_dir)

	if *cfg_dir == "" {
		usr, err := user.Current()
		if err != nil {
			log.Fatal("%v", err)
			return
		}
		*cfg_dir = filepath.Join(usr.HomeDir, ".evilginx")
	}

	log.Info("loading configuration from: %s", *cfg_dir)

	eng, err := engine.New(engine.Options{
		PhishletsDir:   *phishlets_dir,
		RedirectorsDir: *redirectors_dir,
		ConfigDir:      *cfg_dir,
		GophishDB:      *gophish_db,
		Turnstile:      *turnstile,
		Developer:      *developer_mode,
		FeedEnabled:    *feed_enabled,
	})
	if err != nil {
		log.Fatal("%v", err)
		return
	}

	if err := eng.Start(); err != nil {
		log.Fatal("%v", err)
		return
	}

	t, err := core.NewTerminal(eng.Proxy, eng.Cfg, eng.CertDB, eng.DB, *developer_mode)
	if err != nil {
		log.Fatal("%v", err)
		return
	}

	t.DoWork()
}