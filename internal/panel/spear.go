package panel

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kgretzky/evilginx2/core"
)

// This file implements the Black Cat spear-phishing flow: Target -> Channel
// -> Prompt -> Review & Launch. It mirrors the audit-job pattern used for
// phishlet discovery (background job + JSON polling endpoint), but drives
// tools/spear_enrich.py and finishes by creating a single-target Group,
// Template and Campaign through the platform's own /api/* endpoints — the
// exact payloads the dashboard modals send, so tracking and results behave
// identically.

// spearReport mirrors the tools/spear_enrich.py report JSON.
type spearReport struct {
	LinkedIn      string            `json:"linkedin"`
	Profile       map[string]string `json:"profile"`
	Target        map[string]string `json:"target"`
	Channel       string            `json:"channel"`
	Lang          string            `json:"lang"`
	PromptDefault string            `json:"prompt_default"`
	PromptUsed    string            `json:"prompt_used"`
	CustomPrompt  bool              `json:"custom_prompt"`
	Subject       string            `json:"subject"`
	Body          string            `json:"body"`
	// HTML carries a full branded template (from signclone library) when the
	// operator picks one. Empty means "wrap Body with spearHTMLBody".
	HTML      string   `json:"html"`
	Generator string   `json:"generator"`
	Notes     []string `json:"notes"`
}

// spearPick is one library recommendation rendered in the picker.
type spearPick struct {
	Brand    string
	Display  string
	Domain   string
	Color    string
	Logo     string
	Subject  string
	Envelope string
	Snippet  string
	Reason   string
	Group    string // job | finance | learn | generic (for the full-list optgroups)
	Option   string // short dropdown label (set when bucketing groups)
	IsNew    bool   // added by the most recent library refresh
	Score    int
}

// spearGroupLabel maps a picker group to its dropdown section title.
func spearGroupLabel(g string) string {
	switch g {
	case "job":
		return "Jobs & hiring"
	case "finance":
		return "Finance & billing"
	case "learn":
		return "Courses & labs"
	default:
		return "General"
	}
}

// spearJob is a single running/finished spear step. Jobs are transient
// in-memory state; enrich jobs hold the profile, generate jobs hold the
// final message. Launch consumes a finished generate job.
type spearJob struct {
	id       string
	kind     string // "enrich" | "generate"
	linkedin string
	channel  string // "mail" | "sms"
	lang     string // "en" | "ar"
	sender   string
	refresh  bool   // enrich only: bypass the local profile cache (costs quota)
	prompt   string // operator-edited prompt (generate only)
	reportID string // enrich job id (generate only)
	status   string // "running" | "done" | "error"
	err      string
	report   spearReport
	created  time.Time
}

// spearRunnerFunc executes the wrapper and returns the parsed report.
// It is a field (not a direct exec call) so tests can stub enrichment.
type spearRunnerFunc func(ctx context.Context, python, script string,
	args []string) (spearReport, string, error)

// defaultSpearRunner runs tools/spear_enrich.py in a subprocess and parses
// the report file it writes.
func defaultSpearRunner(ctx context.Context, python, script string,
	args []string) (spearReport, string, error) {
	var rep spearReport
	dir, err := os.MkdirTemp("", "spear_report_")
	if err != nil {
		return rep, "", err
	}
	defer os.RemoveAll(dir)
	out := filepath.Join(dir, "report.json")
	full := make([]string, 0, len(args)+4)
	full = append(full, script)
	full = append(full, args...)
	full = append(full, "--out", out)
	cmd := exec.CommandContext(ctx, python, full...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return rep, tailText(stderr.String()),
			fmt.Errorf("spear runner failed: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		return rep, tailText(stderr.String()),
			fmt.Errorf("spear runner wrote no report: %v", err)
	}
	if err := json.Unmarshal(data, &rep); err != nil {
		return rep, tailText(stderr.String()),
			fmt.Errorf("invalid spear report: %v", err)
	}
	if rep.Profile == nil {
		rep.Profile = map[string]string{}
	}
	if rep.Target == nil {
		rep.Target = map[string]string{}
	}
	return rep, "", nil
}

func tailText(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 2000 {
		s = s[len(s)-2000:]
		if i := strings.Index(s, "\n"); i >= 0 {
			s = s[i+1:]
		}
	}
	return s
}

// WithAdminAPI wires the local GoPhish admin API used by spear launch.
// base is the admin listener origin (e.g. "https://127.0.0.1:3333") and
// keyFunc returns an admin API key on demand (keys can be reset, so it is
// resolved per launch, never cached).
func WithAdminAPI(base string, keyFunc func() (string, error)) Option {
	return func(h *Handler) {
		h.apiBase = base
		h.apiKeyFunc = keyFunc
	}
}

// spearAvailable reports whether enrichment can run: same Python environment
// as the site auditor, plus the wrapper script next to the harvester.
func (h *Handler) spearAvailable() (python, script string, timeout int, ok bool) {
	if !h.audit.Enabled || h.audit.Python == "" || h.audit.Script == "" {
		return "", "", 0, false
	}
	script = filepath.Join(filepath.Dir(h.audit.Script), "spear_enrich.py")
	if _, err := os.Stat(script); err != nil {
		return "", "", 0, false
	}
	timeout = h.audit.Timeout
	if timeout <= 0 {
		timeout = 150
	}
	return h.audit.Python, script, timeout, true
}

func (h *Handler) setSpearJob(j *spearJob) {
	h.spearMu.Lock()
	defer h.spearMu.Unlock()
	if len(h.spearJobs) >= 20 {
		var oldest string
		var oldestTime time.Time
		for k, v := range h.spearJobs {
			if oldest == "" || v.created.Before(oldestTime) {
				oldest, oldestTime = k, v.created
			}
		}
		delete(h.spearJobs, oldest)
	}
	h.spearJobs[j.id] = j
}

func (h *Handler) getSpearJob(id string) *spearJob {
	h.spearMu.Lock()
	defer h.spearMu.Unlock()
	return h.spearJobs[id]
}

func cleanSpearLang(s string) string {
	if strings.TrimSpace(s) == "ar" {
		return "ar"
	}
	return "en"
}

func cleanLinkedIn(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || !strings.Contains(strings.ToLower(s), "linkedin.com") {
		return ""
	}
	return s
}

// spearNamePrefix marks campaigns launched from the spear flow so the
// spear list page can pick them out of the shared campaign store.
const spearNamePrefix = "Spear - "

func spearCampaignName(name string) string {
	name = strings.TrimSpace(name)
	if strings.HasPrefix(name, spearNamePrefix) {
		return name
	}
	return spearNamePrefix + name
}

// spearRow is one spear campaign on the list page.
type spearRow struct {
	ID      int64
	Name    string
	Channel string // "mail" | "sms"
	Created string
	Status  string
	Link    string
}

// spearList renders the spear campaign list (Active/Archived tabs), the
// analogue of the dashboard campaign pages. Spear launches are regular
// platform campaigns whose names carry the spear prefix.
func (h *Handler) spearList(w http.ResponseWriter, r *http.Request) {
	d := h.baseData(pageSpear)
	api, err := h.apiClient()
	if err != nil {
		d.SpearListErr = err.Error()
		h.render(w, r, "page-spears", d)
		return
	}
	raw, err := api.get("/api/campaigns/")
	if err != nil {
		d.SpearListErr = "Could not list campaigns: " + err.Error()
		h.render(w, r, "page-spears", d)
		return
	}
	var items []struct {
		ID      int64  `json:"id"`
		Name    string `json:"name"`
		Created string `json:"created_date"`
		Status  string `json:"status"`
		SMTP    struct {
			ID int64 `json:"id"`
		} `json:"smtp"`
		SMS struct {
			ID int64 `json:"id"`
		} `json:"sms"`
	}
	if err := json.Unmarshal(raw, &items); err != nil {
		d.SpearListErr = "Invalid campaigns response."
		h.render(w, r, "page-spears", d)
		return
	}
	for _, it := range items {
		if !strings.HasPrefix(it.Name, spearNamePrefix) {
			continue
		}
		channel, link := "mail", fmt.Sprintf("/campaigns/%d", it.ID)
		if it.SMS.ID != 0 {
			channel, link = "sms", fmt.Sprintf("/sms_campaigns/%d", it.ID)
		}
		created := it.Created
		if t, err := time.Parse(time.RFC3339, it.Created); err == nil {
			created = t.Format("2006-01-02 15:04")
		}
		row := spearRow{ID: it.ID, Name: it.Name, Channel: channel,
			Created: created, Status: it.Status, Link: link}
		if it.Status == "Completed" {
			d.SpearArchived = append(d.SpearArchived, row)
		} else {
			d.SpearRows = append(d.SpearRows, row)
		}
	}
	sort.Slice(d.SpearRows, func(i, j int) bool {
		return d.SpearRows[i].ID > d.SpearRows[j].ID
	})
	sort.Slice(d.SpearArchived, func(i, j int) bool {
		return d.SpearArchived[i].ID > d.SpearArchived[j].ID
	})
	h.render(w, r, "page-spears", d)
}

func (h *Handler) spearPage(w http.ResponseWriter, r *http.Request) {
	d := h.baseData(pageSpear)
	_, _, _, d.SpearEnabled = h.spearAvailable()
	if jid := r.URL.Query().Get("job"); jid != "" {
		h.applySpearJob(&d, jid)
	} else if strings.TrimSpace(r.URL.Query().Get("channel")) == "sms" {
		// Deep-link from the SMS campaigns page preselects the channel.
		d.SpearChannel = "sms"
	}
	if sjid := r.URL.Query().Get("sigjob"); sjid != "" {
		h.applySigRefreshJob(&d, sjid)
	}
	h.render(w, r, "page-spear", d)
}

// applySpearJob renders the current state of a spear job into the page:
// a polling banner while running, the profile + editable prompt when
// enrichment finishes, and the review form when generation finishes.
func (h *Handler) applySpearJob(d *pageData, jid string) {
	j := h.getSpearJob(jid)
	if j == nil {
		d.SpearErr = "Spear job not found."
		return
	}
	d.SpearLinkedIn, d.SpearChannel, d.SpearSender = j.linkedin, j.channel, j.sender
	d.SpearLang = j.lang
	if d.SpearLang == "" {
		d.SpearLang = j.report.Lang
	}
	switch j.status {
	case "running":
		d.SpearJobID = j.id
		d.SpearRunning = true
	case "done":
		d.SpearJobID = j.id
		d.SpearProfile = j.report.Profile
		d.SpearTarget = j.report.Target
		d.SpearNotes = j.report.Notes
		d.SpearGenerator = j.report.Generator
		d.SpearChannel = j.report.Channel
		if d.SpearChannel == "" {
			d.SpearChannel = j.channel
		}
		if j.kind == "enrich" {
			d.SpearHasProfile = true
			d.SpearPrompt = j.report.PromptDefault
		} else {
			d.SpearHasProfile = true
			d.SpearHasResult = true
			d.SpearPrompt = j.report.PromptUsed
			d.SpearSubject = j.report.Subject
			d.SpearBody = j.report.Body
			d.SpearCampaign = "Spear - " + spearDisplayName(j.report.Target)
			profiles, err := h.spearProfileNames(d.SpearChannel)
			if err != nil {
				d.SpearProfilesErr = err.Error()
			} else {
				d.SpearProfiles = profiles
			}
		}
	case "error":
		d.SpearErr = j.err
	}
	// Library picker: top-3 suggestions plus the full browsable library.
	// Mail only — the library is HTML email templates, not SMS copy.
	// Silent when the library is absent (nil, nil) so the wizard still works.
	if j.status == "done" && len(j.report.Profile) > 0 && d.SpearChannel != "sms" {
		var news map[string]bool
		if root, ok := spearLibraryRoot(); ok {
			news = loadLastNew(root)
		}
		if picks, err := spearPicksFor(j.report.Profile, j.report.Target); err != nil {
			d.SpearPicksErr = err.Error()
		} else {
			for i := range picks {
				picks[i].IsNew = news[strings.ToLower(picks[i].Brand)]
			}
			d.SpearPicks = picks
		}
		if d.SpearPicksErr == "" {
			if all, err := spearLibraryAll(j.report.Profile, j.report.Target); err != nil {
				d.SpearPicksErr = err.Error()
			} else {
				d.SpearLibTotal = len(all)
				d.SpearLibGroups = spearLibGroups(all, news)
			}
		}
	}
}

func spearSplitName(full string) (string, string) {
	parts := strings.Fields(strings.TrimSpace(full))
	if len(parts) == 0 {
		return "", ""
	}
	if len(parts) == 1 {
		return parts[0], ""
	}
	return parts[0], strings.Join(parts[1:], " ")
}

// rebuildSpearTarget re-derives the campaign target from the (possibly
// hand-edited) profile so there is a single source of truth.
func rebuildSpearTarget(rep *spearReport) {
	first, last := spearSplitName(rep.Profile["Name"])
	pos := strings.TrimSpace(rep.Profile["Current_Position"])
	if comp := strings.TrimSpace(rep.Profile["Company"]); comp != "" {
		if pos != "" {
			pos += " at " + comp
		} else {
			pos = comp
		}
	}
	if rep.Target == nil {
		rep.Target = map[string]string{}
	}
	rep.Target["first_name"] = first
	rep.Target["last_name"] = last
	rep.Target["position"] = pos
	rep.Target["email"] = strings.TrimSpace(rep.Profile["Email"])
}

func spearDisplayName(target map[string]string) string {
	name := strings.TrimSpace(strings.TrimSpace(target["first_name"]) + " " +
		strings.TrimSpace(target["last_name"]))
	if name == "" {
		return "LinkedIn target"
	}
	return name
}

// spearNorm keeps [a-z0-9] only, lowercased — same as recommend.py.
func spearNorm(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// spearLibraryRoot locates signclone/gophish_templates (index.csv + json/).
// Returns ok=false when the library is absent (panel still works, picker hides).
func spearLibraryRoot() (string, bool) {
	cands := []string{}
	if wd, err := os.Getwd(); err == nil {
		cands = append(cands, filepath.Join(wd, "signclone", "gophish_templates"))
		// panel tests run inside internal/panel: repo root is ../..
		cands = append(cands, filepath.Join(wd, "..", "..", "signclone", "gophish_templates"))
	}
	if ex, err := os.Executable(); err == nil {
		d := filepath.Dir(ex)
		for i := 0; i < 4; i++ {
			cands = append(cands, filepath.Join(d, "signclone", "gophish_templates"))
			d = filepath.Dir(d)
		}
	}
	for _, c := range cands {
		if st, err := os.Stat(filepath.Join(c, "index.csv")); err == nil && !st.IsDir() {
			return c, true
		}
	}
	return "", false
}

// spearGuessCategory mirrors recommend.py keyword buckets.
func spearGuessCategory(position, company string) string {
	text := strings.ToLower(position + " " + company)
	learn, finance, job := 0, 0, 0
	for _, kw := range []string{"soc", "pentest", "cyber", "secur", "dfir", "student", "trainee", "iti", "nti", "depi", "analyst"} {
		if strings.Contains(text, kw) {
			learn += 10
		}
	}
	for _, kw := range []string{"bank", "finance", "account"} {
		if strings.Contains(text, kw) {
			finance += 10
		}
	}
	for _, kw := range []string{"recruit", "seeking", "fresh grad", "hr ", "sales", "marketing", "intern"} {
		if strings.Contains(text, kw) {
			job += 10
		}
	}
	best, bestScore := "generic", 0
	for cat, sc := range map[string]int{"learn": learn, "finance": finance, "job": job} {
		if sc > bestScore {
			best, bestScore = cat, sc
		}
	}
	return best
}

func spearBrandCategory(brand string) string {
	switch strings.ToLower(brand) {
	case "wuzzuf", "bayt", "linkedin", "hire", "talent", "career", "careers",
		"jobright", "naukrigulf", "forasna", "manatal", "successfactors", "icims",
		"recruitment", "taleez", "zety":
		return "job"
	case "banquemisr", "vodafone", "stripe", "taptapsend", "luno", "payments", "statement", "noon":
		return "finance"
	case "tryhackme", "hackthebox", "cybertalents", "letsdefend", "immersivelabs",
		"cyberdefenders", "rangeforce", "sans", "isc2", "eccouncil", "nti", "iti",
		"depi", "maharatech", "hackerrank", "udacity":
		return "learn"
	}
	return "generic"
}

// spearPicksFor scores the template library for this target. (nil, nil) when
// the library is absent — the picker simply hides.
// spearLibraryScored scores every library template for this target, best
// first. (nil, "", nil) when the library is absent — callers hide the picker.
func spearLibraryScored(profile, target map[string]string) ([]spearPick, string, error) {
	root, ok := spearLibraryRoot()
	if !ok {
		return nil, "", nil
	}
	f, err := os.Open(filepath.Join(root, "index.csv"))
	if err != nil {
		return nil, "", nil
	}
	defer f.Close()
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil || len(rows) < 2 {
		return nil, "", fmt.Errorf("template library index is unreadable")
	}
	header := map[string]int{}
	for i, h := range rows[0] {
		header[strings.TrimSpace(h)] = i
	}
	col := func(r []string, name string) string {
		if j, ok := header[name]; ok && j < len(r) {
			return r[j]
		}
		return ""
	}
	company := ""
	position := ""
	if profile != nil {
		company = profile["Company"]
		position = profile["Current_Position"]
	}
	if target != nil && position == "" {
		position = target["position"]
	}
	cn := spearNorm(company)
	cat := spearGuessCategory(position, company)
	type scored struct {
		p     spearPick
		score int
		foot  int
	}
	out := []scored{}
	for _, r := range rows[1:] {
		brand, display, domain := col(r, "brand"), col(r, "display"), col(r, "domain")
		if brand == "" {
			continue
		}
		score := 0
		reasons := []string{}
		matched := false
		for _, cand := range []string{strings.ToLower(brand), spearNorm(display)} {
			if len(cand) >= 4 && cand != "" && (strings.Contains(cn, cand) || strings.Contains(cand, cn)) {
				matched = true
			}
		}
		if !matched && domain != "" {
			root := spearNorm(strings.Split(domain, ".")[0])
			if len(root) >= 4 && strings.Contains(cn, root) {
				matched = true
			}
		}
		if company != "" && matched {
			score += 100
			reasons = append(reasons, "company-match")
		}
		if spearBrandCategory(brand) == cat && cat != "generic" {
			score += 50
			reasons = append(reasons, "cat:"+cat)
		}
		foot := 0
		fmt.Sscan(col(r, "footer_chars"), &foot)
		score += min(foot/50, 10)
		if domain != "" && strings.Count(domain, ".") == 1 {
			score += 5
		}
		out = append(out, scored{p: spearPick{
			Brand: brand, Display: display, Domain: domain,
			Color: col(r, "color"), Logo: col(r, "logo"),
			Subject: col(r, "subject"), Envelope: col(r, "envelope_sender"),
			Reason: strings.Join(reasons, ","),
			Group:  spearBrandCategory(brand),
			Score:  score,
		}, score: score, foot: foot})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].score != out[j].score {
			return out[i].score > out[j].score
		}
		return out[i].foot > out[j].foot
	})
	all := make([]spearPick, 0, len(out))
	for _, s := range out {
		all = append(all, s.p)
	}
	return all, root, nil
}

// spearLibraryAll returns the whole library for the "browse all" dropdown,
// grouped by category (jobs, finance, courses, general), best first per group.
func spearLibraryAll(profile, target map[string]string) ([]spearPick, error) {
	all, _, err := spearLibraryScored(profile, target)
	if err != nil || all == nil {
		return all, err
	}
	groupOrder := map[string]int{"job": 0, "finance": 1, "learn": 2, "generic": 3}
	sort.SliceStable(all, func(i, j int) bool {
		oi, oj := groupOrder[all[i].Group], groupOrder[all[j].Group]
		if oi == oj {
			return all[i].Score > all[j].Score
		}
		return oi < oj
	})
	return all, nil
}

// spearLibGroup is one optgroup in the full-library dropdown.
type spearLibGroup struct {
	Title string
	Items []spearPick
}

// spearLibGroups buckets picks into dropdown sections with short labels.
// Brands in news get IsNew plus a ★ NEW prefix on their option label.
func spearLibGroups(all []spearPick, news map[string]bool) []spearLibGroup {
	groups := []spearLibGroup{}
	byGroup := map[string][]spearPick{}
	for _, p := range all {
		// Short dropdown label: brand + domain + trimmed subject.
		sub := []rune(p.Subject)
		if len(sub) > 70 {
			sub = append(sub[:70], []rune("...")...)
		}
		if news[strings.ToLower(p.Brand)] {
			p.IsNew = true
			p.Option = "★ NEW · " + p.Display + " (" + p.Domain + ") — " + string(sub)
		} else {
			p.Option = p.Display + " (" + p.Domain + ") — " + string(sub)
		}
		byGroup[p.Group] = append(byGroup[p.Group], p)
	}
	for _, g := range []string{"job", "finance", "learn", "generic"} {
		if len(byGroup[g]) > 0 {
			groups = append(groups, spearLibGroup{
				Title: spearGroupLabel(g), Items: byGroup[g]})
		}
	}
	return groups
}

// spearPicksFor returns the top-3 suggestions with preview snippets.
func spearPicksFor(profile, target map[string]string) ([]spearPick, error) {
	all, root, err := spearLibraryScored(profile, target)
	if err != nil || all == nil {
		return all, err
	}
	picks := []spearPick{}
	for i := 0; i < len(all) && i < 3; i++ {
		p := all[i]
		// Full text for the preview <details> (collapsed by default).
		// Capped generously so a pathological template can't bloat the page.
		if jb, err := os.ReadFile(filepath.Join(root, "json", p.Brand+".json")); err == nil {
			var lib struct {
				Text string `json:"text"`
			}
			if json.Unmarshal(jb, &lib) == nil {
				rs := []rune(strings.TrimSpace(lib.Text))
				if len(rs) > 2000 {
					rs = append(rs[:2000], []rune("\n...")...)
				}
				p.Snippet = string(rs)
			}
		}
		picks = append(picks, p)
	}
	return picks, nil
}

func cleanSpearBrand(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" || strings.Contains(s, "/") || strings.Contains(s, "\\") || strings.Contains(s, "..") {
		return ""
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '_' && r != '.' {
			return ""
		}
	}
	return s
}

// spearUseLibrary applies a library template to the wizard: it creates a
// finished generate-kind job (generator "library") so Review & Launch works
// unchanged, but the launch uses the full branded HTML instead of the wrapper.
func (h *Handler) spearUseLibrary(w http.ResponseWriter, r *http.Request) {
	d := h.baseData(pageSpear)
	_, _, _, d.SpearEnabled = h.spearAvailable()
	if err := r.ParseForm(); err != nil {
		d.Msg, d.MsgErr = "Failed to parse form: "+err.Error(), true
		h.render(w, r, "page-spear", d)
		return
	}
	src := h.getSpearJob(strings.TrimSpace(r.PostFormValue("job")))
	if src == nil || src.status != "done" {
		d.Msg, d.MsgErr = "Pick a template after enrichment finishes.", true
		h.render(w, r, "page-spear", d)
		return
	}
	brand := cleanSpearBrand(r.PostFormValue("brand"))
	if brand == "" {
		d.Msg, d.MsgErr = "Invalid template brand.", true
		h.applySpearJob(&d, src.id)
		h.render(w, r, "page-spear", d)
		return
	}
	root, ok := spearLibraryRoot()
	if !ok {
		d.Msg, d.MsgErr = "Template library not found on this server.", true
		h.applySpearJob(&d, src.id)
		h.render(w, r, "page-spear", d)
		return
	}
	jb, err := os.ReadFile(filepath.Join(root, "json", brand+".json"))
	if err != nil {
		d.Msg, d.MsgErr = "Template not found: "+brand, true
		h.applySpearJob(&d, src.id)
		h.render(w, r, "page-spear", d)
		return
	}
	var lib struct {
		Name     string `json:"name"`
		Subject  string `json:"subject"`
		Text     string `json:"text"`
		HTML     string `json:"html"`
		Envelope string `json:"envelope_sender"`
	}
	if err := json.Unmarshal(jb, &lib); err != nil || strings.TrimSpace(lib.HTML) == "" {
		d.Msg, d.MsgErr = "Template file is invalid: "+brand, true
		h.applySpearJob(&d, src.id)
		h.render(w, r, "page-spear", d)
		return
	}
	// Parent enrich job stays the single source of truth for the profile.
	parentID := src.id
	if src.kind == "generate" && src.reportID != "" {
		parentID = src.reportID
	}
	rep := src.report
	rep.Subject = lib.Subject
	rep.Body = ensureSpearText(lib.Text)
	rep.HTML = lib.HTML
	rep.Generator = "library"
	rep.Notes = append(append([]string{}, rep.Notes...), "Library template applied: "+lib.Name)
	j := &spearJob{id: core.GenRandomToken(), kind: "generate",
		linkedin: src.linkedin, channel: src.channel, lang: src.lang, sender: src.sender,
		reportID: parentID, status: "done", created: time.Now(), report: rep}
	h.setSpearJob(j)
	h.applySpearJob(&d, j.id)
	d.Msg = "Library template applied: " + lib.Name + " — review below, then launch."
	h.render(w, r, "page-spear", d)
}

// spearEnrich starts a background enrichment job for the submitted LinkedIn
// URL. The page re-renders immediately with the running banner; the embedded
// script polls /spear/jobs and reloads with ?job=<id> on completion.
func (h *Handler) spearEnrich(w http.ResponseWriter, r *http.Request) {
	d := h.baseData(pageSpear)
	_, _, _, d.SpearEnabled = h.spearAvailable()
	if err := r.ParseForm(); err != nil {
		d.Msg, d.MsgErr = "Failed to parse form: "+err.Error(), true
		h.render(w, r, "page-spear", d)
		return
	}
	linkedin := cleanLinkedIn(r.PostFormValue("linkedin"))
	channel := strings.TrimSpace(r.PostFormValue("channel"))
	if channel != "sms" {
		channel = "mail"
	}
	lang := cleanSpearLang(r.PostFormValue("lang"))
	sender := strings.TrimSpace(r.PostFormValue("sender"))
	d.SpearLinkedIn, d.SpearChannel, d.SpearSender = linkedin, channel, sender
	d.SpearLang = lang
	if linkedin == "" {
		d.Msg, d.MsgErr = "Provide a valid LinkedIn profile URL.", true
		h.render(w, r, "page-spear", d)
		return
	}
	python, script, timeout, ok := h.spearAvailable()
	if !ok {
		d.Msg, d.MsgErr = "Spear enrichment is not configured. Add a site_auditor section (python/script) to config.json next to tools/spear_enrich.py and restart.", true
		h.render(w, r, "page-spear", d)
		return
	}
	j := &spearJob{id: core.GenRandomToken(), kind: "enrich",
		linkedin: linkedin, channel: channel, lang: lang, sender: sender,
		refresh: r.PostFormValue("refresh") != "",
		status: "running", created: time.Now()}
	h.setSpearJob(j)
	go h.runSpearEnrich(j, python, script, timeout)
	d.SpearJobID = j.id
	d.SpearRunning = true
	h.render(w, r, "page-spear", d)
}

func (h *Handler) runSpearEnrich(j *spearJob, python, script string, timeout int) {
	ctx, cancel := context.WithTimeout(context.Background(),
		time.Duration(timeout)*time.Second)
	defer cancel()
	args := []string{"--linkedin", j.linkedin, "--channel", j.channel,
		"--lang", j.lang, "--enrich-only", "--timeout", strconv.Itoa(timeout)}
	if j.sender != "" {
		args = append(args, "--sender", j.sender)
	}
	if j.refresh {
		args = append(args, "--refresh")
	}
	rep, tail, err := h.spearRun(ctx, python, script, args)
	h.spearMu.Lock()
	defer h.spearMu.Unlock()
	cur := h.spearJobs[j.id]
	if cur == nil {
		return
	}
	if err != nil {
		cur.status = "error"
		cur.err = shortErr(fmt.Errorf("%v (%s)", err, tail))
		return
	}
	cur.status = "done"
	cur.report = rep
}

// spearGenerate runs message generation for a finished enrich job using the
// operator-edited prompt. The prompt travels via a temp file so arbitrarily
// long edits survive intact.
func (h *Handler) spearGenerate(w http.ResponseWriter, r *http.Request) {
	d := h.baseData(pageSpear)
	_, _, _, d.SpearEnabled = h.spearAvailable()
	if err := r.ParseForm(); err != nil {
		d.Msg, d.MsgErr = "Failed to parse form: "+err.Error(), true
		h.render(w, r, "page-spear", d)
		return
	}
	src := h.getSpearJob(strings.TrimSpace(r.PostFormValue("job")))
	if src == nil || src.status != "done" || src.kind != "enrich" {
		d.Msg, d.MsgErr = "Generate needs a finished enrichment first.", true
		h.render(w, r, "page-spear", d)
		return
	}
	prompt := r.PostFormValue("prompt")
	python, script, timeout, ok := h.spearAvailable()
	if !ok {
		d.Msg, d.MsgErr = "Spear enrichment is not configured.", true
		h.render(w, r, "page-spear", d)
		return
	}
	j := &spearJob{id: core.GenRandomToken(), kind: "generate",
		linkedin: src.linkedin, channel: src.report.Channel,
		lang: src.report.Lang, sender: src.sender, prompt: prompt, reportID: src.id,
		status: "running", created: time.Now()}
	if j.channel == "" {
		j.channel = src.channel
	}
	if j.lang == "" {
		j.lang = src.lang
	}
	if j.lang == "" {
		j.lang = "en"
	}
	h.setSpearJob(j)
	go h.runSpearGenerate(j, src, python, script, timeout)
	// Keep the wizard context so the page stays on step 3 with a progress
	// banner instead of flashing back to step 1 while the model works.
	h.applySpearJob(&d, src.id)
	d.SpearJobID = j.id
	d.SpearRunning = true
	d.SpearGoto = "spear-sec-3"
	if strings.TrimSpace(prompt) != "" {
		d.SpearPrompt = prompt
	}
	d.SpearLinkedIn, d.SpearChannel, d.SpearSender = j.linkedin, j.channel, j.sender
	h.render(w, r, "page-spear", d)
}

func (h *Handler) runSpearGenerate(j, src *spearJob, python, script string, timeout int) {
	dir, err := os.MkdirTemp("", "spear_gen_")
	if err != nil {
		h.failSpearJob(j.id, "Could not stage generation: "+err.Error())
		return
	}
	defer os.RemoveAll(dir)
	raw, err := json.Marshal(src.report)
	if err != nil {
		h.failSpearJob(j.id, "Could not serialize profile: "+err.Error())
		return
	}
	reportPath := filepath.Join(dir, "in.json")
	promptPath := filepath.Join(dir, "prompt.txt")
	if err := os.WriteFile(reportPath, raw, 0o600); err != nil {
		h.failSpearJob(j.id, "Could not stage profile: "+err.Error())
		return
	}
	args := []string{"--generate-only", "--report-in", reportPath,
		"--timeout", strconv.Itoa(timeout), "--lang", j.lang}
	if strings.TrimSpace(j.prompt) != "" {
		if err := os.WriteFile(promptPath, []byte(j.prompt), 0o600); err != nil {
			h.failSpearJob(j.id, "Could not stage prompt: "+err.Error())
			return
		}
		args = append(args, "--prompt-file", promptPath)
	}
	if j.channel != "" {
		args = append(args, "--channel", j.channel)
	}
	ctx, cancel := context.WithTimeout(context.Background(),
		time.Duration(timeout)*time.Second)
	defer cancel()
	rep, tail, err := h.spearRun(ctx, python, script, args)
	h.spearMu.Lock()
	defer h.spearMu.Unlock()
	cur := h.spearJobs[j.id]
	if cur == nil {
		return
	}
	if err != nil {
		cur.status = "error"
		cur.err = shortErr(fmt.Errorf("%v (%s)", err, tail))
		return
	}
	cur.status = "done"
	cur.report = rep
}

func (h *Handler) failSpearJob(id, msg string) {
	h.spearMu.Lock()
	defer h.spearMu.Unlock()
	if cur := h.spearJobs[id]; cur != nil {
		cur.status = "error"
		cur.err = msg
	}
}

// spearRefinePrompt builds the LLM prompt for the "edit with LLM" step: it
// carries the current message plus the operator's instruction, and forces the
// model to preserve template variables and the output format.
func spearRefinePrompt(rep spearReport, channel, instruction string) string {
	who := strings.TrimSpace(rep.Target["first_name"] + " " + rep.Target["last_name"])
	if who == "" {
		who = "the target"
	}
	pos := strings.TrimSpace(rep.Target["position"])
	current := "SUBJECT: " + strings.TrimSpace(rep.Subject) + "\n\n" + strings.TrimSpace(rep.Body)
	if channel == "sms" {
		return fmt.Sprintf("You are editing an authorized security-awareness SMS for %s (%s). "+
			"Apply this instruction: %s\n\nCurrent message:\n%s\n\n"+
			"Rules: max 300 characters, plain text, keep the landing placeholder {{URL}} exactly, "+
			"no shortened links beyond it. Output only the revised SMS text, nothing else.",
			who, pos, instruction, current)
	}
	return fmt.Sprintf("You are editing an authorized security-awareness email for %s (%s). "+
		"Apply this instruction: %s\n\nCurrent message:\n%s\n\n"+
		"Rules: keep personalization variables like {{.FirstName}} exactly as-is, "+
		"keep the landing placeholder {{URL}} exactly (do not rename or drop it), "+
		"stay realistic for an authorized test — no threats of account closure, no password requests. "+
		"Respond in exactly this format:\nSUBJECT: <subject line>\n\n<email body>",
		who, pos, instruction, current)
}

// spearRefine runs one LLM edit round on a finished message (generated or
// library). It creates a new finished-tracked generate job so Review & Launch
// works unchanged; the page polls it like any generation.
func (h *Handler) spearRefine(w http.ResponseWriter, r *http.Request) {
	d := h.baseData(pageSpear)
	_, _, _, d.SpearEnabled = h.spearAvailable()
	if err := r.ParseForm(); err != nil {
		d.Msg, d.MsgErr = "Failed to parse form: "+err.Error(), true
		h.render(w, r, "page-spear", d)
		return
	}
	src := h.getSpearJob(strings.TrimSpace(r.PostFormValue("job")))
	if src == nil || src.status != "done" || src.kind != "generate" {
		d.Msg, d.MsgErr = "Refine needs a finished message first (generate or pick a template).", true
		if src != nil {
			h.applySpearJob(&d, src.id)
		}
		h.render(w, r, "page-spear", d)
		return
	}
	instruction := strings.TrimSpace(r.PostFormValue("instruction"))
	if instruction == "" {
		d.Msg, d.MsgErr = "Write what the LLM should change (e.g. make it shorter, more formal, Arabic).", true
		h.applySpearJob(&d, src.id)
		h.render(w, r, "page-spear", d)
		return
	}
	if len([]rune(instruction)) > 2000 {
		d.Msg, d.MsgErr = "Instruction is too long (max 2000 characters).", true
		h.applySpearJob(&d, src.id)
		h.render(w, r, "page-spear", d)
		return
	}
	python, script, timeout, ok := h.spearAvailable()
	if !ok {
		d.Msg, d.MsgErr = "Spear enrichment is not configured.", true
		h.applySpearJob(&d, src.id)
		h.render(w, r, "page-spear", d)
		return
	}
	channel := src.report.Channel
	if channel != "sms" {
		channel = src.channel
	}
	if channel != "sms" {
		channel = "mail"
	}
	lang := src.report.Lang
	if lang == "" {
		lang = src.lang
	}
	if lang == "" {
		lang = "en"
	}
	// Keep pointing at the parent enrich job so profile edits still
	// invalidate this refinement like any other generated message.
	parentID := src.reportID
	if parentID == "" {
		parentID = src.id
	}
	j := &spearJob{id: core.GenRandomToken(), kind: "generate",
		linkedin: src.linkedin, channel: channel, lang: lang, sender: src.sender,
		prompt: spearRefinePrompt(src.report, channel, instruction),
		reportID: parentID, status: "running", created: time.Now()}
	h.setSpearJob(j)
	hadBranding := strings.TrimSpace(src.report.HTML) != ""
	go func() {
		h.runSpearGenerate(j, src, python, script, timeout)
		// A refinement is a fresh LLM message: if it started from a branded
		// library template, say so — the standard wrapper now applies.
		if hadBranding {
			h.spearMu.Lock()
			defer h.spearMu.Unlock()
			if cur := h.spearJobs[j.id]; cur != nil && cur.status == "done" {
				cur.report.Notes = append(cur.report.Notes,
					"Refined with LLM from a library template; the branded layout was replaced by the standard message wrapper.")
			}
		}
	}()
	// Keep the finished message on screen so the page stays on step 3 with
	// a progress banner instead of flashing back to step 1.
	h.applySpearJob(&d, src.id)
	d.SpearJobID = j.id
	d.SpearRunning = true
	d.SpearGoto = "spear-sec-3"
	d.SpearLinkedIn, d.SpearChannel, d.SpearSender = j.linkedin, j.channel, j.sender
	h.render(w, r, "page-spear", d)
}

// spearMessageSave stores operator hand-edits to the generated message so
// the Result box is editable: what you save is exactly what launch uses.
// A hand edit clears any branded library HTML (it no longer matches the
// edited text) with a note, mirroring the refine behavior.
func (h *Handler) spearMessageSave(w http.ResponseWriter, r *http.Request) {
	d := h.baseData(pageSpear)
	_, _, _, d.SpearEnabled = h.spearAvailable()
	if err := r.ParseForm(); err != nil {
		d.Msg, d.MsgErr = "Failed to parse form: "+err.Error(), true
		h.render(w, r, "page-spear", d)
		return
	}
	j := h.getSpearJob(strings.TrimSpace(r.PostFormValue("job")))
	if j == nil || j.status != "done" || j.kind != "generate" {
		d.Msg, d.MsgErr = "Save needs a finished message first.", true
		if j != nil {
			h.applySpearJob(&d, j.id)
		}
		h.render(w, r, "page-spear", d)
		return
	}
	subject := strings.TrimSpace(r.PostFormValue("subject"))
	body := strings.TrimSpace(r.PostFormValue("body"))
	channel := j.report.Channel
	if channel != "sms" {
		channel = j.channel
	}
	if channel != "sms" && subject == "" {
		d.Msg, d.MsgErr = "Subject is empty — launch would fall back to a generic one.", true
		h.applySpearJob(&d, j.id)
		h.render(w, r, "page-spear", d)
		return
	}
	if body == "" {
		d.Msg, d.MsgErr = "Message body is empty.", true
		h.applySpearJob(&d, j.id)
		h.render(w, r, "page-spear", d)
		return
	}
	if !strings.Contains(spearLandingURL(body), "{{.URL}}") {
		d.Msg, d.MsgErr = "Body must contain the {{URL}} landing placeholder — otherwise targets get no link.", true
		h.applySpearJob(&d, j.id)
		h.render(w, r, "page-spear", d)
		return
	}
	h.spearMu.Lock()
	cur := h.spearJobs[j.id]
	if cur == nil || cur.status != "done" {
		h.spearMu.Unlock()
		d.Msg, d.MsgErr = "Save needs a finished message first.", true
		h.render(w, r, "page-spear", d)
		return
	}
	if channel != "sms" {
		cur.report.Subject = subject
	}
	cur.report.Body = body
	if strings.TrimSpace(cur.report.HTML) != "" {
		cur.report.HTML = ""
		cur.report.Notes = append(cur.report.Notes,
			"Hand-edited by operator; the branded library layout was replaced by the standard message wrapper.")
	} else {
		cur.report.Notes = append(cur.report.Notes, "Hand-edited by operator.")
	}
	h.spearMu.Unlock()
	h.applySpearJob(&d, j.id)
	d.Msg = "Message updated — review step uses exactly this text."
	h.render(w, r, "page-spear", d)
}

// spearProfileSave stores hand edits to the enriched profile (step 2 is the
// single place where target details change) and rebuilds the campaign
// target from it. Editing an earlier step invalidates any message already
// generated from it, so derived generate jobs are dropped and the operator
// regenerates — stale data can never reach a launch.
func (h *Handler) spearProfileSave(w http.ResponseWriter, r *http.Request) {
	d := h.baseData(pageSpear)
	_, _, _, d.SpearEnabled = h.spearAvailable()
	if err := r.ParseForm(); err != nil {
		d.Msg, d.MsgErr = "Failed to parse form: "+err.Error(), true
		h.render(w, r, "page-spear", d)
		return
	}
	j := h.getSpearJob(strings.TrimSpace(r.PostFormValue("job")))
	if j == nil || j.status != "done" {
		d.Msg, d.MsgErr = "Save needs a finished enrichment first.", true
		h.render(w, r, "page-spear", d)
		return
	}
	// Resolve the enrich job holding the profile (a generate job only
	// carries a snapshot copy of it).
	ej := j
	if j.kind == "generate" && j.reportID != "" {
		if orig := h.getSpearJob(j.reportID); orig != nil {
			ej = orig
		}
	}
	if ej.report.Profile == nil {
		ej.report.Profile = map[string]string{}
	}
	ej.report.Profile["Name"] = strings.TrimSpace(r.PostFormValue("name"))
	ej.report.Profile["Current_Position"] = strings.TrimSpace(r.PostFormValue("position"))
	ej.report.Profile["Company"] = strings.TrimSpace(r.PostFormValue("company"))
	ej.report.Profile["Location"] = strings.TrimSpace(r.PostFormValue("location"))
	ej.report.Profile["Industry"] = strings.TrimSpace(r.PostFormValue("industry"))
	ej.report.Profile["Email"] = strings.TrimSpace(r.PostFormValue("email"))
	rebuildSpearTarget(&ej.report)
	// Drop generate results derived from the pre-edit profile.
	h.spearMu.Lock()
	for id, gj := range h.spearJobs {
		if gj.kind == "generate" && gj.reportID == ej.id {
			delete(h.spearJobs, id)
		}
	}
	h.spearMu.Unlock()
	d.Msg = "Profile updated."
	h.applySpearJob(&d, ej.id)
	h.render(w, r, "page-spear", d)
}

// spearJobsStatus returns the JSON status of a single job (or of all jobs)
// for the polling script on the spear page. GET only, no CSRF involved.
func (h *Handler) spearJobsStatus(w http.ResponseWriter, r *http.Request) {
	type jobStatus struct {
		Job    string `json:"job"`
		Kind   string `json:"kind"`
		Status string `json:"status"`
		Err    string `json:"err,omitempty"`
	}
	enc := json.NewEncoder(w)
	if q := r.URL.Query().Get("job"); q != "" {
		j := h.getSpearJob(q)
		if j == nil {
			enc.Encode(jobStatus{Job: q, Status: "missing"})
			return
		}
		enc.Encode(jobStatus{Job: j.id, Kind: j.kind, Status: j.status, Err: j.err})
		return
	}
	h.spearMu.Lock()
	list := make([]*spearJob, 0, len(h.spearJobs))
	for _, j := range h.spearJobs {
		list = append(list, j)
	}
	h.spearMu.Unlock()
	out := make([]jobStatus, 0, len(list))
	for _, j := range list {
		out = append(out, jobStatus{Job: j.id, Kind: j.kind, Status: j.status, Err: j.err})
	}
	enc.Encode(out)
}

// spearAPIClient is the minimal surface used to drive campaign creation
// through the platform's own REST API. The HTTP implementation talks to the
// local admin listener; tests stub it.
type spearAPIClient interface {
	get(path string) ([]byte, error)
	post(path string, payload any) (status int, body []byte, err error)
}

type httpSpearAPI struct {
	base   string
	key    string
	client *http.Client
}

func (a *httpSpearAPI) auth(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+a.key)
}

func apiErrorMessage(status int, body []byte) string {
	var parsed struct {
		Message string `json:"message"`
		Error   string `json:"error"`
		Detail  string `json:"detail"`
	}
	if err := json.Unmarshal(body, &parsed); err == nil {
		for _, m := range []string{parsed.Message, parsed.Error, parsed.Detail} {
			if strings.TrimSpace(m) != "" {
				return fmt.Sprintf("API %d: %s", status, strings.TrimSpace(m))
			}
		}
	}
	if t := strings.TrimSpace(string(body)); t != "" && len(t) < 300 {
		return fmt.Sprintf("API %d: %s", status, t)
	}
	return fmt.Sprintf("API %d", status)
}

func (a *httpSpearAPI) get(path string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, a.base+path, nil)
	if err != nil {
		return nil, err
	}
	a.auth(req)
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, errors.New(apiErrorMessage(resp.StatusCode, body))
	}
	return body, nil
}

func (a *httpSpearAPI) post(path string, payload any) (int, []byte, error) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(payload); err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequest(http.MethodPost, a.base+path, &buf)
	if err != nil {
		return 0, nil, err
	}
	a.auth(req)
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 && resp.StatusCode != http.StatusConflict {
		return resp.StatusCode, body,
			errors.New(apiErrorMessage(resp.StatusCode, body))
	}
	return resp.StatusCode, body, nil
}

func (h *Handler) apiClient() (spearAPIClient, error) {
	if strings.TrimSpace(h.apiBase) == "" || h.apiKeyFunc == nil {
		return nil, errors.New("campaign launch is unavailable – the panel was started without admin API access")
	}
	key, err := h.apiKeyFunc()
	if err != nil || strings.TrimSpace(key) == "" {
		return nil, errors.New("campaign launch is unavailable – no admin API key found")
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	return &httpSpearAPI{
		base:   strings.TrimSuffix(strings.TrimSpace(h.apiBase), "/"),
		key:    strings.TrimSpace(key),
		client: &http.Client{Timeout: 30 * time.Second, Transport: tr},
	}, nil
}

// spearProfileNames lists sending-profile names for the review select, using
// the same endpoints the dashboard modals read.
func (h *Handler) spearProfileNames(channel string) ([]string, error) {
	api, err := h.apiClient()
	if err != nil {
		return nil, err
	}
	path := "/api/smtp/"
	if channel == "sms" {
		path = "/api/sms/"
	}
	raw, err := api.get(path)
	if err != nil {
		return nil, err
	}
	var items []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, fmt.Errorf("invalid profiles response: %v", err)
	}
	names := make([]string, 0, len(items))
	for _, it := range items {
		if strings.TrimSpace(it.Name) != "" {
			names = append(names, it.Name)
		}
	}
	return names, nil
}

// postUnique creates an object, retrying with a numeric suffix while the API
// answers 409 (the platform's "name already in use" signal).
func postUnique(api spearAPIClient, path, base string,
	makePayload func(name string) any) (string, []byte, error) {
	name := base
	for i := 1; ; i++ {
		status, raw, err := api.post(path, makePayload(name))
		if err != nil {
			return "", nil, err
		}
		if status != http.StatusConflict {
			return name, raw, nil
		}
		i++
		name = fmt.Sprintf("%s %d", base, i)
		if i > 5 {
			return "", nil, fmt.Errorf("%s: name %q is already in use", path, base)
		}
	}
}

func spearLandingURL(body string) string {
	s := strings.ReplaceAll(body, "{{URL}}", "{{.URL}}")
	// Tolerate common LLM variants so the lure link never gets lost.
	s = strings.ReplaceAll(s, "{{url}}", "{{.URL}}")
	s = strings.ReplaceAll(s, "{{ URL }}", "{{.URL}}")
	return s
}

func spearHTMLBody(body string) string {
	esc := html.EscapeString(spearLandingURL(body))
	esc = strings.ReplaceAll(esc, "\n", "<br>")
	paras := strings.ReplaceAll(esc, "<br><br>", "</p><p>")
	// Outlook-safe table layout (no flex/div-only). CTA + fallback link use
	// {{.URL}} (evilginx lure with encrypted rid); {{.Tracker}} is the open
	// pixel and must stay last, otherwise open-tracking silently breaks.
	return `<html><head><meta charset="utf-8"></head><body style="margin:0;padding:0;background:#f4f4f4;font-family:Arial,Helvetica,sans-serif;">` +
		`<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f4;"><tr><td align="center">` +
		`<table role="presentation" width="600" cellpadding="0" cellspacing="0" style="background:#ffffff;border:1px solid #e0e0e0;border-radius:8px;margin:20px auto;">` +
		`<tr><td style="padding:28px 24px;color:#222;font-size:14px;line-height:1.7;"><p>` + paras + `</p>` +
		`<table role="presentation" cellpadding="0" cellspacing="0" style="margin:22px auto;"><tr><td align="center" bgcolor="#2563eb" style="border-radius:6px;"><a href="{{.URL}}" style="display:inline-block;padding:13px 34px;color:#ffffff;text-decoration:none;font-weight:bold;font-size:15px;">Open Secure Link</a></td></tr></table>` +
		`<p style="font-size:12px;color:#666;">If the button doesn't work, copy this link:<br><span style="color:#2563eb;">{{.URL}}</span></p>` +
		`<p style="font-size:12px;color:#666;">Recipient: {{.Email}} &nbsp;|&nbsp; ID: {{.RId}}</p>` +
		`</td></tr></table></td></tr></table>{{.Tracker}}</body></html>`
}

// ensureSpearText guarantees the text part carries the landing link even when
// the model forgets the placeholder.
func ensureSpearText(text string) string {
	t := spearLandingURL(text)
	if !strings.Contains(t, "{{.URL}}") {
		t = strings.TrimSpace(t) + "\n\nLink: {{.URL}}"
	}
	return t
}

var spearAssetImgRe = regexp.MustCompile(`(?i)<img[^>]+src=["'](https?://[^"']+)["']`)

// spearProbeURL HEADs an asset (GET fallback for servers refusing HEAD).
// Returns 0 + error text when unreachable.
func spearProbeURL(client *http.Client, u string) (int, string) {
	for _, method := range []string{http.MethodHead, http.MethodGet} {
		req, err := http.NewRequest(method, u, nil)
		if err != nil {
			return 0, err.Error()
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (template-asset-check)")
		resp, err := client.Do(req)
		if err != nil {
			if method == http.MethodHead {
				continue
			}
			return 0, err.Error()
		}
		resp.Body.Close()
		if resp.StatusCode < 400 {
			return resp.StatusCode, ""
		}
		if method == http.MethodHead && (resp.StatusCode == http.StatusForbidden ||
			resp.StatusCode == http.StatusMethodNotAllowed) {
			continue
		}
		return resp.StatusCode, http.StatusText(resp.StatusCode)
	}
	return 0, "unreachable"
}

// spearCheckAssets is the pre-launch validation hook: it verifies the final
// mail HTML carries the critical template vars and that every external image
// actually loads, so targets never see broken-image icons. It passes silently
// when there are no external images (plain-text style templates).
// BLACKCAT_SKIP_ASSET_CHECK=1 escapes the network part for offline labs
// (the {{.URL}}/{{.Tracker}} presence check always runs).
func spearCheckAssets(htmlBody string) error {
	if !strings.Contains(htmlBody, "{{.URL}}") {
		return errors.New("template HTML is missing {{.URL}} — targets would get no landing link")
	}
	if !strings.Contains(htmlBody, "{{.Tracker}}") {
		return errors.New("template HTML is missing {{.Tracker}} — email-open tracking would silently break")
	}
	matches := spearAssetImgRe.FindAllStringSubmatch(htmlBody, 9)
	if len(matches) == 0 {
		return nil
	}
	seen := map[string]bool{}
	urls := []string{}
	for _, m := range matches {
		u := m[1]
		if strings.Contains(u, "{{") || strings.Contains(u, "}}") {
			continue
		}
		if !seen[u] {
			seen[u] = true
			urls = append(urls, u)
		}
	}
	if len(urls) == 0 || os.Getenv("BLACKCAT_SKIP_ASSET_CHECK") == "1" {
		return nil
	}
	client := &http.Client{Timeout: 5 * time.Second}
	type probe struct {
		url  string
		code int
		note string
	}
	out := make(chan probe, len(urls))
	for _, u := range urls {
		go func(u string) {
			code, note := spearProbeURL(client, u)
			out <- probe{u, code, note}
		}(u)
	}
	dead := []string{}
	for range urls {
		r := <-out
		if r.code >= 400 || r.code == 0 {
			detail := r.note
			if r.code >= 400 {
				detail = fmt.Sprintf("HTTP %d %s", r.code, r.note)
			}
			dead = append(dead, fmt.Sprintf("%s (%s)", r.url, detail))
		}
	}
	if len(dead) > 0 {
		return fmt.Errorf("dead template assets would show broken images to targets: %s — self-host the logo or pick another template",
			strings.Join(dead, "; "))
	}
	return nil
}

// spearLaunch consumes a finished generate job and creates the single-target
// Group, Template and Campaign through the platform APIs — the same payloads
// the dashboard modals send, so tracking and results behave identically.
func (h *Handler) spearLaunch(w http.ResponseWriter, r *http.Request) {
	d := h.baseData(pageSpear)
	_, _, _, d.SpearEnabled = h.spearAvailable()
	if err := r.ParseForm(); err != nil {
		d.Msg, d.MsgErr = "Failed to parse form: "+err.Error(), true
		h.render(w, r, "page-spear", d)
		return
	}
	gj := h.getSpearJob(strings.TrimSpace(r.PostFormValue("job")))
	if gj == nil || gj.status != "done" || gj.kind != "generate" {
		d.Msg, d.MsgErr = "Launch needs a finished message first.", true
		h.render(w, r, "page-spear", d)
		return
	}
	// Restore wizard state first so validation errors keep everything the
	// operator already filled in.
	h.applySpearJob(&d, gj.id)
	rep := gj.report
	channel := rep.Channel
	if channel != "sms" {
		channel = "mail"
	}
	campaign := strings.TrimSpace(r.PostFormValue("campaign"))
	lure := strings.TrimSpace(r.PostFormValue("url"))
	profile := strings.TrimSpace(r.PostFormValue("profile"))
	phone := strings.TrimSpace(r.PostFormValue("phone"))
	d.SpearCampaign, d.SpearURL, d.SpearPhone = campaign, lure, phone
	if campaign == "" {
		d.Msg, d.MsgErr = "Give the campaign a name.", true
		h.render(w, r, "page-spear", d)
		return
	}
	// Keep spear launches listable: the list page picks campaigns out by
	// this prefix, mirroring the group/template naming.
	campaign = spearCampaignName(campaign)
	if lure == "" {
		d.Msg, d.MsgErr = "Provide the lure URL targets open.", true
		h.render(w, r, "page-spear", d)
		return
	}
	if profile == "" {
		d.Msg, d.MsgErr = "Choose a sending profile.", true
		h.render(w, r, "page-spear", d)
		return
	}
	address := strings.TrimSpace(rep.Target["email"])
	if channel == "sms" {
		if phone == "" {
			d.Msg, d.MsgErr = "SMS needs the target phone number (it goes into the Email column).", true
			h.render(w, r, "page-spear", d)
			return
		}
		address = phone
	} else if address == "" {
		d.Msg, d.MsgErr = "No email for this target — add it in step 2 before launching a mail campaign.", true
		h.render(w, r, "page-spear", d)
		return
	}
	api, err := h.apiClient()
	if err != nil {
		d.Msg, d.MsgErr = err.Error(), true
		h.render(w, r, "page-spear", d)
		return
	}
	base := "Spear - " + spearDisplayName(rep.Target)

	// Pre-launch validation FIRST so a broken template fails before any group
	// exists (no orphans): vars + live external images for mail.
	launchSubject := strings.TrimSpace(rep.Subject)
	if channel == "mail" && launchSubject == "" {
		launchSubject = "A quick security check"
	}
	launchHTML := spearHTMLBody(rep.Body)
	if strings.TrimSpace(rep.HTML) != "" {
		launchHTML = spearLandingURL(rep.HTML)
	}
	launchText := ensureSpearText(rep.Body)
	if channel == "mail" {
		if err := spearCheckAssets(launchHTML); err != nil {
			d.Msg, d.MsgErr = fmt.Sprintf("Pre-launch check failed: %v", err), true
			h.render(w, r, "page-spear", d)
			return
		}
	}

	// 1) Single-target group.
	groupName, _, err := postUnique(api, "/api/groups/", base,
		func(name string) any {
			return map[string]any{"name": name, "targets": []any{
				map[string]any{
					"first_name": strings.TrimSpace(rep.Target["first_name"]),
					"last_name":  strings.TrimSpace(rep.Target["last_name"]),
					"email":      address,
					"position":   strings.TrimSpace(rep.Target["position"]),
				},
			}}
		})
	if err != nil {
		d.Msg, d.MsgErr = "Group creation failed: "+err.Error(), true
		h.render(w, r, "page-spear", d)
		return
	}

	// 2) Template from the generated message — or the full branded HTML when
	// the operator picked a library template (generator "library").
	// Bodies were pre-validated above; reuse them verbatim.
	templateName, _, err := postUnique(api, "/api/templates/", base,
		func(name string) any {
			if channel == "sms" {
				return map[string]any{"name": name,
					"text": launchText}
			}
			return map[string]any{"name": name, "subject": launchSubject,
				"text": launchText,
				"html": launchHTML}
		})
	if err != nil {
		d.Msg, d.MsgErr = fmt.Sprintf("Template creation failed: %v (group %q was created and can be reused).", err, groupName), true
		h.render(w, r, "page-spear", d)
		return
	}

	// 3) Campaign — the dashboard modal payload, verbatim in shape.
	launch := time.Now().UTC().Format(time.RFC3339)
	var campPath string
	var campPayload map[string]any
	if channel == "sms" {
		campPath = "/api/sms_campaigns/"
		campPayload = map[string]any{"name": campaign,
			"template":    map[string]any{"name": templateName},
			"url":         lure,
			"sms":         map[string]any{"name": profile},
			"launch_date": launch,
			"groups":      []any{map[string]any{"name": groupName}}}
	} else {
		campPath = "/api/campaigns/"
		campPayload = map[string]any{"name": campaign,
			"template":    map[string]any{"name": templateName},
			"url":         lure,
			"smtp":        map[string]any{"name": profile},
			"launch_date": launch,
			"groups":      []any{map[string]any{"name": groupName}}}
	}
	status, raw, err := api.post(campPath, campPayload)
	if err != nil || (status != http.StatusOK && status != http.StatusCreated) {
		if err == nil {
			err = errors.New(apiErrorMessage(status, raw))
		}
		d.Msg, d.MsgErr = fmt.Sprintf("Campaign launch failed: %v (group %q and template %q were created and can be reused).", err, groupName, templateName), true
		h.render(w, r, "page-spear", d)
		return
	}
	var created struct {
		ID int64 `json:"id"`
	}
	_ = json.Unmarshal(raw, &created)
	d.SpearDone = true
	d.SpearDoneKind = channel
	d.SpearDoneID = created.ID
	d.SpearDoneName = campaign
	d.Msg = fmt.Sprintf("Spear campaign %q launched (group %q, template %q).",
		campaign, groupName, templateName)
	h.render(w, r, "page-spear", d)
}
