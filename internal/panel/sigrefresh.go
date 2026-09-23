package panel

// Library refresh flow: one button re-runs the signclone pipeline end to
// end — sign.py harvests fresh signatures from the Gmail accounts, then
// convert_to_gophish.py rebuilds the GoPhish templates. The picker reads
// index.csv live, so new brands appear without a restart.
//
// Long-running like the audit pattern: POST starts (or reuses) a background
// job, GET polls it, the page reloads on completion.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/kgretzky/evilginx2/core"
)

// sigRefreshTimeout bounds the whole harvest+convert run (mailbox scans are
// inherently slow: pagination plus per-message throttling in sign.py).
const sigRefreshTimeout = 30 * time.Minute

// sigRefreshJob is one library-refresh run. Jobs are transient in-memory
// state; the refreshed files on disk are the real result.
type sigRefreshJob struct {
	id          string
	accounts    int
	status      string // "running" | "done" | "error"
	err         string
	sigBefore   int
	sigAfter    int
	templates   int
	beforeNames []string // signature stems present at start (to spot new ones)
	created     time.Time
}

// lastNewFileName records which brands the latest refresh added, so the
// picker can badge them ★ NEW.
const lastNewFileName = ".last_new.json"

// listSigStems returns the brand stems (*.txt without extension) in dir.
func listSigStems(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	out := []string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".txt") {
			continue
		}
		out = append(out, strings.TrimSuffix(e.Name(), ".txt"))
	}
	return out
}

// diffNew returns stems present in after but not before.
func diffNew(before, after []string) []string {
	had := map[string]bool{}
	for _, b := range before {
		had[strings.ToLower(b)] = true
	}
	var added []string
	for _, a := range after {
		if !had[strings.ToLower(a)] {
			added = append(added, a)
		}
	}
	return added
}

// writeLastNew persists the newly added brands for the picker badges.
// Silent on any failure (badging is best-effort, never blocks the flow).
func writeLastNew(templatesDir string, brands []string) {
	if templatesDir == "" {
		return
	}
	if st, err := os.Stat(templatesDir); err != nil || !st.IsDir() {
		return
	}
	raw, _ := json.Marshal(map[string]any{"brands": brands})
	_ = os.WriteFile(filepath.Join(templatesDir, lastNewFileName), raw, 0o644)
}

// loadLastNew returns the brands badged ★ NEW (empty when never refreshed).
func loadLastNew(templatesDir string) map[string]bool {
	out := map[string]bool{}
	raw, err := os.ReadFile(filepath.Join(templatesDir, lastNewFileName))
	if err != nil {
		return out
	}
	var parsed struct {
		Brands []string `json:"brands"`
	}
	if json.Unmarshal(raw, &parsed) != nil {
		return out
	}
	for _, b := range parsed.Brands {
		out[strings.ToLower(b)] = true
	}
	return out
}

// sigRefreshFunc executes the two scripts and returns counts. It is a field
// (not a direct exec call) so tests can stub the harvest.
type sigRefreshFunc func(ctx context.Context, python, dir string, accounts int) (sigBefore, sigAfter, templates int, tail string, err error)

// spearSigncloneDir locates the signclone pipeline directory (sign.py +
// convert_to_gophish.py). (nil-ok false) when the panel runs without it.
func spearSigncloneDir() (string, bool) {
	cands := []string{}
	if wd, err := os.Getwd(); err == nil {
		cands = append(cands, filepath.Join(wd, "signclone"))
		// panel tests run inside internal/panel: repo root is ../..
		cands = append(cands, filepath.Join(wd, "..", "..", "signclone"))
	}
	if ex, err := os.Executable(); err == nil {
		d := filepath.Dir(ex)
		for i := 0; i < 4; i++ {
			cands = append(cands, filepath.Join(d, "signclone"))
			d = filepath.Dir(d)
		}
	}
	for _, c := range cands {
		if st, err := os.Stat(filepath.Join(c, "sign.py")); err == nil && !st.IsDir() {
			return c, true
		}
	}
	return "", false
}

// sigPython picks the interpreter: the configured auditor python when set,
// else the platform default.
func (h *Handler) sigPython() string {
	if h.audit.Enabled && h.audit.Python != "" {
		return h.audit.Python
	}
	if runtime.GOOS == "windows" {
		return "py"
	}
	return "python3"
}

func countSigFiles(dir, sub, ext string) int {
	entries, err := os.ReadDir(filepath.Join(dir, sub))
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(strings.ToLower(e.Name()), ext) {
			n++
		}
	}
	return n
}

// defaultSigRefreshRun is the real pipeline: harvest then convert, counting
// signatures before/after plus rebuilt templates.
func defaultSigRefreshRun(ctx context.Context, python, dir string, accounts int) (int, int, int, string, error) {
	before := countSigFiles(dir, "company_signatures", ".txt")
	run := func(script string, args ...string) (string, error) {
		full := append([]string{script}, args...)
		cmd := exec.CommandContext(ctx, python, full...)
		cmd.Dir = dir
		var stderr strings.Builder
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return tailText(stderr.String()),
				fmt.Errorf("%s failed: %v", script, err)
		}
		return "", nil
	}
	if tail, err := run("sign.py", "--accounts", strconv.Itoa(accounts)); err != nil {
		return before, before, 0, tail, err
	}
	if tail, err := run("convert_to_gophish.py", "--min-len", "30", "--no-logo-check"); err != nil {
		// Harvest succeeded but conversion broke: report counts without templates.
		after := countSigFiles(dir, "company_signatures", ".txt")
		return before, after, 0, tail, err
	}
	after := countSigFiles(dir, "company_signatures", ".txt")
	templates := countSigFiles(dir, filepath.Join("gophish_templates", "json"), ".json")
	return before, after, templates, "", nil
}

func (h *Handler) getSigJob(id string) *sigRefreshJob {
	h.sigMu.Lock()
	defer h.sigMu.Unlock()
	return h.sigJobs[id]
}

// spearSigRefresh starts (or reuses) a library refresh job.
func (h *Handler) spearSigRefresh(w http.ResponseWriter, r *http.Request) {
	d := h.baseData(pageSpear)
	_, _, _, d.SpearEnabled = h.spearAvailable()
	if err := r.ParseForm(); err != nil {
		d.Msg, d.MsgErr = "Failed to parse form: "+err.Error(), true
		h.render(w, r, "page-spear", d)
		return
	}
	spearID := strings.TrimSpace(r.PostFormValue("job"))
	if spearID != "" {
		h.applySpearJob(&d, spearID)
		d.SpearGoto = "spear-sec-3"
	}
	accounts := 3
	if n, err := strconv.Atoi(strings.TrimSpace(r.PostFormValue("accounts"))); err == nil {
		accounts = min(max(n, 1), 5)
	}
	dir, ok := spearSigncloneDir()
	if !ok {
		d.Msg, d.MsgErr = "Signature pipeline not found on this server (signclone/ missing).", true
		h.render(w, r, "page-spear", d)
		return
	}
	// Single-flight: an already-running refresh is reused, never duplicated.
	h.sigMu.Lock()
	for _, j := range h.sigJobs {
		if j.status == "running" {
			h.sigMu.Unlock()
			d.SigRefreshJobID = j.id
			d.SpearJobID = spearID
			d.SigRefreshing = true
			d.Msg = "A library refresh is already running — attached to it."
			h.render(w, r, "page-spear", d)
			return
		}
	}
	// Prune history, keep it bounded like spear jobs.
	if len(h.sigJobs) >= 20 {
		var oldest string
		var oldestTime time.Time
		for k, v := range h.sigJobs {
			if oldest == "" || v.created.Before(oldestTime) {
				oldest, oldestTime = k, v.created
			}
		}
		delete(h.sigJobs, oldest)
	}
	j := &sigRefreshJob{id: core.GenRandomToken(), accounts: accounts,
		status: "running", created: time.Now(),
		beforeNames: listSigStems(filepath.Join(dir, "company_signatures"))}
	h.sigJobs[j.id] = j
	h.sigMu.Unlock()

	python := h.sigPython()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), sigRefreshTimeout)
		defer cancel()
		run := h.sigRun
		if run == nil {
			run = defaultSigRefreshRun
		}
		before, after, templates, tail, err := run(ctx, python, dir, accounts)
		h.sigMu.Lock()
		defer h.sigMu.Unlock()
		cur := h.sigJobs[j.id]
		if cur == nil {
			return
		}
		if err != nil {
			cur.status = "error"
			cur.err = shortErr(fmt.Errorf("%v (%s)", err, tail))
			return
		}
		cur.status = "done"
		cur.sigBefore, cur.sigAfter, cur.templates = before, after, templates
		writeLastNew(filepath.Join(dir, "gophish_templates"),
			diffNew(cur.beforeNames, listSigStems(filepath.Join(dir, "company_signatures"))))
	}()

	d.SigRefreshJobID = j.id
	d.SpearJobID = spearID
	d.SigRefreshing = true
	h.render(w, r, "page-spear", d)
}

// spearSigStatus reports one refresh job as JSON for the picker polling script.
func (h *Handler) spearSigStatus(w http.ResponseWriter, r *http.Request) {
	type status struct {
		Job       string `json:"job"`
		Status    string `json:"status"`
		Err       string `json:"err,omitempty"`
		Accounts  int    `json:"accounts,omitempty"`
		SigBefore int    `json:"sig_before,omitempty"`
		SigAfter  int    `json:"sig_after,omitempty"`
		SigNew    int    `json:"sig_new,omitempty"`
		Templates int    `json:"templates,omitempty"`
	}
	enc := json.NewEncoder(w)
	q := r.URL.Query().Get("job")
	j := h.getSigJob(q)
	if j == nil {
		enc.Encode(status{Job: q, Status: "missing"})
		return
	}
	out := status{Job: j.id, Status: j.status, Err: j.err, Accounts: j.accounts,
		SigBefore: j.sigBefore, SigAfter: j.sigAfter, Templates: j.templates}
	if j.status == "done" {
		out.SigNew = j.sigAfter - j.sigBefore
		if out.SigNew < 0 {
			out.SigNew = 0
		}
	}
	enc.Encode(out)
}

// applySigRefreshJob renders a finished/failed refresh into the picker area.
func (h *Handler) applySigRefreshJob(d *pageData, jid string) {
	j := h.getSigJob(jid)
	if j == nil {
		d.SigRefreshErr = "Refresh job not found."
		return
	}
	d.SigRefreshJobID = j.id
	switch j.status {
	case "running":
		d.SigRefreshing = true
	case "done":
		newCount := j.sigAfter - j.sigBefore
		if newCount < 0 {
			newCount = 0
		}
		d.SigRefreshDone = fmt.Sprintf(
			"Library refreshed: %d signatures (%d new) → %d templates.",
			j.sigAfter, newCount, j.templates)
	case "error":
		d.SigRefreshErr = j.err
	}
}
