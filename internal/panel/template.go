package panel

// pageTemplate holds the self-contained panel pages. It is a single template
// set with one full page per route plus shared partials (head/CSS, topbar,
// message banner). All request handlers run behind the gophish admin login
// and the gorilla/csrf middleware, so every POST form carries a csrf_token
// field. Links and form actions are prefixed with .Base, the mount point the
// handler is served under.
const pageTemplate = `{{define "doc-head"}}<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link rel="shortcut icon" href="/images/blackcat.svg" type="image/svg+xml">
<link rel="icon" href="/images/blackcat.svg" type="image/svg+xml">
<title>Black Cat &middot; {{.Page}}</title>
<link href="/css/dist/gophish.css" rel="stylesheet" type="text/css">
<link href="/css/blackcat.css" rel="stylesheet" type="text/css">
<link href='https://fonts.googleapis.com/css?family=Roboto:700,500' rel='stylesheet' type='text/css'>
<link href='https://fonts.googleapis.com/css?family=Source+Sans+Pro:400,300,600,700' rel='stylesheet' type='text/css'>
<style>
  /* Black Cat panel components. The page shell (brand bar, unified menu,
     page background, typography) comes from the shared stylesheets above,
     so these pages render inside the exact same Black Cat layout as the
     main dashboard. Only panel-unique components are styled here. */
  main { max-width: 980px; margin: 24px auto; padding: 0 16px 48px; }
  section { background: linear-gradient(180deg, #16213f 0%, #121b36 100%); border: 1px solid rgba(76,201,240,.16); border-radius: 16px; padding: 18px 22px; margin-bottom: 22px; box-shadow: 0 10px 30px rgba(0,0,0,.35); scroll-margin-top: 130px; }
  .spear-steps { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 18px; }
  .spear-step { display: inline-flex; align-items: center; gap: 8px; padding: 8px 14px; border-radius: 12px; border: 1px solid rgba(76,201,240,.16); background: rgba(22,33,63,.6); color: #94a3b8; font-size: 13px; font-weight: 700; }
  .spear-step span { width: 22px; height: 22px; border-radius: 50%; display: inline-flex; align-items: center; justify-content: center; font-size: 12px; background: rgba(148,163,184,.2); color: #f1f5f9; }
  .spear-step.done { color: #aee7ff; border-color: rgba(76,201,240,.4); }
  .spear-step.done span { background: rgba(46,204,113,.25); color: #5df08f; }
  button.spear-step { font: inherit; }
  button.spear-step:disabled { opacity: .45; cursor: default; }
  button.spear-step:not(:disabled) { cursor: pointer; }
  .spear-step.locked { opacity: .45; }
  .spear-step.current, .spear-step.view { color: #06121f; background: linear-gradient(90deg, #4cc9f0, #7bdff5); border-color: rgba(76,201,240,.6); box-shadow: 0 0 12px rgba(76,201,240,.55); }
  .spear-step.current span, .spear-step.view span { background: rgba(6,18,31,.25); color: #06121f; }
  .spear-sec { display: none; }
  .spear-sec.open { display: block; }
  h2 { margin-top: 0; font-size: 15px; text-transform: uppercase; letter-spacing: .05em; color: #4cc9f0; }
  section p { color: #c6cfe0; }
  ul.status { list-style: none; padding: 0; margin: 0 0 16px; display: flex; flex-wrap: wrap; gap: 24px; }
  ul.status li b { display: block; color: #fff; font-size: 15px; }
  ul.status li small { color: #94a3b8; font-size: 12px; }
  .cards { display: flex; flex-wrap: wrap; gap: 16px; margin-bottom: 6px; }
  .card { flex: 1 1 180px; background: rgba(76,201,240,.06); border: 1px solid rgba(76,201,240,.16); border-radius: 16px; padding: 12px 16px; }
  .card b { display: block; font-size: 22px; color: #fff; }
  .card small { color: #94a3b8; font-size: 12px; }
  table { width: 100%; border-collapse: collapse; font-size: 14px; }
  th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid rgba(148,163,184,.14); vertical-align: middle; }
  tr:hover td { background: rgba(76,201,240,.05); }
  th { color: #4cc9f0; font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
  td { color: #f1f5f9; }
  .badge { display: inline-block; padding: 2px 10px; border-radius: 999px; font-size: 12px; font-weight: 700; }
  .on { background: rgba(46,204,113,.16); color: #5df08f; border: 1px solid rgba(46,204,113,.4); }
  .off { background: rgba(240,91,79,.14); color: #ff9d94; border: 1px solid rgba(240,91,79,.4); }
  .warn { background: rgba(243,156,18,.16); color: #ffd166; border: 1px solid rgba(243,156,18,.4); }
  .msg { border-radius: 12px; padding: 10px 14px; margin-bottom: 16px; font-size: 14px; border: 1px solid rgba(76,201,240,.16); }
  .msg.ok { background: rgba(46,204,113,.12); color: #d7ffe2; border-color: rgba(46,204,113,.35); }
  .msg.err { background: rgba(240,91,79,.14); color: #ffd9d4; border-color: rgba(240,91,79,.4); }
  label { display: block; margin: 10px 0 4px; font-size: 13px; color: #f1f5f9; }
  input[type=text], select, textarea { padding: 8px 12px; background: #0e1730; border: 1px solid rgba(148,163,184,.28); color: #f1f5f9; border-radius: 12px; font-size: 14px; box-sizing: border-box; }
  input[type=text]:focus, select:focus, textarea:focus { border-color: #4cc9f0; box-shadow: 0 0 12px rgba(76,201,240,.55); outline: none; }
  input::placeholder, textarea::placeholder { color: #64748b; }
  select option { background: #0e1730; }
  .mono { font-family: Consolas, Menlo, monospace; }
  .slim { width: 220px; }
  .full { width: 100%; }
  form.row { display: inline-flex; gap: 6px; align-items: center; flex-wrap: wrap; }
  button { margin-top: 16px; background: linear-gradient(90deg, #3aa8d6, #4cc9f0); color: #06121f; font-weight: 700; border: 1px solid rgba(76,201,240,.6); border-radius: 12px; padding: 10px 18px; font-size: 14px; cursor: pointer; box-shadow: 0 4px 16px rgba(76,201,240,.35); }
  button:hover { filter: brightness(1.1); box-shadow: 0 0 12px rgba(76,201,240,.55), 0 6px 22px rgba(114,9,183,.45); }
  button.small { margin-top: 0; padding: 6px 12px; font-size: 13px; }
  button.link { background: transparent; color: #f1f5f9; border: 1px solid rgba(76,201,240,.3); box-shadow: none; font-weight: 600; }
  button.link:hover { background: rgba(76,201,240,.12); color: #fff; }
  a.buttonlike { display: inline-block; padding: 6px 12px; font-size: 13px; font-weight: 600; border: 1px solid rgba(76,201,240,.3); border-radius: 12px; color: #f1f5f9; text-decoration: none; }
  a.buttonlike:hover { background: rgba(76,201,240,.12); color: #fff; }
  pre.result { background: #0f1419; color: #7ee787; padding: 12px 14px; border-radius: 12px; border: 1px solid rgba(76,201,240,.25); overflow-wrap: anywhere; }
  pre.error { background: rgba(240,91,79,.14); color: #ffb4ac; border-radius: 12px; border: 1px solid rgba(240,91,79,.4); }
  pre.dump { background: #0f1419; color: #c9d1d9; padding: 12px 14px; border-radius: 12px; border: 1px solid rgba(76,201,240,.25); overflow: auto; max-height: 320px; font-size: 12px; }
  details summary { cursor: pointer; color: #4cc9f0; font-size: 13px; }
  ol.flow li { margin-bottom: 8px; font-size: 14px; color: #c6cfe0; }
  ol.flow li b { color: #fff; }
  code { background: rgba(76,201,240,.12); color: #aee7ff; padding: 1px 6px; border-radius: 8px; font-size: 13px; }
</style>
</head>
{{end}}

{{define "topbar"}}<body>
<div class="navbar navbar-inverse navbar-fixed-top bc-brandbar" role="navigation">
  <div class="container-fluid bc-shell-row">
    <div class="navbar-header bc-brand">
      <img class="bc-cat-logo" src="/images/blackcat.svg" alt="Black Cat logo" height="34" width="34" />
      <a class="navbar-brand" href="/">&nbsp;<strong>Black Cat</strong></a>
    </div>
    <div class="bc-bar-actions">
      <a class="btn btn-primary btn-sm" href="/settings"><i class="fa fa-gear"></i> Account</a>
      <a class="btn btn-primary btn-sm" href="/logout" title="Sign out"><i class="fa fa-sign-out"></i></a>
    </div>
  </div>
</div>
<!-- Unified Black Cat menu: one pill per area with a dropdown, mirroring the
     main dashboard shell (same order, labels, icons and classes), so every
     destination exists exactly once and both shells feel like one tool.
     Admin-only entries (User Management, Webhooks) stay in the main shell:
     they need the server-side .ModifySystem flag and their routes are
     permission-gated. Dropdowns are vanilla-JS (toggle .open). -->
<nav class="bc-topnav" aria-label="Primary">
  <div class="bc-topnav-inner">
    <a class="bc-nav-link" href="/"><i class="fa fa-dashboard"></i>Dashboard</a>
    <div class="dropdown bc-drop">
      <a href="#" class="bc-nav-link bc-drop-toggle" aria-haspopup="true" aria-expanded="false"><i class="fa fa-rocket"></i>Campaigns <span class="caret"></span></a>
      <ul class="dropdown-menu">
        <li><a href="/campaigns"><i class="fa fa-envelope"></i>Email Campaign</a></li>
        <li><a href="/sms_campaigns"><i class="fa fa-mobile"></i>SMS Campaign</a></li>
        <li><a href="{{.Base}}/spear"><i class="fa fa-crosshairs"></i>Spear Phishing</a></li>
      </ul>
    </div>
    <div class="dropdown bc-drop">
      <a href="#" class="bc-nav-link bc-drop-toggle" aria-haspopup="true" aria-expanded="false"><i class="fa fa-archive"></i>Assets <span class="caret"></span></a>
      <ul class="dropdown-menu">
        <li><a href="/groups"><i class="fa fa-users"></i>Users &amp; Groups</a></li>
        <li><a href="/templates"><i class="fa fa-file-text-o"></i>Email/SMS Templates</a></li>
        <li><a href="/sending_profiles"><i class="fa fa-paper-plane-o"></i>Email Sending Profiles</a></li>
        <li><a href="/sms_sending_profiles"><i class="fa fa-commenting-o"></i>SMS Sending Profiles</a></li>
      </ul>
    </div>
    <div class="dropdown bc-drop">
      <a href="#" class="bc-nav-link bc-drop-toggle" aria-haspopup="true" aria-expanded="false"><i class="fa fa-server"></i>Infrastructure <span class="caret"></span></a>
      <ul class="dropdown-menu">
        <li><a href="{{.Base}}/"><i class="fa fa-home"></i>Overview</a></li>
        <li><a href="{{.Base}}/phishlets"><i class="fa fa-th-large"></i>Phishlets</a></li>
        <li><a href="{{.Base}}/domain"><i class="fa fa-globe"></i>Domain &amp; SSL</a></li>
        <li><a href="{{.Base}}/sessions"><i class="fa fa-trophy"></i>Sessions{{if .CountSessionsOK}} ({{.CountSessions}}){{end}}</a></li>
        <li><a href="{{.Base}}/lures"><i class="fa fa-magnet"></i>Lures</a></li>
      </ul>
    </div>
    <div class="dropdown bc-drop">
      <a href="#" class="bc-nav-link bc-drop-toggle" aria-haspopup="true" aria-expanded="false"><i class="fa fa-gear"></i>System <span class="caret"></span></a>
      <ul class="dropdown-menu">
        <li><a href="/settings"><i class="fa fa-gear"></i>Account Settings</a></li>
      </ul>
    </div>
    <a class="bc-nav-link" href="/guide.html"><i class="fa fa-book"></i>User Guide</a>
    <a class="bc-nav-link" href="/api-docs.html"><i class="fa fa-code"></i>API Docs</a>
  </div>
</nav>
<script>
(function () {
    function norm(p) {
        if (!p) return '/';
        if (p.length > 1) p = p.replace(/\/+$/, '');
        return p || '/';
    }
    var inner = document.querySelector('.bc-topnav-inner');
    if (!inner) return;
    var path = norm(window.location.pathname);
    var links = inner.querySelectorAll('a[href]');
    var best = null, bestLen = -1;
    for (var i = 0; i < links.length; i++) {
        var href = norm(links[i].getAttribute('href'));
        if (!href || href.charAt(0) !== '/') continue;
        if (href === '/') {
            if (path === '/' && bestLen < 0) { best = links[i]; bestLen = 0; }
            continue;
        }
        if ((path === href || path.indexOf(href + '/') === 0) && href.length > bestLen) {
            best = links[i];
            bestLen = href.length;
        }
    }
    if (best) {
        best.classList.add('active');
        var drop = best.closest ? best.closest('.dropdown') : null;
        if (drop) {
            var t = drop.querySelector('.bc-drop-toggle');
            if (t) t.classList.add('active');
        }
    }
    function closeAll(except) {
        var open = inner.querySelectorAll('.dropdown.open');
        for (var j = 0; j < open.length; j++) {
            if (open[j] !== except) {
                open[j].classList.remove('open');
                var tg = open[j].querySelector('.bc-drop-toggle');
                if (tg) tg.setAttribute('aria-expanded', 'false');
            }
        }
    }
    var toggles = inner.querySelectorAll('.bc-drop-toggle');
    for (var k = 0; k < toggles.length; k++) {
        (function (tgl) {
            tgl.addEventListener('click', function (ev) {
                ev.preventDefault();
                var d = tgl.parentElement;
                var willOpen = !d.classList.contains('open');
                closeAll(d);
                if (willOpen) {
                    d.classList.add('open');
                    tgl.setAttribute('aria-expanded', 'true');
                } else {
                    tgl.setAttribute('aria-expanded', 'false');
                }
            });
        })(toggles[k]);
    }
    document.addEventListener('click', function (ev) {
        if (!ev.target.closest || !ev.target.closest('.bc-drop')) closeAll(null);
    });
    document.addEventListener('keydown', function (ev) {
        if (ev.key === 'Escape') closeAll(null);
    });
})();
</script>
<script>
(function(){
  try {
    if (window.location.search.indexOf('job=') !== -1 && window.history && window.history.replaceState) {
      window.history.replaceState(null, '', window.location.pathname);
    }
  } catch (e) {}
})();
</script>
<main>
  {{template "banner" .}}
{{end}}

{{define "banner"}}{{if .Msg}}<div class="msg {{if .MsgErr}}err{{else}}ok{{end}}">{{.Msg}}</div>{{end}}{{end}}

{{define "page-overview"}}{{template "doc-head" .}}{{template "topbar" .}}
  <section>
    <h2>Engine status</h2>
    <ul class="status">
      <li><small>Base domain</small><b>{{if .Domain}}{{.Domain}}{{else}}&mdash;{{end}}</b></li>
      <li><small>External IP</small><b>{{if .ExternalIP}}{{.ExternalIP}}{{else}}&mdash;{{end}}</b></li>
      <li><small>Proxy listen</small><b>{{.ListenURL}}</b></li>
      <li><small>DNS port</small><b>{{.DnsPort}}</b></li>
    </ul>
    <div class="cards">
      <div class="card"><b>{{.CountEnabled}}/{{.CountPhishlets}}</b><small>phishlets enabled</small></div>
      <div class="card"><b>{{.CountLures}}</b><small>lures</small></div>
      <div class="card"><b>{{if .CountSessionsOK}}{{.CountSessions}}{{else}}&mdash;{{end}}</b><small>captured sessions</small></div>
    </div>
  </section>
  <section>
    <h2>How the combination works</h2>
    <ol class="flow">
      <li>Set the <b>base domain</b> and <b>external IP</b> on the <a href="{{.Base}}/domain">Domain &amp; SSL</a> page and sync certificates.</li>
      <li>Give each phishlet a <b>hostname</b> and <b>enable</b> it on the <a href="{{.Base}}/phishlets">Phishlets</a> page.</li>
      <li><b>Create a lure</b> on the <a href="{{.Base}}/lures">Lures</a> page and generate its phishing URL with the recipient's <code>rid</code>.</li>
      <li>Paste that URL as the landing page in your <b>gophish email template</b> and launch the campaign – gophish tracks opens and clicks.</li>
      <li>Victims land on the evilginx proxy; captured credentials and session tokens appear on the <a href="{{.Base}}/sessions">Sessions</a> page, in the campaign results, and on the live feed.</li>
    </ol>
  </section>
</main>
</body>
</html>
{{end}}

{{define "page-phishlets"}}{{template "doc-head" .}}{{template "topbar" .}}
  {{if not .AuditEnabled}}
  <section>
    <h2>New Phishlet</h2>
    <p style="font-size: 13px; color: #c6cfe0;">Auto-generation is disabled. Add a <code>site_auditor</code> section to <code>config.json</code> (pointing <code>script</code> at <code>tools/phishlet_harvester.py</code>) and restart.</p>
  </section>
  {{else}}
  <section>
    <h2>New Phishlet</h2>
    <p style="font-size: 13px; color: #c6cfe0;">Discover the login page of a site that has no phishlet yet, then review and register the generated phishlet. The result is a starting scaffold &mdash; verify the hosts, cookies and credential keys before use.</p>
    <form method="post" action="{{.Base}}/phishlets/create">
      <input type="hidden" name="csrf_token" value="{{.Csrf}}">
      <label for="new_domain">Target domain</label>
      <input type="text" id="new_domain" name="domain" class="slim" value="{{.AuditDomain}}" placeholder="e.g. example.com">
      <button type="submit">Discover &amp; generate</button>
    </form>

    {{if .AuditErr}}
    <div class="msg err" style="margin-top: 14px;">{{.AuditErr}}</div>
    {{end}}

    {{if .AuditJobID}}
    <div class="msg ok" id="audit-running" style="margin-top: 14px;">Discovering the login page for <b>{{.AuditDomain}}</b>... this can take up to a minute.</div>
    <script>
    (function(){
      var jobId = '{{.AuditJobID}}';
      var jobBase = '{{.Base}}';
      var tick = function(){
        var x = new XMLHttpRequest();
        x.open('GET', jobBase + '/phishlets/jobs?job=' + encodeURIComponent(jobId), true);
        x.onreadystatechange = function(){
          if (x.readyState === 4 && x.status === 200) {
            var j = JSON.parse(x.responseText);
            if (j.status === 'done' || j.status === 'error') {
              window.location.href = jobBase + '/phishlets?job=' + encodeURIComponent(jobId);
            } else {
              setTimeout(tick, 2000);
            }
          } else if (x.readyState === 4) {
            setTimeout(tick, 3000);
          }
        };
        x.send();
      };
      setTimeout(tick, 2000);
    })();
    </script>
    {{end}}

    {{if .AuditYAML}}
    <div style="margin-top: 14px;">
      <p style="font-size: 13px; color: #c6cfe0;">Discovery finished for <b>{{.AuditDomain}}</b>. Review the generated phishlet below, then <b>Create phishlet</b> to register it.</p>
      {{if .AuditNotes}}
      <ul style="font-size: 13px; color: #ffd166;">
        {{range .AuditNotes}}<li>{{.}}</li>{{end}}
      </ul>
      {{end}}
      <form method="post" action="{{.Base}}/phishlets/commit">
        <input type="hidden" name="csrf_token" value="{{.Csrf}}">
        <label for="new_site">Phishlet name</label>
        <input type="text" id="new_site" name="site" class="slim" value="{{.AuditSite}}">
        <label for="new_yaml">Phishlet YAML (editable)</label>
        <textarea id="new_yaml" name="yaml" class="full mono" rows="22" spellcheck="false">{{.AuditYAML}}</textarea>
        <button type="submit">Create phishlet</button>
      </form>
    </div>
    {{end}}
  </section>
  {{end}}

  <section>
    <h2>Phishlets</h2>
    <table>
      <tr><th>Phishlet</th><th>State</th><th>Hostname</th><th>Landing URL</th><th>Actions</th></tr>
      {{range .Phishlets}}
      <tr>
        <td>{{.Name}}</td>
        <td>{{if .Enabled}}<span class="badge on">enabled</span>{{else}}<span class="badge off">disabled</span>{{end}}</td>
        <td>
          <form method="post" action="{{$.Base}}/phishlets" class="row">
            <input type="hidden" name="csrf_token" value="{{$.Csrf}}">
            <input type="hidden" name="site" value="{{.Name}}">
            <input type="text" name="hostname" class="slim" value="{{.Hostname}}" placeholder="host.your-domain.com">
            <button type="submit" name="action" value="hostname" class="small link">Save</button>
          </form>
        </td>
        <td>{{if .Unauth}}{{.Unauth}}{{else}}&mdash;{{end}}</td>
        <td>
          <form method="post" action="{{$.Base}}/phishlets" class="row">
            <input type="hidden" name="csrf_token" value="{{$.Csrf}}">
            <input type="hidden" name="site" value="{{.Name}}">
            {{if .Enabled}}
            <button type="submit" name="action" value="disable" class="small link">Disable</button>
            {{else}}
            <button type="submit" name="action" value="enable" class="small">Enable</button>
            {{end}}
          </form>
        </td>
      </tr>
      {{else}}
      <tr><td colspan="5">No phishlets found.</td></tr>
      {{end}}
    </table>
  </section>
</main>
</body>
</html>
{{end}}

{{define "page-domain"}}{{template "doc-head" .}}{{template "topbar" .}}
  <section>
    <h2>Server settings</h2>
    <ul class="status">
      <li><small>Listen address</small><b>{{.ListenURL}}</b></li>
      <li><small>HTTPS port</small><b>{{.HttpsPort}}</b></li>
      <li><small>DNS port</small><b>{{.DnsPort}}</b></li>
    </ul>
    <form method="post" action="{{.Base}}/domain">
      <input type="hidden" name="csrf_token" value="{{.Csrf}}">
      <input type="hidden" name="action" value="save">
      <label for="domain">Base domain</label>
      <input type="text" id="domain" name="domain" class="slim" value="{{.Domain}}" placeholder="e.g. example.com">
      <label for="external_ip">External IP</label>
      <input type="text" id="external_ip" name="external_ip" class="slim" value="{{.ExternalIP}}" placeholder="e.g. 1.2.3.4">
      <button type="submit">Save settings</button>
    </form>
  </section>
  <section>
    <h2>TLS certificates</h2>
    <p style="font-size: 13px; color: #c6cfe0;">Live status per enabled hostname, probed against the proxy listener. Syncing obtains missing certificates in the background (ACME can take up to a minute).</p>
    <form method="post" action="{{.Base}}/domain">
      <input type="hidden" name="csrf_token" value="{{.Csrf}}">
      <input type="hidden" name="action" value="sync">
      <button type="submit" style="margin-top: 0;">Sync certificates now</button>
    </form>
    <table style="margin-top: 14px;">
      <tr><th>Hostname</th><th>Serving</th><th>Certificate</th></tr>
      {{range .Certs}}
      <tr>
        <td>{{.Hostname}}</td>
        <td>{{if .Enabled}}<span class="badge on">serving</span>{{else}}<span class="badge off">not serving</span>{{end}}</td>
        <td>
          {{if .Present}}<span class="badge on">valid</span> {{.Subject}} &mdash; expires {{.Expires}} ({{.DaysLeft}} days)
          {{else if .Err}}<span class="badge warn">missing</span> {{.Err}}
          {{else}}<span class="badge warn">missing</span>{{end}}
        </td>
      </tr>
      {{else}}
      <tr><td colspan="3">No hostnames configured yet – assign hostnames on the Phishlets page first.</td></tr>
      {{end}}
    </table>
  </section>
</main>
</body>
</html>
{{end}}

{{define "page-sessions"}}{{template "doc-head" .}}{{template "topbar" .}}
  <section>
    <h2>Captured loot (sessions)</h2>
    {{if .SessionsErr}}
    <div class="msg err">{{.SessionsErr}}</div>
    {{else}}
    <p style="font-size: 13px; color: #c6cfe0;">Every victim that completes a login creates a session. Credentials and tokens below are also written to the shared database, so they appear in the gophish campaign results and on the live feed – match them by time and landing URL.</p>
    <table>
      <tr><th>ID</th><th>Phishlet</th><th>Victim</th><th>Credentials</th><th>Custom fields</th><th>Tokens</th><th>Updated</th><th>Loot</th></tr>
      {{range .Sessions}}
      <tr>
        <td>{{.ID}}</td>
        <td>{{.Phishlet}}</td>
        <td>{{if .RemoteAddr}}{{.RemoteAddr}}{{else}}&mdash;{{end}}</td>
        <td>{{if .HasCreds}}<span class="badge on">captured</span> {{.Username}}{{if .Password}} / {{.Password}}{{end}}{{else}}<span class="badge off">none</span>{{end}}</td>
        <td>
          {{if .HasReset}}<span class="badge warn">password reset flow</span><br>{{end}}
          {{if .Custom}}{{range .Custom}}<code>{{.Key}}</code>={{.Value}}<br>{{end}}{{else}}&mdash;{{end}}
        </td>
        <td>cookies {{.CookieHits}} / body {{.BodyHits}} / http {{.HttpHits}}</td>
        <td>{{.Updated}}</td>
        <td>
          <details>
            <summary>full JSON</summary>
            <pre class="dump">{{.Dump}}</pre>
          </details>
        </td>
      </tr>
      {{else}}
      <tr><td colspan="8">No sessions captured yet.</td></tr>
      {{end}}
    </table>
    {{end}}
  </section>
</main>
</body>
</html>
{{end}}

{{define "page-lures"}}{{template "doc-head" .}}{{template "topbar" .}}
  <section>
    <h2>Generate phishing URL</h2>
    <form method="get" action="{{.Base}}/phishurl">
      <label for="p">Phishlet</label>
      <select id="p" name="p" class="slim">
        {{range .PhishletSel}}
        <option value="{{.}}" {{if eq . $.FormSel}}selected{{end}}>{{.}}</option>
        {{end}}
      </select>
      <label for="rid">rid (result id)</label>
      <input type="text" id="rid" name="rid" class="slim" value="{{.FormRid}}" placeholder="e.g. abc123">
      <label for="path">Path</label>
      <input type="text" id="path" name="path" class="slim" value="{{or .FormPath "/"}}" placeholder="/">
      <label for="host">Hostname override (optional, e.g. a lure hostname)</label>
      <input type="text" id="host" name="host" class="slim" value="{{.FormHost}}" placeholder="uses the phishlet hostname by default">
      <label for="extra">Extra parameters (key=value pairs, space or newline separated)</label>
      <textarea id="extra" name="extra" class="full" rows="2" placeholder="username= target={{.ExternalIP}}">{{.FormExtra}}</textarea>
      <button type="submit">Generate URL</button>
    </form>
    {{if .Result}}
    <p><b>Result</b></p>
    <pre class="{{if .ResultErr}}error{{else}}result{{end}}">{{.Result}}</pre>
    {{if not .ResultErr}}<p style="font-size: 13px; color: #c6cfe0;">Paste this URL as the landing page in your gophish email template. The <code>rid</code> ties the victim back to their gophish result row.</p>{{end}}
    {{end}}
  </section>
  <section>
    <h2>Lures</h2>
    <form method="post" action="{{.Base}}/lures">
      <input type="hidden" name="csrf_token" value="{{.Csrf}}">
      <label for="lure_phishlet">Phishlet</label>
      <select id="lure_phishlet" name="phishlet" class="slim">
        {{range .PhishletSel}}
        <option value="{{.}}" {{if eq . $.FormSel}}selected{{end}}>{{.}}</option>
        {{end}}
      </select>
      <label for="lure_path">Path (leave empty for a random one)</label>
      <input type="text" id="lure_path" name="path" class="slim" value="{{.FormLurePath}}" placeholder="/random-path">
      <label for="lure_host">Hostname (optional, overrides the phishlet hostname)</label>
      <input type="text" id="lure_host" name="hostname" class="slim" value="{{.FormLureHost}}" placeholder="link.your-domain.com">
      <label for="lure_redirect">Redirect URL (optional)</label>
      <input type="text" id="lure_redirect" name="redirect" class="slim" value="{{.FormLureRedirect}}" placeholder="https://target.example">
      <button type="submit">Create lure</button>
    </form>
    <table style="margin-top: 14px;">
      <tr><th>ID</th><th>Phishlet</th><th>Path</th><th>Hostname</th><th>Get URL</th><th>Delete</th></tr>
      {{range .Lures}}
      <tr>
        <td>{{.ID}}</td>
        <td>{{.Phishlet}}</td>
        <td>{{.Path}}</td>
        <td>{{if .Hostname}}{{.Hostname}}{{else}}&mdash;{{end}}</td>
        <td><a class="buttonlike" href="{{$.Base}}/phishurl?p={{.Phishlet}}&amp;path={{.Path}}{{if .Hostname}}&amp;host={{.Hostname}}{{end}}&amp;rid={{.Rid}}">get URL</a></td>
        <td>
          <form method="post" action="{{$.Base}}/lures/delete" class="row">
            <input type="hidden" name="csrf_token" value="{{$.Csrf}}">
            <input type="hidden" name="id" value="{{.ID}}">
            <button type="submit" class="small link">Delete</button>
          </form>
        </td>
      </tr>
      {{else}}
      <tr><td colspan="6">No lures found.</td></tr>
      {{end}}
    </table>
  </section>
</main>
</body>
</html>
{{end}}

{{define "page-spears"}}{{template "doc-head" .}}{{template "topbar" .}}
  <section>
    <h2>Spear Phishing</h2>
    <p style="font-size: 13px; color: #c6cfe0;">One target per campaign: enrich a LinkedIn profile, generate a personal message, and launch. Every launch below is a regular platform campaign.</p>
    <a class="buttonlike" href="{{.Base}}/spear/new" style="font-weight:700;">+ New Spear Phishing</a>
  </section>
  {{if .SpearListErr}}
  <section>
    <div class="msg err">{{.SpearListErr}}</div>
  </section>
  {{end}}
  <div class="spear-tabs" role="tablist">
    <button type="button" class="spear-tab active" data-tab="spear-active">Active Campaigns</button>
    <button type="button" class="spear-tab" data-tab="spear-archived">Archived Campaigns</button>
  </div>
  <section id="spear-active">
    {{if .SpearRows}}
    <table>
      <tr><th>Name</th><th>Channel</th><th>Created</th><th>Status</th><th></th></tr>
      {{range .SpearRows}}
      <tr>
        <td>{{.Name}}</td>
        <td>{{if eq .Channel "sms"}}<span class="badge on">SMS</span>{{else}}<span class="badge on">Email</span>{{end}}</td>
        <td>{{.Created}}</td>
        <td><span class="badge on">{{.Status}}</span></td>
        <td><a class="buttonlike" href="{{.Link}}">Results</a></td>
      </tr>
      {{end}}
    </table>
    {{else}}
    <div class="msg">No spear campaigns yet. Launch one!</div>
    {{end}}
  </section>
  <section id="spear-archived" style="display:none;">
    {{if .SpearArchived}}
    <table>
      <tr><th>Name</th><th>Channel</th><th>Created</th><th>Status</th><th></th></tr>
      {{range .SpearArchived}}
      <tr>
        <td>{{.Name}}</td>
        <td>{{if eq .Channel "sms"}}<span class="badge on">SMS</span>{{else}}<span class="badge on">Email</span>{{end}}</td>
        <td>{{.Created}}</td>
        <td>{{.Status}}</td>
        <td><a class="buttonlike" href="{{.Link}}">Results</a></td>
      </tr>
      {{end}}
    </table>
    {{else}}
    <div class="msg">No archived spear campaigns.</div>
    {{end}}
  </section>
  <script>
  (function(){
    var tabs = document.querySelectorAll('.spear-tab[data-tab]');
    function select(id) {
      for (var i = 0; i < tabs.length; i++) {
        if (tabs[i].getAttribute('data-tab') === id) tabs[i].classList.add('active');
        else tabs[i].classList.remove('active');
      }
      var a = document.getElementById('spear-active');
      var b = document.getElementById('spear-archived');
      if (a) a.style.display = (id === 'spear-active') ? '' : 'none';
      if (b) b.style.display = (id === 'spear-archived') ? '' : 'none';
    }
    for (var i = 0; i < tabs.length; i++) {
      (function(t){ t.addEventListener('click', function(){ select(t.getAttribute('data-tab')); }); })(tabs[i]);
    }
  })();
  </script>
</main>
</body>
</html>
{{end}}

{{define "page-spear"}}{{template "doc-head" .}}{{template "topbar" .}}
<style>
.spm-overlay{position:fixed;inset:0;z-index:60;display:flex;align-items:flex-start;justify-content:center;overflow-y:auto;padding:28px 16px;background:rgba(2,6,17,.72);}
.spm-modal{width:100%;max-width:880px;background:#0d1830;border:1px solid rgba(76,201,240,.25);border-radius:16px;box-shadow:0 24px 80px rgba(0,0,0,.6);overflow:hidden;}
.spm-modal-head{display:flex;align-items:center;gap:12px;padding:16px 20px;border-bottom:1px solid rgba(76,201,240,.18);}
.spm-modal-title{font-size:17px;font-weight:800;color:#f1f5f9;}
.spm-modal-sub{font-size:12px;color:#94a3b8;}
.spm-close{margin-left:auto;display:inline-flex;align-items:center;justify-content:center;width:30px;height:30px;border-radius:50%;border:1px solid rgba(76,201,240,.3);color:#c6cfe0;text-decoration:none;font-size:16px;line-height:1;}
.spm-close:hover{background:rgba(76,201,240,.12);color:#fff;}
.spm-modal-progress{padding:14px 20px 4px;}
.spm-modal-body{padding:6px 20px 20px;}
.spm-acc-item{border:1px solid rgba(76,201,240,.16);border-radius:12px;background:rgba(22,33,63,.6);margin-top:10px;overflow:hidden;}
.spm-acc-head{width:100%;display:flex;align-items:center;gap:10px;padding:13px 16px;background:transparent;border:0;color:#f1f5f9;font:inherit;font-weight:700;font-size:14px;cursor:pointer;text-align:left;}
.spm-acc-head:hover{background:rgba(76,201,240,.08);}
.spm-acc-num{width:24px;height:24px;flex:none;border-radius:50%;display:inline-flex;align-items:center;justify-content:center;font-size:12px;background:rgba(148,163,184,.2);color:#f1f5f9;}
.spm-acc-item.open .spm-acc-num{background:linear-gradient(90deg,#4cc9f0,#7bdff5);color:#06121f;}
.spm-acc-status{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-weight:400;font-size:12px;color:#94a3b8;text-align:right;}
.spm-acc-chev{flex:none;color:#7bdff5;transition:transform .15s ease;}
.spm-acc-item.open .spm-acc-chev{transform:rotate(180deg);}
.spm-acc-body{display:none;padding:2px 16px 18px;}
.spm-acc-item.open > .spm-acc-body{display:block;}
.spm-next-row{margin-top:14px;text-align:right;}
/* This view renders its own banner inside the modal (below). Hide the page-level
   one — the fixed overlay would otherwise cover it and errors look like "nothing happens". */
main > .msg{display:none;}
</style>
<div class="spm-overlay">
<div class="spm-modal" role="dialog" aria-modal="true" aria-label="Spear phishing campaign wizard">
  <div class="spm-modal-head">
    <div><div class="spm-modal-title">New Spear Phishing</div><div class="spm-modal-sub">Single-target spear phishing &mdash; not a bulk campaign</div></div>
    <a class="spm-close" href="{{.Base}}/spear" aria-label="Close wizard">&times;</a>
  </div>
  <div class="spm-modal-progress">
  <div class="spear-steps" aria-label="Progress">
    <button type="button" class="spear-step {{if .SpearHasProfile}}done{{else}}current{{end}}" data-goto="spear-sec-1"{{if not .SpearEnabled}} disabled{{end}}><span>1</span>Target</button>
    <button type="button" class="spear-step {{if .SpearHasProfile}}done{{else}}locked{{end}}" data-goto="spear-sec-2"{{if not .SpearHasProfile}} disabled{{end}}><span>2</span>Profile</button>
    <button type="button" class="spear-step {{if .SpearHasResult}}done{{else if .SpearHasProfile}}current{{else}}locked{{end}}" data-goto="spear-sec-3"{{if not .SpearHasProfile}} disabled{{end}}><span>3</span>Message</button>
    <button type="button" class="spear-step {{if .SpearDone}}done{{else if .SpearHasResult}}current{{else}}locked{{end}}" data-goto="spear-sec-4"{{if not .SpearHasResult}} disabled{{end}}><span>4</span>Launch</button>
  </div>
  </div>
  <div class="spm-modal-body">
  {{template "banner" .}}
  {{if not .SpearEnabled}}
  <section>
    <h2>Spear Phishing</h2>
    <p style="font-size: 13px; color: #c6cfe0;">Spear enrichment is not configured. Add a <code>site_auditor</code> section to <code>config.json</code> (pointing <code>script</code> at <code>tools/phishlet_harvester.py</code>) with <code>tools/spear_enrich.py</code> next to it, and restart.</p>
  </section>
  {{else}}
  {{if .SpearDone}}
  <section>
    <h2>Spear phishing launched</h2>
    <div class="msg ok">{{.SpearDoneName}} is live.</div>
    <p style="font-size: 13px; color: #c6cfe0; display: flex; gap: 10px; flex-wrap: wrap; align-items: center;">
      {{if eq .SpearDoneKind "sms"}}
      <a class="buttonlike" href="/sms_campaigns/{{.SpearDoneID}}">View live results</a>
      {{else}}
      <a class="buttonlike" href="/campaigns/{{.SpearDoneID}}">View live results</a>
      {{end}}
      <a class="buttonlike" href="{{.Base}}/spear">&larr; Back to Spear Phishing</a>
      <a href="{{.Base}}/spear/new">Start another spear</a>
    </p>
  </section>
  {{end}}
  <div class="spm-acc-item" data-acc="spear-sec-1">
    <button type="button" class="spm-acc-head" data-acc-head="spear-sec-1" aria-expanded="false"><span class="spm-acc-num">1</span><span>Target — LinkedIn URL &amp; channel</span><span class="spm-acc-status">{{.SpearLinkedIn}}</span><span class="spm-acc-chev">▾</span></button>
    <div class="spm-acc-body" id="spear-sec-1">
    <p style="font-size: 13px; color: #c6cfe0;">Paste one LinkedIn profile URL. Enrichment runs in the background (profile, role, company, email), then unlocks the prompt step. This flow is 1:1 by design &mdash; bulk lists still go through Users &amp; Groups.</p>
    <form method="post" action="{{.Base}}/spear/enrich">
      <input type="hidden" name="csrf_token" value="{{.Csrf}}">
      <label for="spear_linkedin">LinkedIn URL</label>
      <input type="text" id="spear_linkedin" name="linkedin" class="full" value="{{.SpearLinkedIn}}" placeholder="https://www.linkedin.com/in/someone">
      <label for="spear_channel">Channel</label>
      <select id="spear_channel" name="channel" class="slim">
        <option value="mail" {{if eq .SpearChannel "sms"}} {{else}}selected{{end}}>Email</option>
        <option value="sms" {{if eq .SpearChannel "sms"}}selected{{end}}>SMS</option>
      </select>
      <div id="spear_lang_wrap">
        <label for="spear_lang">Message language</label>
        <select id="spear_lang" name="lang" class="slim">
          <option value="en" {{if eq .SpearLang "ar"}} {{else}}selected{{end}}>English</option>
          <option value="ar" {{if eq .SpearLang "ar"}}selected{{end}}>Arabic (&#1575;&#1604;&#1593;&#1585;&#1576;&#1610;&#1577;)</option>
        </select>
      </div>
      <script>
      (function(){
        var ch = document.getElementById('spear_channel');
        var wrap = document.getElementById('spear_lang_wrap');
        function syncSpearLang(){ if (wrap) wrap.style.display = (ch && ch.value === 'sms') ? '' : 'none'; }
        if (ch) ch.addEventListener('change', syncSpearLang);
        syncSpearLang();
      })();
      </script>
      <label for="spear_sender">Sender name (optional, used in the message)</label>
      <input type="text" id="spear_sender" name="sender" class="slim" value="{{.SpearSender}}" placeholder="Security Team">
      <label style="font-weight: normal; font-size: 13px; color: #c6cfe0;"><input type="checkbox" name="refresh" value="1"> Force fresh lookup <span style="color: #94a3b8;">(ignores the local cache, consumes API quota)</span></label>
      <p style="font-size: 12px; color: #94a3b8;">Repeat URLs reuse the local profile cache (30 days) to save quota — tick the box only when you need fresh data.</p>
      <button type="submit">Enrich target</button>
    </form>
    {{if .SpearRunning}}
    <div class="msg ok" id="spear-running" style="margin-top: 14px;">Working on it... this can take up to a minute.</div>
    <script>
    (function(){
      var jobId = '{{.SpearJobID}}';
      var jobBase = '{{.Base}}';
      var tick = function(){
        var x = new XMLHttpRequest();
        x.open('GET', jobBase + '/spear/jobs?job=' + encodeURIComponent(jobId), true);
        x.onreadystatechange = function(){
          if (x.readyState === 4 && x.status === 200) {
            var j = JSON.parse(x.responseText);
            if (j.status === 'done' || j.status === 'error') {
              window.location.href = jobBase + '/spear/new?job=' + encodeURIComponent(jobId);
            } else {
              setTimeout(tick, 2000);
            }
          } else if (x.readyState === 4) {
            setTimeout(tick, 3000);
          }
        };
        x.send();
      };
      setTimeout(tick, 2000);
    })();
    </script>
    {{end}}
    {{if .SpearErr}}
    <div class="msg err" style="margin-top: 14px;">{{.SpearErr}}</div>
    {{end}}
    {{if .SpearHasProfile}}
    <div class="spm-next-row"><button type="button" class="buttonlike" data-acc-next="spear-sec-2">Next: Profile &rarr;</button></div>
    {{end}}
  </div>
  </div>

  {{if .SpearHasProfile}}
  <div class="spm-acc-item" data-acc="spear-sec-2">
    <button type="button" class="spm-acc-head" data-acc-head="spear-sec-2" aria-expanded="false"><span class="spm-acc-num">2</span><span>Profile — review enriched fields</span><span class="spm-acc-status">{{index .SpearProfile "Name"}}</span><span class="spm-acc-chev">▾</span></button>
    <div class="spm-acc-body" id="spear-sec-2">
    <p style="font-size: 13px; color: #c6cfe0;">Review everything below and fix what is wrong or missing &mdash; this is where all editing happens. Saving refreshes the prompt and regenerating picks the changes up.</p>
    {{if not (index .SpearProfile "Name")}}
    <p style="font-size: 13px; color: #c6cfe0;">No profile data came back — fill the details in right here.</p>
    {{end}}
    <form method="post" action="{{.Base}}/spear/profile">
      <input type="hidden" name="csrf_token" value="{{.Csrf}}">
      <input type="hidden" name="job" value="{{.SpearJobID}}">
      <label for="spear_p_name">Full name</label>
      <input type="text" id="spear_p_name" name="name" class="slim" value="{{index .SpearProfile "Name"}}">
      <label for="spear_p_position">Current position</label>
      <input type="text" id="spear_p_position" name="position" class="slim" value="{{index .SpearProfile "Current_Position"}}">
      <label for="spear_p_company">Company (last place worked)</label>
      <input type="text" id="spear_p_company" name="company" class="slim" value="{{index .SpearProfile "Company"}}">
      <label for="spear_p_location">Location</label>
      <input type="text" id="spear_p_location" name="location" class="slim" value="{{index .SpearProfile "Location"}}">
      <label for="spear_p_industry">Industry</label>
      <input type="text" id="spear_p_industry" name="industry" class="slim" value="{{index .SpearProfile "Industry"}}">
      <label for="spear_p_email">Email</label>
      <input type="text" id="spear_p_email" name="email" class="slim" value="{{index .SpearProfile "Email"}}">
      <p style="font-size: 12px; color: #94a3b8;">Required for the Email channel — launch fails without it.</p>
      {{if index .SpearProfile "Email_Confidence"}}<p style="font-size: 12px; color: #c6cfe0;">confidence {{index .SpearProfile "Email_Confidence"}}{{if index .SpearProfile "Email_Source"}} &middot; {{index .SpearProfile "Email_Source"}}{{end}}</p>{{end}}
      <p style="font-size: 13px; color: #c6cfe0;">LinkedIn: {{if index .SpearProfile "LinkedIn_URL"}}{{index .SpearProfile "LinkedIn_URL"}}{{else}}&mdash;{{end}}{{if index .SpearProfile "Email_Confidence"}} &middot; email confidence {{index .SpearProfile "Email_Confidence"}}{{end}}</p>
      <button type="submit">Save profile</button>
    </form>
    {{if .SpearNotes}}
    <ul style="font-size: 13px; color: #ffd166;">
      {{range .SpearNotes}}<li>{{.}}</li>{{end}}
    </ul>
    {{end}}
    <div class="spm-next-row"><button type="button" class="buttonlike" data-acc-next="spear-sec-3">Next: Message &rarr;</button></div>
  </div>
  </div>
  <div class="spm-acc-item" data-acc="spear-sec-3">
    <button type="button" class="spm-acc-head" data-acc-head="spear-sec-3" aria-expanded="false"><span class="spm-acc-num">3</span><span>Message — prompt, templates &amp; result</span><span class="spm-acc-status">{{.SpearSubject}}</span><span class="spm-acc-chev">▾</span></button>
    <div class="spm-acc-body" id="spear-sec-3">
    <p style="font-size: 13px; color: #c6cfe0;">Review the prompt, edit it freely, then <b>Generate message</b>. The result appears below and feeds the review step.</p>
    <form method="post" action="{{.Base}}/spear/generate" onsubmit="var b=this.querySelector('button[type=submit]');if(b){b.disabled=true;b.textContent='Working...';}return true;">
      <input type="hidden" name="csrf_token" value="{{.Csrf}}">
      <input type="hidden" name="job" value="{{.SpearJobID}}">
      <label for="spear_prompt">Prompt sent to the model</label>
      <textarea id="spear_prompt" name="prompt" class="full mono" rows="9" spellcheck="false">{{.SpearPrompt}}</textarea>
      <button type="submit">Generate message</button>
    </form>
    {{if .SpearRunning}}
    <div class="msg ok" style="margin-top: 12px;">Working on the message... this can take up to a minute. Stay here — the page jumps automatically when done, no need to click again.</div>
    {{end}}
    {{if .SpearPicksErr}}
    <div class="msg err" style="margin-top: 12px;">Template library: {{.SpearPicksErr}}</div>
    {{end}}
    {{if or .SpearPicks .SigRefreshing .SigRefreshErr .SigRefreshDone}}
    <div style="margin-top: 18px;">
      <div style="display: flex; align-items: flex-start; gap: 12px;">
        <p style="font-size: 13px; color: #c6cfe0; margin: 0; flex: 1;"><b>Signature library</b> — harvest fresh signatures from Gmail, then rebuild ready-to-use templates. New brands appear here automatically. Takes a while; this section reloads when done.</p>
        <form method="post" action="{{.Base}}/spear/signatures/refresh" style="flex: none;" onsubmit="var b=this.querySelector('button[type=submit]');if(b){b.disabled=true;b.textContent='Refreshing...';}return true;">
          <input type="hidden" name="csrf_token" value="{{.Csrf}}">
          <input type="hidden" name="job" value="{{.SpearJobID}}">
          <label for="spear_sig_accounts" style="font-size: 11px; color: #94a3b8;">Accounts</label>
          <select id="spear_sig_accounts" name="accounts" class="slim" style="width: auto; display: inline-block;">
            <option value="1">1</option>
            <option value="2">2</option>
            <option value="3" selected>3</option>
            <option value="4">4</option>
            <option value="5">5</option>
          </select>
          <button type="submit" title="Re-harvest signatures from Gmail, then rebuild the templates">Refresh library</button>
        </form>
      </div>
      {{if .SigRefreshing}}
      <div class="msg ok" id="sig-refresh-running" style="margin-top: 10px;">Refreshing the library (harvest + rebuild)... you can keep working, this section reloads automatically.</div>
      <script>
      (function(){
        var sigJobId = '{{.SigRefreshJobID}}';
        var spearJobId = '{{.SpearJobID}}';
        var jobBase = '{{.Base}}';
        var tick = function(){
          var x = new XMLHttpRequest();
          x.open('GET', jobBase + '/spear/signatures/status?job=' + encodeURIComponent(sigJobId), true);
          x.onreadystatechange = function(){
            if (x.readyState === 4 && x.status === 200) {
              var j = JSON.parse(x.responseText);
              if (j.status === 'done' || j.status === 'error') {
                var href = jobBase + '/spear/new?sigjob=' + encodeURIComponent(sigJobId);
                if (spearJobId) href += '&job=' + encodeURIComponent(spearJobId);
                window.location.href = href;
              } else {
                setTimeout(tick, 3000);
              }
            } else if (x.readyState === 4) {
              setTimeout(tick, 5000);
            }
          };
          x.send();
        };
        setTimeout(tick, 3000);
      })();
      </script>
      {{end}}
      {{if .SigRefreshErr}}
      <div class="msg err" style="margin-top: 10px;">Library refresh failed: {{.SigRefreshErr}}</div>
      {{end}}
      {{if .SigRefreshDone}}
      <div class="msg ok" style="margin-top: 10px;">{{.SigRefreshDone}}</div>
      {{end}}
    </div>
    {{end}}
    {{if .SpearPicks}}
    <div style="margin-top: 18px;">
      <p style="font-size: 13px; color: #c6cfe0;"><b>Suggested branded templates</b> — picked for {{index .SpearProfile "Current_Position"}}{{if index .SpearProfile "Company"}} at {{index .SpearProfile "Company"}}{{end}}. One click replaces the message above with the full branded version (logo, story, footer, tracking).</p>
      {{range .SpearPicks}}
      <div style="border: 1px solid rgba(76,201,240,.25); border-radius: 10px; overflow: hidden; margin-bottom: 10px; background: rgba(22,33,63,.6);">
        <div style="height: 4px; background: {{.Color}};"></div>
        <div style="padding: 10px 14px; display: flex; align-items: center; gap: 10px;">
          {{if .Logo}}<img src="{{.Logo}}" alt="" width="28" height="28" style="border-radius: 6px; background: #fff;" onerror="this.style.display='none'">{{end}}
          <div style="min-width: 0;">
            <div style="font-weight: 700; color: #f1f5f9;">{{if .IsNew}}<span style="display: inline-block; font-size: 10px; font-weight: 800; color: #06121f; background: #5df08f; border-radius: 6px; padding: 1px 7px; margin-right: 6px; vertical-align: middle;">★ NEW</span>{{end}}{{.Display}} <span style="font-weight: 400; font-size: 12px; color: #94a3b8;">{{.Domain}}</span></div>
            <div style="font-size: 12px; color: #c6cfe0; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">{{.Subject}}</div>
            {{if .Reason}}<div style="font-size: 11px; color: #7bdff5;">{{.Reason}} &middot; score {{.Score}}</div>{{end}}
          </div>
          <form method="post" action="{{$.Base}}/spear/library" style="margin-left: auto;" onsubmit="var b=this.querySelector('button[type=submit]');if(b){b.disabled=true;}return true;">
            <input type="hidden" name="csrf_token" value="{{$.Csrf}}">
            <input type="hidden" name="job" value="{{$.SpearJobID}}">
            <input type="hidden" name="brand" value="{{.Brand}}">
            <button type="submit">Use this</button>
          </form>
        </div>
        {{if .Snippet}}
        <details style="margin: 0 14px 12px; font-size: 12px; color: #94a3b8;">
          <summary style="cursor: pointer;">Preview text</summary>
          <pre class="result" style="white-space: pre-wrap;">{{.Snippet}}</pre>
        </details>
        {{end}}
      </div>
      {{end}}
    </div>
    {{end}}
    {{if .SpearLibGroups}}
    <details style="margin-top: 10px; border: 1px solid rgba(76,201,240,.25); border-radius: 10px; padding: 10px 14px; background: rgba(22,33,63,.6);">
      <summary style="cursor: pointer; font-size: 13px; color: #c6cfe0;"><b>Or browse the full library</b> — every template in the folder ({{.SpearLibTotal}}), grouped by use case</summary>
      <form method="post" action="{{.Base}}/spear/library" style="margin-top: 10px;" onsubmit="var b=this.querySelector('button[type=submit]');if(b){b.disabled=true;}return true;">
        <input type="hidden" name="csrf_token" value="{{.Csrf}}">
        <input type="hidden" name="job" value="{{.SpearJobID}}">
        <label for="spear_lib_all">All templates ({{.SpearLibTotal}})</label>
        <select id="spear_lib_all" name="brand" class="full">
          {{range .SpearLibGroups}}<optgroup label="{{.Title}}">
            {{range .Items}}<option value="{{.Brand}}">{{.Option}}</option>{{end}}
          </optgroup>{{end}}
        </select>
        <button type="submit">Use selected</button>
      </form>
    </details>
    {{end}}
    {{if .SpearHasResult}}
    <div style="margin-top: 14px;">
      <p><b>Result</b> <span class="badge on">{{.SpearGenerator}}</span>{{if eq .SpearLang "ar"}} <span class="badge on">&#1575;&#1604;&#1593;&#1585;&#1576;&#1610;&#1577;</span>{{end}}</p>
      <form method="post" action="{{.Base}}/spear/message" onsubmit="var b=this.querySelector('button[type=submit]');if(b){b.disabled=true;b.textContent='Saving...';}return true;">
        <input type="hidden" name="csrf_token" value="{{.Csrf}}">
        <input type="hidden" name="job" value="{{.SpearJobID}}">
        {{if ne .SpearChannel "sms"}}
        <label for="spear_subject">Subject (editable)</label>
        <input type="text" id="spear_subject" name="subject" class="full" value="{{.SpearSubject}}">
        {{end}}
        <label for="spear_body">Message body (editable — must keep {{"{{URL}}"}})</label>
        <textarea id="spear_body" name="body" class="full mono" rows="12" spellcheck="false">{{.SpearBody}}</textarea>
        <button type="submit">Save edits</button>
      </form>
      <form method="post" action="{{.Base}}/spear/refine" style="margin-top: 10px;" onsubmit="var b=this.querySelector('button[type=submit]');if(b){b.disabled=true;b.textContent='Working...';}return true;">
        <input type="hidden" name="csrf_token" value="{{.Csrf}}">
        <input type="hidden" name="job" value="{{.SpearJobID}}">
        <label for="spear_refine">Edit with LLM — describe the change</label>
        <input type="text" id="spear_refine" name="instruction" class="full" placeholder="e.g. make it shorter and more formal, or translate to Arabic">
        <button type="submit">Refine with LLM</button>
      </form>
    </div>
    {{end}}
    {{if .SpearHasResult}}
    <div class="spm-next-row"><button type="button" class="buttonlike" data-acc-next="spear-sec-4">Next: Review &amp; Launch &rarr;</button></div>
    {{end}}
  </div>
  </div>
  {{end}}

  {{if .SpearHasResult}}
  <div class="spm-acc-item" data-acc="spear-sec-4">
    <button type="button" class="spm-acc-head" data-acc-head="spear-sec-4" aria-expanded="false"><span class="spm-acc-num">4</span><span>Review &amp; Launch</span><span class="spm-acc-status">{{.SpearCampaign}}</span><span class="spm-acc-chev">▾</span></button>
    <div class="spm-acc-body" id="spear-sec-4">
    <p style="font-size: 13px; color: #c6cfe0;">Launching creates a single-target group, a template from the message above, and the {{.SpearChannel}} campaign &mdash; the same objects the dashboard modals create.</p>
    {{if and (eq .SpearChannel "mail") (not (index .SpearTarget "email"))}}
    <div class="msg err">No email on this target — add it in step 2 before launching.</div>
    {{end}}
    {{if .SpearProfilesErr}}
    <div class="msg err">{{.SpearProfilesErr}}</div>
    {{end}}
    <form method="post" action="{{.Base}}/spear/launch" onsubmit="var b=this.querySelector('button[type=submit]');if(b){b.disabled=true;b.textContent='Launching...';}return true;">
      <input type="hidden" name="csrf_token" value="{{.Csrf}}">
      <input type="hidden" name="job" value="{{.SpearJobID}}">
      <label for="spear_campaign">Spear name</label>
      <input type="text" id="spear_campaign" name="campaign" class="slim" value="{{.SpearCampaign}}">
      <label for="spear_url">Lure URL (targets open this)</label>
      <input type="text" id="spear_url" name="url" class="full" value="{{.SpearURL}}" placeholder="https://login.your-domain.com/...">
      <label for="spear_profile">Sending profile</label>
      <select id="spear_profile" name="profile" class="slim">
        {{range .SpearProfiles}}
        <option value="{{.}}">{{.}}</option>
        {{end}}
      </select>
      {{if eq .SpearChannel "sms"}}
      <label for="spear_phone">Target phone (goes into the Email column)</label>
      <input type="text" id="spear_phone" name="phone" class="slim" value="{{.SpearPhone}}" placeholder="+12025550134">
      {{end}}
      <button type="submit">Launch spear phishing</button>
    </form>
  </div>
  </div>
  {{end}}
  </div>
  </div>
  </div>
  {{end}}
  <script>
  (function(){
    var items = {};
    var nodes = document.querySelectorAll('[data-acc]');
    for (var i = 0; i < nodes.length; i++) { if (nodes[i].getAttribute('data-acc')) items[nodes[i].getAttribute('data-acc')] = nodes[i]; }
    var pills = document.querySelectorAll('.spear-step[data-goto]');
    var heads = document.querySelectorAll('[data-acc-head]');
    function accOpen(id, scroll) {
      for (var k in items) {
        if (!items.hasOwnProperty(k)) continue;
        var it = items[k];
        var on = (k === id);
        if (on) { it.classList.add('open'); } else { it.classList.remove('open'); }
        var h = it.querySelector('[data-acc-head]');
        if (h) h.setAttribute('aria-expanded', on ? 'true' : 'false');
      }
      for (var j = 0; j < pills.length; j++) {
        if (pills[j].classList.contains('view')) pills[j].classList.remove('view');
        if (pills[j].getAttribute('data-goto') === id) pills[j].classList.add('view');
      }
      if (id && items[id] && scroll && items[id].scrollIntoView) items[id].scrollIntoView({behavior: 'smooth', block: 'start'});
    }
    for (var a = 0; a < pills.length; a++) {
      (function(p){
        if (p.disabled) return;
        p.addEventListener('click', function(){ accOpen(p.getAttribute('data-goto'), true); });
      })(pills[a]);
    }
    for (var b = 0; b < heads.length; b++) {
      (function(h){
        h.addEventListener('click', function(){ accOpen(h.getAttribute('data-acc-head'), true); });
      })(heads[b]);
    }
    var nexts = document.querySelectorAll('[data-acc-next]');
    for (var c = 0; c < nexts.length; c++) {
      (function(n){
        n.addEventListener('click', function(){ accOpen(n.getAttribute('data-acc-next'), true); });
      })(nexts[c]);
    }
    var init = null;
    var cur = document.querySelector('.spear-step.current');
    if (cur) init = cur.getAttribute('data-goto');
    if ((!init || !items[init]) && pills.length) {
      for (var k = pills.length - 1; k >= 0; k--) {
        var g = pills[k].getAttribute('data-goto');
        if (g && items[g] && !pills[k].disabled) { init = g; break; }
      }
    }
    {{if .SpearGoto}}init = '{{.SpearGoto}}';{{end}}
    accOpen(init, window.location.search.indexOf('job=') !== -1);
  })();
  </script>
</main>
</body>
</html>
{{end}}
`
