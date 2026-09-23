"""
master_osint_pipeline.py — Unified LinkedIn OSINT + Legitimate Outreach Pipeline
================================================================================
Single-file, production-grade replacement for:
  scrap.py / linkedin_osint_strict.py / linkedin_osint_upgraded.py /
  linkedin_osint_outreach.py / osint_common.py

Three phases:
  Phase 1 — LinkedIn recon & data collection (strict, anti-hallucination).
  Phase 2 — Interactive review & scenario selection (CLI flags or prompt).
  Phase 3 — AI generation (Groq/OpenAI) with transparent template fallback.

SAFETY / AUTHORIZED-USE POLICY (enforced by design):
  * Use ONLY on profiles you are authorized to process, and ONLY to send
    lawful, transparent messages (networking, legitimate prospecting, or a
    clearly-labelled security-awareness TRAINING INVITATION sent as yourself).
  * This pipeline does NOT generate deceptive mail: no impersonation of IT /
    security / executives, no fake urgency ("account locked", "act now"),
    no credential / password / MFA-reset lures, no spoofed policy notices.
  * The `training-invite` scenario is an opt-in, clearly-identified invitation
    from the named sender — never a simulated phish. If you need a phishing
    simulation, use a dedicated, consent-gated platform (e.g. GoPhish with
    documented authorization), not this tool.

REQUIREMENTS:
  pip install pandas openpyxl requests

ENVIRONMENT VARIABLES (secrets are NEVER hardcoded):
  RAPIDAPI_KEY    LinkedIn provider key (RapidAPI, host below).
                  Without it: live fetch disabled, SQLite cache only.
  RAPIDAPI_HOST   Optional override (default: linkedin-profile-scraper9.p.rapidapi.com)
  RAPIDAPI_ENDPOINT
                  Optional endpoint path override for providers that use a
                  different route (default: /find-profile, e.g.
                  /get-profile-data-by-url). Must return the same envelope.
  GROQ_API_KEY    Enables primary LLM path (free tier). Optional.
  GROQ_MODEL      Optional override (default: llama-3.3-70b-versatile).
  OPENAI_API_KEY  Fallback LLM path (model gpt-4o-mini). Optional.
  OPENAI_MODEL    Optional override (default: gpt-4o-mini).
  GITHUB_TOKEN    Optional — raises GitHub API rate limit. Optional.
  WHOCORD_PATH    Optional — path to WhoCord repo clone.
  TOOKIE_PATH     Optional — path to TookieOSINT repo clone.

EXTERNAL BINARIES (all OPTIONAL — pipeline works without them):
  sherlock      pip install sherlock-project   (username footprint)
  WhoCord       git clone https://github.com/Siv-nick/WhoCord.git ./WhoCord
                run as: python -m discord_osint --mode manual --target HANDLE
                (full scans take 10+ min; needs no token in manual mode)
  TookieOSINT   git clone https://github.com/Alfredredbird/tookie-osint.git ./TookieOSINT

INPUT:
  Excel with a LinkedIn column (auto-detected):
    Profile_Link | LinkedIn_URL | LinkedIn | URL | Link
  Optional explicit-handle columns (NEVER guessed from LinkedIn slug):
    GitHub_Username | GitHub_Handle | GitHub_URL | Handle | Username
  Optional: Email | Email_Address (treated as user-provided, unverified).

OUTPUT:
  Single pristine Excel file. Columns whose every value is "Not Found"/empty
  are DROPPED; remaining placeholders are written as blank cells, so the file
  contains zero placeholder pollution.

USAGE:
  python master_osint_pipeline.py --input EXAMPLES.xlsx --output results.xlsx
  python master_osint_pipeline.py --input in.xlsx --list
  python master_osint_pipeline.py --input in.xlsx --output out.xlsx --select "1,3"
  python master_osint_pipeline.py --input in.xlsx --output out.xlsx --interactive
  python master_osint_pipeline.py --input in.xlsx --output out.xlsx --scenario training-invite --sender "Mohamed (Security Team)"
  python master_osint_pipeline.py --input in.xlsx --output out.xlsx --no-llm
  python master_osint_pipeline.py --check-tools
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import shutil
import sqlite3
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date
from pathlib import Path
from typing import Any, Callable, Optional

import pandas as pd
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


def _load_dotenv() -> None:
    """Load ./ .env once so keys persist without hardcoding them.

    Format per line: KEY=value  (quotes optional, # = comment).
    Existing real env vars always win over .env values.
    """
    try:
        env_file = Path(__file__).resolve().parent / ".env"
        if not env_file.is_file():
            return
        for line in env_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            k, v = k.strip(), v.strip().strip('"').strip("'")
            if k and v and k not in os.environ:
                os.environ[k] = v
    except Exception:
        pass


_load_dotenv()

# ---------------------------------------------------------------------------
# 0. Constants
# ---------------------------------------------------------------------------

NOT_FOUND = "Not Found"
NOT_RUN = "Not run"
NOT_SELECTED = "Not Selected"
NO_HANDLE = "Not Available (no explicit handle — LinkedIn slug is never used)"

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
HANDLE_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
SITE_NAME_RE = re.compile(r"^[A-Za-z0-9 _\-.]+$")
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
URL_RE = re.compile(r"https?://")
YEAR_RE = re.compile(r"(?:19|20)\d{2}")

EMPTY_TOKENS = {"", "not found", "none", "null", "nan", "n/a"}

LINKEDIN_COLUMNS = ["profile_link", "linkedin_url", "linkedin", "url", "link"]
HANDLE_COLUMNS = ["github_username", "github_handle", "github_user",
                  "github_login", "github", "github_url", "github_link",
                  "github_profile", "github_profile_url", "handle", "username"]
EMAIL_COLUMNS = ["email", "e-mail", "email_address", "emailaddress"]

MONTHS: dict[str, int] = {
    "jan": 1, "january": 1, "feb": 2, "february": 2,
    "mar": 3, "march": 3, "apr": 4, "april": 4,
    "may": 5, "jun": 6, "june": 6, "jul": 7, "july": 7,
    "aug": 8, "august": 8, "sep": 9, "sept": 9, "september": 9,
    "oct": 10, "october": 10, "nov": 11, "november": 11,
    "dec": 12, "december": 12,
}
_RANGE_RE = re.compile(
    r"(january|february|march|april|may|june|july|august|september|sept|"
    r"jan|feb|mar|apr|jun|jul|aug|sep|oct|nov|dec)?\s*((?:19|20)\d{2})",
    re.IGNORECASE,
)
_PRESENT_WORDS = ("present", "current", "now", "ongoing")

# Legitimate scenarios ONLY. There is deliberately no "urgent IT notice" /
# "account action required" / spoofed-policy scenario — those are phishing
# patterns and are refused by design (see module docstring).
SCENARIOS = (
    "networking",        # genuine connection request, no pitch, no link
    "outreach",          # legitimate value-prop email (needs --name + --desc)
    "training-invite",   # transparent, opt-in security-awareness invite
    "github-invite",     # transparent GitHub collaborator invite (needs --invite)
)

COLUMN_ORDER = ["Name", "LinkedIn_URL", "Location", "Current_Position",
                "Company", "Industry", "Years_Experience", "Seniority_Level",
                "Skills", "Education", "About", "Email", "Email_Confidence",
                "Email_Source", "Verified_GitHub", "Verified_GitHub_URL",
                "Scenario", "Email_Subject", "Personalized_Email_Body",
                "Email_Generator", "Outreach_Context",
                "Sherlock_Status", "Sherlock_Found_Links",
                "Whocord_Status", "Whocord_Data",
                "Tookie_Status", "Tookie_Results",
                "Fetch_Origin"]

CACHE_DB = "master_osint_cache.sqlite"
MAX_WORKERS = 16
MAX_TIMEOUT = 7200
MIN_TIMEOUT = 5
EMAIL_SUBJECT_CAP = 78
EMAIL_BODY_WORD_CAP = 160

# Placeholders / deception markers that must NEVER reach output copy.
PLACEHOLDER_TOKENS = ("{", "}", "[Your", "TODO", "Lorem", "<insert",
                      "undefined")
DECEPTION_RE = re.compile(
    r"(account.{0,20}(locked|suspended|compromised|disabled)"
    r"|immediate action required|act (now|immediately)"
    r"|verify your (password|credentials|account)"
    r"|password ex Hanna|mfa.{0,20}reset"
    r"|click (here|below) to (verify|unlock|restore)"
    r"|failure to comply|final warning)",
    re.IGNORECASE,
)
PITCH_RE = re.compile(
    r"\b(free trial|demo|pricing|discount|buy now|limited offer)\b",
    re.IGNORECASE,
)

logger = logging.getLogger("master_osint")

# ---------------------------------------------------------------------------
# 1. Small helpers (text / rows / dates / experience)
# ---------------------------------------------------------------------------

def _text(v: Any) -> str:
    return str(v).strip() if v is not None else ""


def strict_field(v: Any) -> str:
    t = _text(v)
    return NOT_FOUND if not t or t.lower() in EMPTY_TOKENS else t


def _colmap(columns: list) -> dict[str, str]:
    return {str(c).strip().lower(): str(c) for c in columns}


def find_col(colmap: dict[str, str], candidates: list[str]) -> Optional[str]:
    for c in candidates:
        if c in colmap:
            return colmap[c]
    return None


def _cell(row: pd.Series, col: Optional[str]) -> str:
    if not col or col not in row or pd.isna(row[col]):
        return ""
    return str(row[col]).strip()


def is_placeholder(v: Any) -> bool:
    if v is None:
        return True
    if isinstance(v, float) and pd.isna(v):
        return True
    s = str(v).strip()
    return not s or s.lower() in EMPTY_TOKENS


def parse_explicit_handle(v: Any) -> str:
    """Bare username or github.com/<login> URL. Never derives from LinkedIn."""
    t = _text(v)
    if not t or t.lower() in EMPTY_TOKENS:
        return ""
    m = re.search(r"github\.com/([A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?)",
                  t, re.IGNORECASE)
    if m:
        return m.group(1)
    cand = t.lstrip("@").strip().split()[0].split("/")[0]
    return cand if HANDLE_RE.match(cand) else ""


def month_index(year: int, month: int) -> int:
    return year * 12 + month - 1


def _valid_ym(year: int, month: int) -> Optional[tuple[int, int]]:
    if 1900 <= year <= date.today().year + 1:
        return year, max(1, min(12, month))
    return None


def parse_year_month(v: Any) -> Optional[tuple[int, int]]:
    if v is None or v == "":
        return None
    if isinstance(v, dict):
        year = v.get("year") or v.get("Year")
        month = v.get("month") or v.get("Month") or 1
        if not year:
            nested = v.get("date") or v.get("value") or v.get("text")
            return parse_year_month(nested) if nested else None
        if isinstance(month, str):
            month = MONTHS.get(month.strip().lower(), 1)
        try:
            return _valid_ym(int(year), int(month))
        except (TypeError, ValueError):
            return None
    if hasattr(v, "year") and hasattr(v, "month"):
        try:
            return _valid_ym(int(v.year), int(v.month))
        except (TypeError, ValueError):
            return None
    t = _text(v).lower()
    if not t:
        return None
    ym = YEAR_RE.search(t)
    if not ym:
        return None
    mi = next((n for n, mn in MONTHS.items() if re.search(rf"\b{n}\b", t)), 1)
    return _valid_ym(int(ym.group(0)), mi)


def parse_duration_months(v: Any) -> int:
    t = _text(v).lower()
    yrs = re.search(r"(\d+(?:\.\d+)?)\s*(?:yr|yrs|year|years)", t)
    mos = re.search(r"(\d+)\s*(?:mo|mos|month|months)", t)
    total = 0.0
    if yrs:
        total += float(yrs.group(1)) * 12
    if mos:
        total += int(mos.group(1))
    return max(0, round(total))


def parse_duration_range(v: Any, cur: int) -> Optional[tuple[int, int]]:
    t = _text(v)
    if not t or not YEAR_RE.search(t):
        return None
    low = t.lower()
    is_cur = any(w in low for w in _PRESENT_WORDS)
    parts = _RANGE_RE.findall(low)
    if not parts or (len(parts) < 2 and not is_cur):
        return None
    start = month_index(int(parts[0][1]), MONTHS.get(parts[0][0] or "", 1))
    end = cur if is_cur else month_index(int(parts[-1][1]),
                                         MONTHS.get(parts[-1][0] or "", 12))
    return (start, end) if end >= start else None


_START_KEYS = ("start_date", "startDate", "start", "from", "date_from")
_END_KEYS = ("end_date", "endDate", "end", "to", "date_to")
_RANGE_KEYS = ("duration_range", "durationRange", "time_period",
               "timePeriod", "duration_text")
_DURATION_KEYS = ("duration", "time_period", "timePeriod", "duration_text")


def _first(d: dict, keys: tuple[str, ...]) -> Any:
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    return None


def calculate_experience(exps: list, today: Optional[date] = None) -> float:
    if not isinstance(exps, list) or not exps:
        return 0.0
    today = today or date.today()
    cur = month_index(today.year, today.month)
    intervals: list[tuple[int, int]] = []
    fallback = 0
    for job in exps:
        if not isinstance(job, dict):
            continue
        s_raw, e_raw = _first(job, _START_KEYS), _first(job, _END_KEYS)
        s, e = parse_year_month(s_raw), parse_year_month(e_raw)
        e_txt = _text(e_raw).lower()
        is_cur = not e_raw or any(w in e_txt for w in _PRESENT_WORDS)
        if s:
            si = month_index(*s)
            ei = cur if (is_cur or not e) else month_index(*e)
            if ei >= si:
                intervals.append((si, ei))
                continue
        iv = parse_duration_range(_first(job, _RANGE_KEYS), cur)
        if iv:
            intervals.append(iv)
        else:
            fallback += parse_duration_months(_first(job, _DURATION_KEYS))
    if not intervals and not fallback:
        return 0.0
    intervals.sort()
    merged: list[list[int]] = []
    for si, ei in intervals:
        if not merged or si > merged[-1][1] + 1:
            merged.append([si, ei])
        else:
            merged[-1][1] = max(merged[-1][1], ei)
    dated = sum(ei - si + 1 for si, ei in merged)
    return round((dated + fallback) / 12, 1)


def determine_seniority(years: float, title: str) -> str:
    tl = str(title).lower()
    if any(k in tl for k in ["ceo", "founder", "vp", "president",
                             "director", "chief", "partner", "head"]):
        return "Executive / Leadership"
    if years >= 10:
        return "Senior / Expert"
    if years >= 5:
        return "Mid-Senior Level"
    if years >= 2:
        return "Mid-Level"
    return "Entry-Level / Junior"


def parse_education(raw: Any) -> str:
    items: list[str] = []
    seen: set[str] = set()

    def add(e: str) -> None:
        if e and e.lower() not in seen:
            seen.add(e.lower())
            items.append(e)

    if isinstance(raw, list):
        for e in raw:
            if isinstance(e, dict):
                deg = _text(e.get("degree_name") or e.get("degree"))
                sch = _text(e.get("school_name") or e.get("school")
                            or e.get("institution_name"))
                if sch:
                    add(f"{deg} at {sch}".strip() if deg else sch)
            elif isinstance(e, str) and e.strip():
                add(e.strip())
    return " | ".join(items) if items else NOT_FOUND


def normalize_skills(raw: Any) -> list[str]:
    items: list[str] = []
    if isinstance(raw, list):
        for s in raw:
            if isinstance(s, dict):
                name = _text(s.get("name") or s.get("title") or s.get("skill"))
                if name:
                    items.append(name)
            elif isinstance(s, str) and s.strip():
                items.append(s.strip())
    seen: set[str] = set()
    return [x for x in items if not (x.lower() in seen or seen.add(x.lower()))]


def gate_email(resp: dict, threshold: float = 0.8) -> tuple[str, str, str]:
    """(email, confidence, source) — passes ONLY above threshold."""
    info = resp.get("email_data") or resp.get("email")
    if isinstance(info, dict):
        addr = _text(info.get("email"))
        try:
            conf = float(info.get("confidence", 0) or 0)
        except (TypeError, ValueError):
            return NOT_FOUND, NOT_FOUND, NOT_FOUND
        if (info.get("is_found") and EMAIL_RE.match(addr) and conf >= threshold
                and str(info.get("email_deliverability", "")).upper() != "INVALID"):
            return addr, str(info.get("confidence")), "linkedin-api (verified)"
        return NOT_FOUND, NOT_FOUND, NOT_FOUND
    return NOT_FOUND, NOT_FOUND, NOT_FOUND


# ---------------------------------------------------------------------------
# 2. Thread-safe SQLite cache
# ---------------------------------------------------------------------------

_cache_lock = threading.Lock()


def ensure_table(ddl: str) -> None:
    try:
        with _cache_lock:
            conn = sqlite3.connect(CACHE_DB, timeout=10)
            try:
                conn.execute(ddl)
                conn.commit()
            finally:
                conn.close()
    except Exception:
        pass


def cache_get(table: str, key: str) -> Optional[str]:
    if not os.path.exists(CACHE_DB):
        return None
    try:
        with _cache_lock:
            conn = sqlite3.connect(CACHE_DB, timeout=10)
            try:
                row = conn.execute(
                    f"SELECT data FROM {table} WHERE url = ?", (key,)).fetchone()
            finally:
                conn.close()
        return row[0] if row and row[0] else None
    except Exception:
        return None


def cache_set(table: str, key: str, value: str) -> None:
    try:
        import time as _t
        with _cache_lock:
            conn = sqlite3.connect(CACHE_DB, timeout=10)
            try:
                conn.execute(f"CREATE TABLE IF NOT EXISTS {table} "
                             "(url TEXT PRIMARY KEY, data TEXT, ts REAL)")
                conn.execute(f"INSERT OR REPLACE INTO {table} (url, data, ts)"
                             " VALUES (?, ?, ?)", (key, value, _t.time()))
                conn.commit()
            finally:
                conn.close()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# 3. HTTP sessions + LinkedIn client + GitHub verify
# ---------------------------------------------------------------------------

_thread_state = threading.local()


def http_session() -> requests.Session:
    s = getattr(_thread_state, "session", None)
    if s is None:
        s = requests.Session()
        retry = Retry(total=3, backoff_factor=1.0,
                      status_forcelist=(429, 500, 502, 503, 504),
                      allowed_methods=("GET", "POST"))
        adapter = HTTPAdapter(max_retries=retry,
                              pool_connections=8, pool_maxsize=8)
        s.mount("https://", adapter)
        s.mount("http://", adapter)
        s.headers.update({"User-Agent": "master-osint/1.0"})
        _thread_state.session = s
    return s


def provider_msg_from_data(data: Any) -> str:
    """Extract the provider's own error message (RapidAPI forwards it).

    Bare status codes ("API Error 404") hide whether the key, host, path
    or quota is wrong — the provider message usually names it exactly.
    """
    if isinstance(data, dict):
        for key in ("message", "messages", "error", "detail"):
            val = data.get(key)
            if isinstance(val, str) and val.strip():
                return ": " + val.strip()[:220]
    return ""


class LinkedInClient:
    def __init__(self, timeout: int = 60, max_retries: int = 3) -> None:
        self.key = os.environ.get("RAPIDAPI_KEY", "").strip()
        self.host = os.environ.get(
            "RAPIDAPI_HOST",
            "linkedin-profile-scraper9.p.rapidapi.com").strip()
        # Path differs per provider (e.g. /find-profile vs
        # /get-profile-data-by-url) — override without touching code.
        self.endpoint_path = os.environ.get(
            "RAPIDAPI_ENDPOINT", "/find-profile").strip() or "/find-profile"
        if not self.endpoint_path.startswith("/"):
            self.endpoint_path = "/" + self.endpoint_path
        self.endpoint = f"https://{self.host}{self.endpoint_path}"
        self.timeout = timeout
        self.max_retries = max(1, max_retries)
        if not self.key:
            logger.warning("RAPIDAPI_KEY not set — live fetch disabled "
                           "(cache only).")

    def get(self, clean_url: str) -> tuple[Optional[dict], str, Optional[str]]:
        if not clean_url:
            return None, "error", "empty URL"
        # Check new cache + legacy caches for backward compat.
        for db, table, kcol, vcol in (
                (CACHE_DB, "profile_cache", "url", "data"),
                ("linkedin_cache.sqlite", "profiles", "url", "payload"),
                ("linkedin_cache.sqlite", "linkedin_cache", "url", "data"),
                ("cache_profiles.db", "profile_cache", "url", "data")):
            if not os.path.exists(db):
                continue
            try:
                with _cache_lock:
                    conn = sqlite3.connect(db, timeout=10)
                    try:
                        row = conn.execute(
                            f"SELECT {vcol} FROM {table} WHERE {kcol} = ?",
                            (clean_url,)).fetchone()
                    finally:
                        conn.close()
                if row and row[0]:
                    return json.loads(row[0]), "cache", None
            except Exception:
                continue
        if not self.key:
            return None, "error", "RAPIDAPI_KEY not set (cache miss)"
        headers = {"x-rapidapi-key": self.key, "x-rapidapi-host": self.host}
        last = "Max Retries Exceeded"
        for attempt in range(self.max_retries):
            try:
                r = http_session().get(self.endpoint, headers=headers,
                                       params={"url": clean_url},
                                       timeout=self.timeout)
                if r.status_code == 200:
                    data = r.json()
                    if data.get("success"):
                        cache_set("profile_cache", clean_url, json.dumps(data))
                        return data, "live-api", None
                    return None, "api-empty", (
                        "No usable profile data"
                        + provider_msg_from_data(data))
                if r.status_code in (429, 502, 503, 504):
                    last = f"API Error {r.status_code}"
                    time.sleep(2 ** attempt)
                    continue
                try:
                    detail = provider_msg_from_data(r.json())
                except Exception:
                    detail = ""
                return None, "api-error", f"API Error {r.status_code}{detail}"
            except Exception as e:
                last = str(e) or type(e).__name__
                time.sleep(2)
        return None, "error", last


def verify_github(handle: str) -> tuple[str, str]:
    """Live-verify explicit handle. Returns (handle_or_NotFound, url)."""
    if not handle or not HANDLE_RE.match(handle):
        return NOT_FOUND, NOT_FOUND
    try:
        cached = cache_get("github_cache", handle.lower())
        if cached:
            d = json.loads(cached)
            if isinstance(d, dict) and d.get("login"):
                return handle, d.get("html_url") or NOT_FOUND
    except Exception:
        pass
    headers = {"Accept": "application/vnd.github+json",
               "User-Agent": "master-osint/1.0"}
    tok = os.environ.get("GITHUB_TOKEN", "").strip()
    if tok:
        headers["Authorization"] = f"Bearer {tok}"
    try:
        r = http_session().get(f"https://api.github.com/users/{handle}",
                               headers=headers, timeout=20)
        if r.status_code == 200 and (r.json() or {}).get("login"):
            d = r.json()
            try:
                cache_set("github_cache", handle.lower(), json.dumps(d))
            except Exception:
                pass
            return handle, d.get("html_url") or NOT_FOUND
    except Exception as e:
        logger.debug("GitHub verify failed: %s", e)
    return NOT_FOUND, NOT_FOUND


# ---------------------------------------------------------------------------
# 4. External tools (Sherlock / WhoCord / Tookie) — all optional
# ---------------------------------------------------------------------------

def _utf8_env() -> dict:
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    return env


def _run(argv: list[str], cwd: Optional[str] = None,
         timeout: int = 300) -> tuple[Optional[int], str, str, bool]:
    try:
        p = subprocess.run(argv, cwd=cwd or None, capture_output=True,
                           text=True, timeout=timeout, env=_utf8_env(),
                           shell=False)
        return p.returncode, p.stdout or "", p.stderr or "", False
    except subprocess.TimeoutExpired as e:
        out = e.stdout.decode("utf-8", "replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
        err = e.stderr.decode("utf-8", "replace") if isinstance(e.stderr, bytes) else (e.stderr or "")
        return None, out, err, True


def _tail(text: str, cap: int = 500) -> str:
    return " | ".join(t.strip() for t in (text or "").strip().splitlines()[-5:] if t.strip())[:cap]


def run_sherlock(handle: str, sites: Optional[list[str]] = None,
                 timeout: int = 300) -> dict:
    if not handle or not HANDLE_RE.match(handle):
        return {"Sherlock_Status": NO_HANDLE,
                "Sherlock_Found_Links": NOT_FOUND}
    if not shutil.which("sherlock"):
        return {"Sherlock_Status": "Not Available (pip install sherlock-project)",
                "Sherlock_Found_Links": NOT_FOUND}
    cmd = ["sherlock", handle, "--print-found", "--timeout", "10", "--no-color"]
    for s in sites or []:
        s = str(s).strip()
        if SITE_NAME_RE.match(s):
            cmd += ["--site", s]
    code, out, err, timed_out = _run(cmd, timeout=timeout)
    if not timed_out and "data.sherlockproject.xyz" in err:
        code, out, err, timed_out = _run(cmd + ["--local"], timeout=timeout)
    found = [l.strip() for l in ANSI_RE.sub("", out).splitlines()
             if l.strip().startswith("[+]")]
    if found:
        return {"Sherlock_Status": f"Success: found {len(found)} link(s)",
                "Sherlock_Found_Links": " | ".join(found[:20])}
    if timed_out:
        return {"Sherlock_Status": f"Error: timed out after {timeout}s",
                "Sherlock_Found_Links": NOT_FOUND}
    if code != 0:
        return {"Sherlock_Status": f"Error: exit {code}: {_tail(err)}",
                "Sherlock_Found_Links": NOT_FOUND}
    return {"Sherlock_Status": "No Results",
            "Sherlock_Found_Links": NOT_FOUND}


def _find_repo(env_key: str, names: list[str],
               marker: list[str]) -> Optional[str]:
    cands: list[str] = []
    if os.environ.get(env_key, "").strip():
        cands.append(os.environ[env_key].strip())
    here = Path(__file__).resolve().parent
    cands += [str(here / n) for n in names]
    for c in cands:
        if c and (Path(c) / Path(*marker)).exists():
            return c
    return None


def run_whocord(handle: str, timeout: int = 1200) -> dict:
    if not handle or not HANDLE_RE.match(handle):
        return {"Whocord_Status": NO_HANDLE, "Whocord_Data": NOT_FOUND}
    repo = _find_repo("WHOCORD_PATH", ["WhoCord", "whocord"],
                      ["discord_osint", "__main__.py"])
    if not repo:
        return {"Whocord_Status": "Not Available (clone "
                "https://github.com/Siv-nick/WhoCord.git as ./WhoCord)",
                "Whocord_Data": NOT_FOUND}
    import sys as _sys
    cache = Path(repo) / "investigation_cache"
    before = {p.name for p in cache.glob("*.json")} if cache.exists() else set()
    code, out, err, timed_out = _run(
        [_sys.executable, "-u", "-m", "discord_osint", "--mode", "manual",
         "--target", handle, "--output", "json"], cwd=repo, timeout=timeout)
    if timed_out:
        return {"Whocord_Status": f"Error: timed out after {timeout}s",
                "Whocord_Data": NOT_FOUND}
    if code != 0:
        return {"Whocord_Status": f"Error: exit {code}: {_tail(err + chr(10) + out)}",
                "Whocord_Data": NOT_FOUND}
    reports = sorted(cache.glob("*.json"),
                     key=lambda p: p.stat().st_mtime) if cache.exists() else []
    fresh = [p for p in reports if p.name not in before]
    newest = fresh[-1] if fresh else (reports[-1] if reports else None)
    if not newest:
        return {"Whocord_Status": "No Results (no report generated)",
                "Whocord_Data": NOT_FOUND}
    try:
        summary = json.dumps(json.loads(newest.read_text(encoding="utf-8")),
                             ensure_ascii=False)[:4000]
    except Exception:
        summary = newest.read_text(encoding="utf-8", errors="replace")[:4000]
    return {"Whocord_Status": "Success", "Whocord_Data": summary}


def run_tookie(handle: str, timeout: int = 600, threads: int = 10) -> dict:
    if not handle or not HANDLE_RE.match(handle):
        return {"Tookie_Status": NO_HANDLE, "Tookie_Results": NOT_FOUND}
    repo = _find_repo("TOOKIE_PATH", ["TookieOSINT", "tookie-osint"],
                      ["brib.py"])
    if not repo:
        return {"Tookie_Status": "Not Available (clone "
                "https://github.com/Alfredredbird/tookie-osint.git "
                "as ./TookieOSINT)", "Tookie_Results": NOT_FOUND}
    import sys as _sys
    threads = max(1, min(50, int(threads)))
    before = {p.name for p in Path(repo).glob("*.json")}
    code, out, err, timed_out = _run(
        [_sys.executable, "-u", "brib.py", "-u", handle, "-sC", "-o", "json",
         "-t", str(threads), "--skipheaders", "-sr"], cwd=repo, timeout=timeout)
    links: list[str] = []
    for line in ANSI_RE.sub("", out).splitlines():
        m = re.match(r"\s*\[\+\]\s*(https?://\S+)", line.strip())
        if m and m.group(1) not in links:
            links.append(m.group(1))
    fresh = [p for p in Path(repo).glob("*.json") if p.name not in before]
    if fresh:
        try:
            newest = max(fresh, key=lambda p: p.stat().st_mtime)
            for entry in json.loads(newest.read_text(encoding="utf-8")):
                if isinstance(entry, dict) and entry.get("found") and entry.get("url"):
                    if entry["url"] not in links:
                        links.append(entry["url"])
        except Exception as e:
            logger.debug("Tookie JSON parse failed: %s", e)
    if links:
        status = f"Success: found {len(links)} link(s)"
        if timed_out:
            status = f"Partial (timed out after {timeout}s): found {len(links)} link(s)"
        elif code != 0:
            status = f"Partial (exit {code}): found {len(links)} link(s)"
        return {"Tookie_Status": status,
                "Tookie_Results": " | ".join(links[:30])}
    if timed_out:
        return {"Tookie_Status": f"Error: timed out after {timeout}s",
                "Tookie_Results": NOT_FOUND}
    if code != 0:
        return {"Tookie_Status": f"Error: exit {code}: {_tail(err)}",
                "Tookie_Results": NOT_FOUND}
    return {"Tookie_Status": "No Results", "Tookie_Results": NOT_FOUND}


def check_tools() -> dict:
    out: dict[str, str] = {}
    out["sherlock_binary"] = shutil.which("sherlock") or "MISSING"
    try:
        r = http_session().get("https://api.github.com/rate_limit", timeout=15)
        out["github_api"] = f"reachable (HTTP {r.status_code})"
    except Exception as e:
        out["github_api"] = f"UNREACHABLE: {e}"
    out["rapidapi_key"] = ("set" if os.environ.get("RAPIDAPI_KEY", "").strip()
                           else "NOT SET (cache only)")
    out["groq_key"] = ("set" if os.environ.get("GROQ_API_KEY", "").strip()
                       else "NOT SET (template fallback)")
    out["openai_key"] = ("set" if os.environ.get("OPENAI_API_KEY", "").strip()
                         else "NOT SET")
    out["whocord_repo"] = (_find_repo("WHOCORD_PATH", ["WhoCord", "whocord"],
                                      ["discord_osint", "__main__.py"])
                           or "MISSING")
    out["tookie_repo"] = (_find_repo("TOOKIE_PATH",
                                     ["TookieOSINT", "tookie-osint"],
                                     ["brib.py"]) or "MISSING")
    return out


# ---------------------------------------------------------------------------
# 5. Phase 1 — recon
# ---------------------------------------------------------------------------

def fetch_row(client: LinkedInClient, idx: int, total: int,
              linkedin_url: str, email_threshold: float) -> dict:
    """Strict OSINT parse of one profile. No guessing, ever."""
    clean_url = str(linkedin_url).split("?")[0].strip()
    logger.info("[%d/%d] %s", idx + 1, total, clean_url or "(empty)")
    payload, origin, error = client.get(clean_url)
    if payload is None:
        return {
            "Name": f"ERROR: {error or 'No Data'}",
            "LinkedIn_URL": clean_url or NOT_FOUND, "Location": NOT_FOUND,
            "Current_Position": NOT_FOUND, "Company": NOT_FOUND,
            "Industry": NOT_FOUND, "Years_Experience": 0.0,
            "Seniority_Level": NOT_FOUND, "Skills": NOT_FOUND,
            "Education": NOT_FOUND, "About": NOT_FOUND, "Email": NOT_FOUND,
            "Email_Confidence": NOT_FOUND, "Email_Source": NOT_FOUND,
            "Fetch_Origin": origin,
        }
    resp = payload.get("response", {}) or {}
    name = strict_field(resp.get("full_name"))
    position = strict_field(resp.get("job_title") or resp.get("headline"))
    company = strict_field((resp.get("company", {}) or {}).get("name"))
    exps = resp.get("work_experience") or resp.get("experiences") or []
    if exps and isinstance(exps[0], dict):
        latest = _text(exps[0].get("company_name") or exps[0].get("company"))
        if latest:
            company = latest
    industry = strict_field((resp.get("company", {}) or {}).get("industry"))
    exp_list = exps if isinstance(exps, list) else []
    years = calculate_experience(exp_list)
    email, conf, src = gate_email(resp, email_threshold)
    return {
        "Name": name, "LinkedIn_URL": clean_url,
        "Location": strict_field(resp.get("location")),
        "Current_Position": position, "Company": company,
        "Industry": industry, "Years_Experience": years,
        "Seniority_Level": determine_seniority(
            years, position if position != NOT_FOUND else ""),
        "Skills": ", ".join(normalize_skills(
            resp.get("skills") or resp.get("skill") or [])) or NOT_FOUND,
        "Education": parse_education(
            resp.get("education") or resp.get("educations") or []),
        "About": strict_field(resp.get("about") or resp.get("summary")),
        "Email": email, "Email_Confidence": conf, "Email_Source": src,
        "Fetch_Origin": origin,
    }


def _safe_fetch(client: LinkedInClient, *a: Any, **k: Any) -> dict:
    try:
        return fetch_row(client, *a, **k)
    except Exception as e:
        logger.error("Fetch failed: %s", e)
        return {"Name": f"ERROR: {e}"[:200], "LinkedIn_URL": NOT_FOUND,
                "Location": NOT_FOUND, "Current_Position": NOT_FOUND,
                "Company": NOT_FOUND, "Industry": NOT_FOUND,
                "Years_Experience": 0.0, "Seniority_Level": NOT_FOUND,
                "Skills": NOT_FOUND, "Education": NOT_FOUND,
                "About": NOT_FOUND, "Email": NOT_FOUND,
                "Email_Confidence": NOT_FOUND, "Email_Source": NOT_FOUND,
                "Fetch_Origin": "error"}


# ---------------------------------------------------------------------------
# 6. Phase 2 — interactive review & scenario layer
# ---------------------------------------------------------------------------

EDITABLE_FIELDS = ["Name", "Current_Position", "Company", "Industry",
                   "Location", "Skills", "Education", "Email", "About"]


def print_roster(rows: list[dict]) -> None:
    print(f"\n{'#':<4}{'Name':<24}{'Position':<34}{'Company'}")
    print("-" * 90)
    for i, r in enumerate(rows):
        print(f"{i + 1:<4}{str(r.get('Name'))[:23]:<24}"
              f"{str(r.get('Current_Position'))[:33]:<34}{r.get('Company')}")
    print('\nSelect with: --select "1,3"  or  --select "omar,moaz"\n')


def resolve_selection(selector: str, rows: list[dict]) -> set[int]:
    if not (selector or "").strip():
        return set(range(len(rows)))
    picked: set[int] = set()
    for token in (t.strip() for t in selector[:2000].split(",") if t.strip()):
        if token.isdigit():
            i = int(token) - 1
            if 0 <= i < len(rows):
                picked.add(i)
            else:
                logger.warning("Index %s out of range — ignored.", token)
            continue
        matches = [i for i, r in enumerate(rows)
                   if token.lower() in str(r.get("Name", "")).lower()]
        if matches:
            picked.update(matches)
        else:
            logger.warning("No profile matches '%s' — ignored.", token)
    return picked


def choose_scenario(args: argparse.Namespace) -> tuple[str, str]:
    """Returns (scenario, free-text note). CLI flags win; else prompt."""
    scenario = (args.scenario or "").strip().lower()
    note = (args.scenario_note or "").strip()
    if scenario and scenario in SCENARIOS:
        return scenario, note
    if scenario and scenario not in SCENARIOS:
        logger.warning("Unknown scenario '%s' — falling back to prompt. "
                       "Valid: %s", scenario, ", ".join(SCENARIOS))
        scenario = ""
    if args.no_interactive:
        return scenario or "networking", note
    print("\n--- Scenario (legitimate, transparent messages only) ---")
    for i, s in enumerate(SCENARIOS, 1):
        print(f"  {i}. {s}")
    print("  (Deceptive 'urgent IT / policy action' lures are not offered.)")
    try:
        raw = input(f"Choose scenario [1-{len(SCENARIOS)}, default 1]: ").strip()
    except (EOFError, KeyboardInterrupt):
        raw = ""
    mapping = {str(i): s for i, s in enumerate(SCENARIOS, 1)}
    scenario = mapping.get(raw, SCENARIOS[0] if not raw else "")
    if scenario not in SCENARIOS:
        scenario = "networking"
    if not note:
        try:
            note = input("Optional context note (1 line, factual only): ").strip()
        except (EOFError, KeyboardInterrupt):
            note = ""
    return scenario, note[:500]


def interactive_review(rows: list[dict], args: argparse.Namespace) -> list[dict]:
    """Let the operator inspect / correct / drop rows before generation."""
    if args.no_interactive:
        return rows
    print_roster(rows)
    try:
        raw = input("Review: press Enter to accept all, 'e' to edit, "
                    "'d' to drop rows (e.g. d 2,3): ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return rows
    if raw.startswith("d"):
        nums = re.findall(r"\d+", raw)
        drop = {int(n) - 1 for n in nums if n.isdigit()}
        kept = [r for i, r in enumerate(rows) if i not in drop]
        print(f"Dropped {len(rows) - len(kept)} row(s).")
        rows = kept
        print_roster(rows)
        try:
            raw = input("Press Enter to continue, 'e' to edit: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            raw = ""
    if raw == "e":
        for i, r in enumerate(rows):
            print(f"\n--- [{i + 1}/{len(rows)}] {r.get('Name')} ---")
            for f in EDITABLE_FIELDS:
                cur = r.get(f, NOT_FOUND)
                shown = "" if is_placeholder(cur) else str(cur)[:120]
                try:
                    new = input(f"  {f} [{shown}]: ").strip()
                except (EOFError, KeyboardInterrupt):
                    new = ""
                if new:
                    r[f] = new
                elif new == "" and False:
                    pass
            # Recompute seniority if title/years touched.
            try:
                yrs = float(r.get("Years_Experience", 0) or 0)
            except (TypeError, ValueError):
                yrs = 0.0
                r["Years_Experience"] = 0.0
            pos = r.get("Current_Position", "")
            r["Seniority_Level"] = determine_seniority(
                yrs, "" if is_placeholder(pos) else str(pos))
    return rows


# ---------------------------------------------------------------------------
# 7. Phase 3 — generation (LLM first, transparent template fallback)
# ---------------------------------------------------------------------------

_LLM_SYSTEM = (
    "You write short, lawful, transparent B2B messages. You MUST use ONLY the "
    "verified prospect fields given in the user message. If a field is empty, "
    "work around it naturally and NEVER invent a name, company, metric, or fact. "
    "STRICT PROHIBITIONS: never impersonate IT, security, HR, or an executive; "
    "never create false urgency (no 'account locked', 'act now', 'suspended'); "
    "never request passwords, credentials, MFA codes, or bank details; never "
    "spoof a policy notice or system alert. "
    "Scenario rules: 'networking' = genuine connection request, no pitch, no link. "
    "'outreach' = ground the hook in product_scenario when present; include "
    "product_url once as a plain URL only if non-empty, else NO link. "
    "'training-invite' = a clearly-identified, opt-in training invitation sent "
    "AS the named sender (e.g. 'I'm Mohamed from ...'); state it is optional "
    "training, give what/where, invite them to reply — never a trick or test. "
    "'github-invite' = a transparent GitHub collaborator invitation sent AS the "
    "named sender: name the repo in invite_repo EXACTLY as given, state it is "
    "private, say they must accept the invitation and be logged in to browse it. "
    "If a verified GitHub handle is in context, address the invite to that account. "
    "The CTA asks them to accept the invite. No urgency, no pressure. "
    "Sign off with sender_name when non-empty, else 'Best regards' with NO name. "
    "Reply with a single JSON object: {\"subject\": \"...\", \"body\": \"...\"}. "
    "Subject under 50 chars. Body under 130 words: icebreaker tied to verified "
    "role/company, one relevant line, one low-friction question CTA. Plain text."
)

_GROQ_PREFERENCE = (
    "llama-3.3-70b-versatile",
    "meta-llama/llama-4-maverick-17b-128e-instruct",
    "meta-llama/llama-4-scout-17b-16e-instruct",
    "openai/gpt-oss-120b",
    "openai/gpt-oss-20b",
    "llama-3.1-8b-instant",
)
_SKIP_HINTS = ("whisper", "tts", "embed", "guard", "vision", "transcri")


def _hook_for(position: str, industry: str) -> tuple[str, str]:
    hooks: list[tuple[tuple[str, ...], str, str]] = [
        (("threat intelligence", "soc analyst", "security operations",
          "incident response", "penetration", "cyber security",
          "cybersecurity"), "security operations",
         "SOC alert fatigue and slow triage queues"),
        (("data scientist", "data analyst", "data analytics",
          "machine learning", "business intelligence"),
         "data & analytics", "manual reporting work that eats analysis time"),
        (("software", "developer", "devops", "cloud"),
         "engineering", "release bottlenecks and tool sprawl"),
    ]
    searchable = f"{position} {industry}".lower()
    for kws, hook, pain in hooks:
        if any(re.search(rf"\b{re.escape(k)}\b", searchable) for k in kws):
            return hook, pain
    if industry and not is_placeholder(industry):
        return industry.lower(), f"the day-to-day challenges facing {industry} teams"
    return "", ""


class EmailGenerator:
    SAFE_SUBJECT = "Quick hello and request to connect"
    SAFE_BODY = ("Hi there,\n\nI've been researching strong professionals lately, "
                 "and your profile stood out. I'd love to stay in touch and follow "
                 "your work.\n\nWould you be open to connecting here?\n\nBest regards,")

    def __init__(self, product: dict[str, str], scenario: str = "networking",
                 scenario_note: str = "", use_llm: bool = True,
                 llm_timeout: int = 60) -> None:
        self.product = {k: (v or "").strip() for k, v in (product or {}).items()}
        self.scenario = scenario if scenario in SCENARIOS else "networking"
        self.scenario_note = (scenario_note or "").strip()[:500]
        self.use_llm = use_llm
        self.llm_timeout = llm_timeout

    @property
    def has_product(self) -> bool:
        return bool(self.product.get("product_name")
                    and self.product.get("product_desc"))

    # -- validation ------------------------------------------------------
    def _validate(self, subject: str, body: str) -> None:
        blob = f"{subject}\n{body}"
        if DECEPTION_RE.search(blob):
            raise ValueError("deceptive urgency/impersonation language")
        for marker in PLACEHOLDER_TOKENS:
            if marker in ("{", "}"):
                continue
            if marker.lower() in blob.lower():
                raise ValueError(f"placeholder leak: {marker!r}")
        if re.search(r"\bnot found\b", blob, re.IGNORECASE):
            raise ValueError("placeholder leak: 'Not Found'")
        if re.search(r"\bnull\b", blob, re.IGNORECASE):
            raise ValueError("placeholder leak: 'null'")
        if not self.product.get("product_url") and URL_RE.search(body):
            # training-invite/outreach without URL must not invent links.
            # Exception: github-invite with an http(s) invite_repo may quote it once.
            invite_url = (self.product.get("invite_repo") or "").strip().startswith("http")
            if self.scenario != "outreach" or not self.has_product:
                if not (self.scenario == "github-invite" and invite_url):
                    raise ValueError("invented URL with none provided")
        if self.scenario == "networking" and PITCH_RE.search(body):
            raise ValueError("product pitch in networking mode")
        if len(subject) > EMAIL_SUBJECT_CAP:
            raise ValueError("subject too long")
        if len(body.split()) > EMAIL_BODY_WORD_CAP:
            raise ValueError("body too long")

    # -- transparent template fallback -----------------------------------
    def template(self, profile: dict) -> tuple[str, str]:
        name = profile.get("Name", "")
        position = profile.get("Current_Position", "")
        company = profile.get("Company", "")
        industry = profile.get("Industry", "")
        hook, pain = _hook_for(
            "" if is_placeholder(position) else str(position),
            "" if is_placeholder(industry) else str(industry))
        first = (str(name).split()[0] if not is_placeholder(name)
                 and str(name).split() else "")
        greeting = f"Hi {first}," if first else "Hi there,"
        sender = self.product.get("sender_name", "")
        signoff = f"Best,\n{sender}" if sender else "Best regards,"
        gh = profile.get("Verified_GitHub", "")
        proof = (f" I came across your GitHub (@{gh}) — solid public work."
                 if gh and not is_placeholder(gh) else "")

        if not is_placeholder(position) and not is_placeholder(company):
            ice = (f"Your work as {position} at {company} caught my eye"
                   + (f" — especially on the {hook} side." if hook else "."))
            subject = (f"Quick idea for {company}" if self.scenario == "outreach"
                       and self.has_product else f"Your work at {company}")
        elif not is_placeholder(position):
            ice = (f"Your background in {position} caught my eye"
                   + (f" — especially on the {hook} side." if hook else "."))
            subject = ("A quick idea worth 2 minutes?"
                       if self.scenario == "outreach" and self.has_product
                       else "Quick hello and request to connect")
        elif not is_placeholder(company):
            ice = f"I've been following the team at {company}."
            subject = (f"Quick idea for {company}"
                       if self.scenario == "outreach" and self.has_product
                       else f"Your work at {company}")
        else:
            ice = "I've been researching strong teams lately, and your profile stood out."
            subject = ("A quick idea worth 2 minutes?"
                       if self.scenario == "outreach" and self.has_product
                       else "Quick hello and request to connect")

        if self.scenario == "training-invite":
            who = sender or "our security awareness team"
            subject = f"Invite: security awareness session at {company}" \
                if not is_placeholder(company) else "Invite: security awareness session"
            body = (f"{greeting}\n\n{ice}{proof}\n\nI'm {who}, and we're running "
                    f"an optional security-awareness session (spotting phishing, "
                    f"safe reporting). {self.scenario_note + ' ' if self.scenario_note else ''}"
                    f"Would you be interested in joining or receiving the materials?\n\n"
                    f"Just reply and I'll share details — no action needed otherwise.\n\n{signoff}")
            return subject, body

        invite = (self.product.get("invite_repo") or "").strip().rstrip("/")
        if self.scenario == "github-invite" and invite:
            subject = ("Private repo invite — quick accept?" if invite.startswith("http")
                       else f"Private repo invite: {invite}")
            handle_bit = (f"your GitHub account (@{gh})"
                          if gh and not is_placeholder(gh) else "your GitHub account")
            detail = f" {self.scenario_note}" if self.scenario_note else ""
            body = (
                f"{greeting}\n\n"
                f"{ice}{proof}\n\n"
                f"I'm {sender or 'a fellow developer'}, and I'd value your evaluation of my work.{detail}\n\n"
                f"I've added {handle_bit} as a collaborator on {invite} — "
                f"it's a private project, so you'll need to accept the invitation "
                f"and be logged in to browse the code.\n\n"
                f"Could you accept the invite when you get a moment? "
                f"Happy to walk you through it afterwards — no rush at all.\n\n"
                f"{signoff}"
            )
            return subject, body

        if self.scenario == "outreach" and self.has_product:
            middle = (f"Most {hook} teams I talk to struggle with {pain}. "
                      if pain else "Most teams I talk to struggle with doing more with less time. ")
            sentence = (f"We built {self.product['product_name']} — "
                        f"{self.product['product_desc']}.")
            sc = self.product.get("product_scenario", "").rstrip()
            if sc:
                if sc[-1:] not in (".", "!", "?"):
                    sc += "."
                sentence += f" {sc}"
            if self.product.get("product_benefit"):
                sentence += f" It {self.product['product_benefit']}."
            if self.product.get("product_url"):
                sentence += f" You can take a quick look here: {self.product['product_url']}."
            middle += sentence
            cta = "Would you be open to a 15-minute look next week to see if it fits your stack?"
        else:
            middle = (f"I'm building connections with people doing great work in {hook}, "
                      f"and I'd love to stay in touch and follow your work."
                      if hook else "I'd love to stay in touch and follow your work.")
            cta = "Would you be open to connecting here?"
        return subject, f"{greeting}\n\n{ice}{proof}\n\n{middle}\n\n{cta}\n\n{signoff}"

    # -- LLM path ---------------------------------------------------------
    def _endpoint(self) -> Optional[tuple[str, str, str, str]]:
        gk = os.environ.get("GROQ_API_KEY", "").strip()
        if gk:
            model = os.environ.get("GROQ_MODEL",
                                   "llama-3.3-70b-versatile").strip()
            return ("https://api.groq.com/openai/v1/chat/completions",
                    gk, model, f"llm:groq/{model}")
        ok = os.environ.get("OPENAI_API_KEY", "").strip()
        if ok:
            model = os.environ.get("OPENAI_MODEL", "gpt-4o-mini").strip()
            return ("https://api.openai.com/v1/chat/completions",
                    ok, model, f"llm:openai/{model}")
        return None

    def _live_groq_models(self) -> list[str]:
        try:
            r = http_session().get(
                "https://api.groq.com/openai/v1/models",
                headers={"Authorization":
                         f"Bearer {os.environ.get('GROQ_API_KEY', '')}"},
                timeout=20)
            if r.status_code != 200:
                return []
            return [m.get("id", "") for m in r.json().get("data", [])
                    if m.get("id")]
        except Exception as e:
            logger.debug("Groq /models failed: %s", e)
            return []

    def _post(self, url: str, key: str, model: str,
              user_msg: dict) -> tuple[bool, str]:
        try:
            r = http_session().post(
                url, headers={"Authorization": f"Bearer {key}"},
                json={"model": model, "temperature": 0.7, "max_tokens": 400,
                      "messages": [{"role": "system", "content": _LLM_SYSTEM},
                                   {"role": "user",
                                    "content": json.dumps(user_msg)}]},
                timeout=self.llm_timeout)
        except Exception as e:
            return False, f"request failed: {e}"
        if r.status_code != 200:
            try:
                detail = (r.json().get("error") or {}).get("message", "") or r.text[:300]
            except Exception:
                detail = r.text[:300]
            return False, f"HTTP {r.status_code}: {detail}"
        try:
            content = ((r.json().get("choices") or [{}])[0].get("message")
                       or {}).get("content", "")
        except Exception as e:
            return False, f"bad response JSON: {e}"
        return True, content

    def _from_llm(self, profile: dict) -> Optional[tuple[str, str, str]]:
        ep = self._endpoint()
        if not ep:
            return None
        url, key, model, label = ep
        clean = {k: ("" if is_placeholder(v) else v)
                 for k, v in profile.items()
                 if k in ("Name", "Current_Position", "Company", "Industry",
                          "Verified_GitHub")}
        user_msg = {"verified_prospect": clean,
                    "scenario": self.scenario,
                    "scenario_note": self.scenario_note,
                    "product": self.product}
        ok, content = self._post(url, key, model, user_msg)
        if not ok:
            if ("groq" in url and ("404" in content or "400" in content)
                    and "model" in content.lower()):
                live = self._live_groq_models()
                fb = next((c for c in _GROQ_PREFERENCE
                           if c != model and c in live), None)
                if not fb:
                    fb = next((m for m in live
                               if m != model and not any(
                                   h in m.lower() for h in _SKIP_HINTS)), None)
                if fb:
                    logger.info("Retrying with live model '%s'.", fb)
                    ok, content = self._post(url, key, fb, user_msg)
                    if ok:
                        label = f"llm:groq/{fb}"
            if not ok:
                logger.warning("LLM failed (%.200s) -> template", content)
                return None
        try:
            txt = re.sub(r"^```(?:json)?|```$", "", content.strip(),
                         flags=re.MULTILINE).strip()
            parsed = json.loads(txt)
            subject, body = _text(parsed.get("subject")), _text(parsed.get("body"))
            if not subject or not body:
                raise ValueError("empty subject/body")
            self._validate(subject, body)
            return subject, body, label
        except (ValueError, AttributeError) as e:
            logger.warning("LLM output rejected (%s) -> template", e)
            return None

    def generate(self, profile: dict) -> tuple[str, str, str]:
        if self.use_llm:
            try:
                res = self._from_llm(profile)
                if res:
                    return res
            except Exception as e:
                logger.warning("LLM crashed (%s) -> template", e)
        try:
            subject, body = self.template(profile)
            self._validate(subject, body)
            return subject, body, "template"
        except ValueError as e:
            logger.error("Template invalid (%s) -> safe static", e)
            return self.SAFE_SUBJECT, self.SAFE_BODY, "safe-static"


# ---------------------------------------------------------------------------
# 8. Output hygiene — zero placeholder pollution
# ---------------------------------------------------------------------------

def prune_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Drop all-placeholder columns; blank remaining placeholders.

    A column is dropped when EVERY value is empty / 'Not Found'-like /
    'Not run' / 'Not Selected'. Surviving cells holding those markers are
    written as "" so the Excel contains zero placeholder text (except the
    intentional 'Not Selected' marker is also blanked for pristine output —
    selection state is implicit by row presence... kept here as blank too).
    """
    drop_markers = {m.lower() for m in
                    (list(EMPTY_TOKENS) + [NOT_RUN.lower(),
                                           NOT_SELECTED.lower(), NO_HANDLE.lower()])}
    keep: list[str] = []
    for col in df.columns:
        vals = df[col].tolist()
        if not vals:
            continue
        all_empty = True
        for v in vals:
            if isinstance(v, (int, float)) and not pd.isna(v):
                if not (isinstance(v, float) and v == 0.0 and col == "Years_Experience"):
                    all_empty = False
                    break
                # Years_Experience == 0.0 counts as real data (junior).
                all_empty = False
                break
            s = "" if v is None or (isinstance(v, float) and pd.isna(v)) else str(v).strip()
            if s and s.lower() not in drop_markers and "not available" not in s.lower():
                all_empty = False
                break
        if not all_empty:
            keep.append(col)
    df = df[keep] if keep else df.iloc[:, 0:0]
    for col in df.columns:
        if col == "Years_Experience":
            continue
        df[col] = df[col].apply(
            lambda v: "" if v is None or (isinstance(v, float) and pd.isna(v))
            or str(v).strip().lower() in drop_markers
            or "not available (no explicit handle" in str(v).lower() else v)
    # Re-blank any column that became entirely empty after mapping.
    df = df.dropna(axis=1, how="all")
    df = df.loc[:, [c for c in df.columns
                    if not (df[c].astype(str).str.strip() == "").all()]]
    ordered = [c for c in COLUMN_ORDER if c in df.columns]
    ordered += [c for c in df.columns if c not in ordered]
    return df.reindex(columns=ordered)


# ---------------------------------------------------------------------------
# 9. CLI
# ---------------------------------------------------------------------------

def _bounded_int(name: str, low: int, high: int) -> Callable[[str], int]:
    def convert(raw: str) -> int:
        try:
            v = int(raw)
        except (TypeError, ValueError):
            raise argparse.ArgumentTypeError(f"--{name} must be an integer")
        if not low <= v <= high:
            raise argparse.ArgumentTypeError(
                f"--{name} must be within [{low},{high}]")
        return v
    return convert


def build_parser() -> argparse.ArgumentParser:
    summary = (
        "master_osint_pipeline.py — LinkedIn OSINT + legitimate outreach in one run.\n"
        "WHAT IT DOES:\n"
        "  Phase 1 (Recon): reads LinkedIn URLs from Excel, fetches profiles\n"
        "    (RapidAPI, cache-first), parses Name/Position/Company/Experience/\n"
        "    Skills/Education/Email (strict, no guessing) + verifies GitHub.\n"
        "  Phase 2 (Review): shows a roster, lets you drop/edit rows and pick\n"
        "    a transparent scenario (networking / outreach / training-invite).\n"
        "  Phase 3 (Generate): optional Sherlock/WhoCord/Tookie scans for the\n"
        "    selected rows, then writes a personalized message per row\n"
        "    (Groq/OpenAI -> template fallback) into one clean Excel file\n"
        "    with zero placeholder pollution.\n"
        "QUICK START:\n"
        '  python master_osint_pipeline.py --input EXAMPLES.xlsx --output results.xlsx\n'
        '  python master_osint_pipeline.py --input in.xlsx --list\n'
        '  python master_osint_pipeline.py --input in.xlsx --output out.xlsx --no-interactive --scenario networking --sender "Mohamed" --no-llm'
    )
    ap = argparse.ArgumentParser(
        description=summary,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", default="EXAMPLES.xlsx",
                    help="Input Excel with LinkedIn URLs. Ex: --input EXAMPLES.xlsx")
    ap.add_argument("--output", default="master_osint_results.xlsx",
                    help="Output Excel file. Ex: --output results.xlsx")
    ap.add_argument("--workers", type=_bounded_int("workers", 1, MAX_WORKERS),
                    default=5,
                    help="Parallel threads 1-16. Ex: --workers 3")
    ap.add_argument("--email-threshold", type=float, default=0.8,
                    help="Min email confidence 0.0-1.0. Ex: --email-threshold 0.8")
    ap.add_argument("--verbose", action="store_true",
                    help="DEBUG logging. Ex: --verbose")
    ap.add_argument("--list", action="store_true",
                    help="Phase 1 only: fetch, print roster, exit. Ex: --input in.xlsx --list")
    ap.add_argument("--select", default="",
                    help='Rows to generate: 1-based indices or name parts. Ex: --select "1,3"  Ex: --select "omar,moaz"  (empty = all)')
    ap.add_argument("--interactive", dest="interactive", action="store_true",
                    default=True,
                    help="Review/edit rows before generation (default ON). Ex: --interactive")
    ap.add_argument("--no-interactive", dest="interactive",
                    action="store_false",
                    help="Disable prompts for automation. Ex: --no-interactive --scenario networking")
    ap.add_argument("--scenario", default="",
                    choices=[""] + list(SCENARIOS),
                    help="Message scenario: networking | outreach | training-invite. Ex: --scenario training-invite")
    ap.add_argument("--scenario-note", default="",
                    help='One-line factual context. Ex: --scenario-note "came across public DevOps work"')
    ap.add_argument("--name", default="",
                    help='Product name (outreach only). Ex: --name "SentinelX"')
    ap.add_argument("--desc", default="",
                    help='Product description. Ex: --desc "AI triage for SOC alert queues"')
    ap.add_argument("--scenario-product", default="",
                    help='Use-case story woven into hook. Ex: --scenario-product "plugs into Sentinel in 10 minutes"')
    ap.add_argument("--benefit", default="",
                    help='Product benefit. Ex: --benefit "cuts triage time by 60%%"')
    ap.add_argument("--url", default="",
                    help='Product URL (else NO links). Ex: --url "https://example.com"')
    ap.add_argument("--sender", default="",
                    help='Signature name. Ex: --sender "Mohamed"')
    ap.add_argument("--invite", default="",
                    help='GitHub private-repo invite mode: owner/repo or full URL. Ex: --invite "myorg/my-project"')
    ap.add_argument("--no-llm", action="store_true",
                    help="Skip LLM, use templates directly. Ex: --no-llm")
    ap.add_argument("--handle-column", default="",
                    help='Explicit handle column name. Ex: --handle-column "GitHub_Username"')
    ap.add_argument("--use-sherlock", action="store_true",
                    help="Enable Sherlock scan (needs handle). Ex: --use-sherlock --sherlock-sites GitHub,GitLab")
    ap.add_argument("--sherlock-sites", default="",
                    help='Subset of sites for speed. Ex: --sherlock-sites "GitHub,GitLab"')
    ap.add_argument("--sherlock-timeout",
                    type=_bounded_int("sherlock-timeout", MIN_TIMEOUT, MAX_TIMEOUT),
                    default=300,
                    help="Seconds per Sherlock scan. Ex: --sherlock-timeout 300")
    ap.add_argument("--use-whocord", action="store_true",
                    help="Enable WhoCord scan (SLOW, 10+ min/handle). Ex: --use-whocord --select \"2\"")
    ap.add_argument("--whocord-timeout",
                    type=_bounded_int("whocord-timeout", MIN_TIMEOUT, MAX_TIMEOUT),
                    default=1200,
                    help="Seconds per WhoCord scan. Ex: --whocord-timeout 1200")
    ap.add_argument("--use-tookie", action="store_true",
                    help="Enable TookieOSINT scan. Ex: --use-tookie")
    ap.add_argument("--tookie-timeout",
                    type=_bounded_int("tookie-timeout", MIN_TIMEOUT, MAX_TIMEOUT),
                    default=600,
                    help="Seconds per Tookie scan. Ex: --tookie-timeout 600")
    ap.add_argument("--tookie-threads",
                    type=_bounded_int("tookie-threads", 1, 50), default=10,
                    help="Tookie threads 1-50. Ex: --tookie-threads 10")
    ap.add_argument("--check-tools", action="store_true",
                    help="Diagnose keys/tools then exit. Ex: --check-tools")
    return ap


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S", force=True)

    if args.check_tools:
        for k, v in check_tools().items():
            print(f"{k}: {v}")
        return 0
    if not 0.0 <= args.email_threshold <= 1.0:
        logger.error("--email-threshold must be within [0.0, 1.0].")
        return 2
    if not Path(args.input).is_file():
        logger.error("Input file not found: %s", args.input)
        return 2

    gk, ok_ = (os.environ.get("GROQ_API_KEY", "").strip(),
               os.environ.get("OPENAI_API_KEY", "").strip())
    logger.info("LLM path: %s", "enabled" if (gk or ok_) and not args.no_llm
                else "template-only (no key or --no-llm)")

    ensure_table("CREATE TABLE IF NOT EXISTS profile_cache "
                 "(url TEXT PRIMARY KEY, data TEXT, ts REAL)")
    ensure_table("CREATE TABLE IF NOT EXISTS github_cache "
                 "(url TEXT PRIMARY KEY, data TEXT, ts REAL)")
    try:
        df = pd.read_excel(args.input)
    except Exception as e:
        logger.error("Cannot read %s: %s", args.input, e)
        return 2
    colmap = _colmap(list(df.columns))
    link_col = find_col(colmap, LINKEDIN_COLUMNS)
    if not link_col:
        logger.error("No LinkedIn column found. Need one of %s.",
                     LINKEDIN_COLUMNS)
        return 2

    rows = list(df.iterrows())
    hmap = {str(c).strip().lower(): str(c) for c in df.columns}
    gh_col = args.handle_column or next(
        (hmap[k] for k in HANDLE_COLUMNS if k in hmap), None)
    if args.handle_column and args.handle_column not in df.columns:
        logger.error("Handle column '%s' not in input.", args.handle_column)
        return 2
    handles = ([parse_explicit_handle(v) for v in df[gh_col].tolist()]
               if gh_col else [""] * len(rows))
    if (args.use_sherlock or args.use_whocord or args.use_tookie) and not gh_col:
        logger.warning("Tools enabled but no handle column — tool columns "
                       "will be 'Not Available'. Add 'GitHub_Username'.")

    # ---- Phase 1: recon everyone ----
    client = LinkedInClient()
    fetched: list[dict] = [{}] * len(rows)
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(_safe_fetch, client, i, len(rows),
                          _cell(row, link_col),
                          args.email_threshold): i
                for i, (_, row) in enumerate(rows)}
        for fut in as_completed(futs):
            try:
                fetched[futs[fut]] = fut.result()
            except Exception as e:
                logger.error("Row %d crashed: %s", futs[fut], e)
                fetched[futs[fut]] = _safe_fetch.__wrapped__ \
                    if hasattr(_safe_fetch, "__wrapped__") else {}
    fetched = [r for r in fetched if r]
    if args.list:
        print_roster(fetched)
        return 0

    # Verify explicit GitHub handles (cheap, always when column exists).
    verified: list[tuple[str, str]] = []
    if gh_col:
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            verified = list(ex.map(verify_github, handles))
    else:
        verified = [(NOT_FOUND, NOT_FOUND)] * len(fetched)
    for r, (h, u) in zip(fetched, verified):
        r["Verified_GitHub"] = h
        r["Verified_GitHub_URL"] = u

    # ---- Phase 2: review + scenario ----
    fetched = interactive_review(fetched, argparse.Namespace(
        **{"no_interactive": not args.interactive}))
    scenario, note = choose_scenario(argparse.Namespace(
        scenario=args.scenario, scenario_note=args.scenario_note,
        no_interactive=not args.interactive))
    if scenario == "outreach" and not (args.name.strip() and args.desc.strip()):
        logger.warning("--scenario outreach without --name/--desc: rows will "
                       "fall back to networking-style copy (no invented product).")
        scenario = "networking"
    if args.invite.strip() and scenario != "github-invite":
        logger.info("--invite given: switching scenario to github-invite.")
        scenario = "github-invite"
    if scenario == "github-invite" and not args.invite.strip():
        logger.error("--scenario github-invite needs --invite owner/repo (or URL).")
        return 2
    product = {"product_name": args.name, "product_desc": args.desc,
               "product_scenario": args.scenario_product,
               "product_benefit": args.benefit, "product_url": args.url,
               "sender_name": args.sender, "invite_repo": args.invite.strip()}
    generator = EmailGenerator(product, scenario=scenario, scenario_note=note,
                               use_llm=not args.no_llm)
    logger.info("Scenario: %s%s", scenario,
                f" (note: {note})" if note else "")

    # ---- Phase 3: tools + generation for selected ----
    selected = resolve_selection(args.select, fetched)
    logger.info("Selected %d/%d for generation.", len(selected), len(fetched))
    sherlock_sites = [s.strip() for s in (args.sherlock_sites or "").split(",")
                      if s.strip()]

    def _phase3(i: int) -> dict:
        r = {k: v for k, v in fetched[i].items()}
        h = handles[i] if i < len(handles) else ""
        tools_on = args.use_sherlock or args.use_whocord or args.use_tookie
        if i in selected and tools_on and h and HANDLE_RE.match(h):
            cols: dict = {}
            if args.use_sherlock:
                cols.update(run_sherlock(h, sites=sherlock_sites,
                                         timeout=args.sherlock_timeout))
            else:
                cols.update({"Sherlock_Status": NOT_RUN,
                             "Sherlock_Found_Links": NOT_FOUND})
            if args.use_whocord:
                cols.update(run_whocord(h, timeout=args.whocord_timeout))
            else:
                cols.update({"Whocord_Status": NOT_RUN,
                             "Whocord_Data": NOT_FOUND})
            if args.use_tookie:
                cols.update(run_tookie(h, timeout=args.tookie_timeout,
                                       threads=args.tookie_threads))
            else:
                cols.update({"Tookie_Status": NOT_RUN,
                             "Tookie_Results": NOT_FOUND})
            r.update(cols)
        else:
            r.update({"Sherlock_Status": NOT_RUN,
                      "Sherlock_Found_Links": NOT_FOUND,
                      "Whocord_Status": NOT_RUN, "Whocord_Data": NOT_FOUND,
                      "Tookie_Status": NOT_RUN, "Tookie_Results": NOT_FOUND})
        if i not in selected:
            r.update({"Scenario": scenario, "Email_Subject": NOT_SELECTED,
                      "Personalized_Email_Body": NOT_SELECTED,
                      "Email_Generator": "not-selected",
                      "Outreach_Context": NOT_FOUND})
            return r
        gh = r.get("Verified_GitHub", NOT_FOUND)
        ctx_bits = []
        if gh and not is_placeholder(gh):
            ctx_bits.append(f"verified GitHub @{gh}")
        r["Outreach_Context"] = ("; ".join(ctx_bits)
                                 if ctx_bits else "no external footprint")
        profile = {"Name": r.get("Name", ""), "Current_Position": r.get(
            "Current_Position", ""), "Company": r.get("Company", ""),
            "Industry": r.get("Industry", ""),
            "Verified_GitHub": r.get("Verified_GitHub", "")}
        try:
            subj, body, label = generator.generate(profile)
        except Exception as e:
            logger.error("Generation crashed (%s) -> safe static", e)
            subj, body, label = (EmailGenerator.SAFE_SUBJECT,
                                 EmailGenerator.SAFE_BODY, "safe-static")
        r.update({"Scenario": scenario, "Email_Subject": subj,
                  "Personalized_Email_Body": body, "Email_Generator": label})
        return r

    results: list[Optional[dict]] = [None] * len(fetched)
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(_phase3, i): i for i in range(len(fetched))}
        for fut in as_completed(futs):
            try:
                results[futs[fut]] = fut.result()
            except Exception as e:
                logger.error("Row %d crashed: %s", futs[fut], e)
    final_rows = [r for r in results if r]
    try:
        out_df = prune_dataframe(pd.DataFrame(final_rows))
        out_df.to_excel(args.output, index=False)
    except Exception as e:
        logger.error("Excel export failed: %s", e)
        return 1
    dropped = len(pd.DataFrame(final_rows).columns) - len(out_df.columns)
    logger.info("Saved %d rows -> %s (dropped %d all-empty columns)",
                len(final_rows), args.output, max(0, dropped))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
