#!/usr/bin/env python3
"""spear_enrich.py — single-target OSINT enrichment for Black Cat spear phishing.

Bridge between the LinkedIn OSINT pipeline (scraping/master_osint_pipeline.py)
and campaign creation: LinkedIn URL in, enriched profile + generated message
out as JSON.

  python tools/spear_enrich.py --linkedin <url> --out report.json
  python tools/spear_enrich.py --linkedin <url> --out report.json --channel sms
  python tools/spear_enrich.py --linkedin <url> --out report.json --prompt-file prompt.txt
  python tools/spear_enrich.py --linkedin <url> --out report.json --enrich-only
  python tools/spear_enrich.py --generate-only --report-in report.json \
      --out report.json --prompt-file edited_prompt.txt

Contract (consumed by the panel spear flow, same pattern as
tools/phishlet_harvester.py):
  * exit 0  — report.json written (profile may be sparse offline; the
              `notes` array always explains what happened).
  * exit 2  — usage error (bad LinkedIn URL, missing pipeline, bad args).
  * exit 1  — enrichment subprocess failed (report.json still written with
              an `err` field so the UI can show it).

Enrichment always runs the pipeline with --no-llm; message generation is done
here so the operator's (possibly edited) prompt is used verbatim:
  Groq (GROQ_API_KEY) -> OpenAI fallback (OPENAI_API_KEY) -> template fallback.

Authorized-use only: run enrichment solely against targets you are explicitly
authorized to process as part of a sanctioned engagement.
"""

from __future__ import annotations

import argparse
import csv
import datetime
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PIPELINE = REPO_ROOT / "scraping" / "master_osint_pipeline.py"
PIPELINE_CWD = REPO_ROOT / "scraping"

PROFILE_FIELDS = (
    "Name", "LinkedIn_URL", "Location", "Current_Position", "Company",
    "Industry", "Email", "Email_Confidence", "Email_Source",
)


def load_dotenv() -> None:
    """Mirror the pipeline's own .env loading (scraping/.env): KEY=value
    lines, quotes optional, # comments. Real environment always wins, so
    server env vars override the file. Secrets are never printed."""
    try:
        env_file = PIPELINE_CWD / ".env"
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


def fail(report_path: str | None, msg: str, code: int) -> int:
    if report_path:
        try:
            Path(report_path).write_text(
                json.dumps({"err": msg, "profile": {}, "notes": [msg]},
                           ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except OSError:
            pass
    print(f"spear_enrich: error: {msg}", file=sys.stderr)
    return code


def valid_linkedin(url: str) -> str:
    url = (url or "").strip()
    if not url or "linkedin.com" not in url.lower():
        return ""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


CACHE_DIR = REPO_ROOT / "tools" / ".spear_cache"
DEFAULT_CACHE_TTL_DAYS = 30


def cache_key(url: str) -> str:
    """Stable cache identity: normalized URL -> sha1 (query/fragment ignored)."""
    u = (url or "").strip().lower().split("?")[0].split("#")[0].rstrip("/")
    return hashlib.sha1(u.encode()).hexdigest()


def cache_load(url: str, ttl_days: int) -> tuple[dict | None, str]:
    """(profile, age_note) on a fresh hit, else (None, reason). Never raises."""
    try:
        p = CACHE_DIR / (cache_key(url) + ".json")
        if not p.is_file():
            return None, "miss"
        data = json.loads(p.read_text(encoding="utf-8"))
        if data.get("url_key") != cache_key(url):
            return None, "miss"
        try:
            age = (datetime.datetime.now(datetime.timezone.utc) -
                   datetime.datetime.fromisoformat(data["fetched_at"])).days
        except (KeyError, ValueError):
            return None, "miss"
        if age > ttl_days:
            return None, f"expired ({age}d > {ttl_days}d)"
        prof = data.get("profile") or {}
        if not isinstance(prof, dict):
            return None, "miss"
        when = data.get("fetched_at", "")[:10]
        return prof, f"cached {when} ({age}d ago)"
    except Exception:
        return None, "miss"


def cache_save(url: str, profile: dict) -> bool:
    """Persist a SUCCESSFUL profile only (never poison with empty/error data)."""
    try:
        name = (profile.get("Name") or "").strip()
        if not name or name.upper().startswith("ERROR"):
            return False
        if not isinstance(profile, dict):
            return False
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        (CACHE_DIR / (cache_key(url) + ".json")).write_text(json.dumps({
            "url_key": cache_key(url),
            "url": url,
            "fetched_at": datetime.datetime.now(
                datetime.timezone.utc).isoformat(),
            "profile": profile,
        }, ensure_ascii=False, indent=2), encoding="utf-8")
        return True
    except Exception:
        return False


def split_name(full: str) -> tuple[str, str]:
    full = (full or "").strip()
    if full.upper().startswith("ERROR"):
        return "", ""
    parts = full.split()
    if not parts:
        return "", ""
    if len(parts) == 1:
        return parts[0], ""
    return parts[0], " ".join(parts[1:])


def write_input_xlsx(url: str, path: Path) -> None:
    from openpyxl import Workbook

    wb = Workbook()
    try:
        ws = wb.active
        ws.title = "targets"
        ws.append(["LinkedIn_URL"])
        ws.append([url])
        wb.save(path)
    finally:
        wb.close()


def read_bytes_backoff(path: Path, attempts: int = 6,
                       first_delay: float = 0.5) -> bytes:
    """Read a freshly-written file with exponential backoff.

    Windows background agents (antivirus/indexer) briefly lock new files;
    plain byte reads plus increasing delays ride out those transient locks.
    """
    delay = first_delay
    last: OSError | None = None
    for _ in range(attempts):
        try:
            return path.read_bytes()
        except OSError as e:
            last = e
            time.sleep(delay)
            delay *= 2
    raise last if last else OSError(f"cannot read {path}")


def read_profile_retry(xlsx: Path) -> dict:
    """Parse the pipeline output workbook.

    Reads raw bytes first (plain reads are never the problem), then parses
    fully in memory so no file handle is ever held on the output path —
    this is immune to WinError 32 races on the file itself.
    """
    from openpyxl import load_workbook

    data = read_bytes_backoff(xlsx)
    wb = load_workbook(io.BytesIO(data), read_only=True, data_only=True)
    try:
        ws = wb.active
        rows = list(ws.iter_rows(values_only=True))
    finally:
        wb.close()
    if len(rows) < 2:
        return {}
    headers = [(c or "") for c in rows[0]]
    values = rows[1]
    row = {str(h): ("" if v is None else str(v)).strip()
           for h, v in zip(headers, values)}
    return {k: row.get(k, "") for k in PROFILE_FIELDS}


def read_profile(xlsx: Path) -> dict:
    return read_profile_retry(xlsx)


def library_hint(profile: dict, limit: int = 2) -> str:
    """Top-N real senders from signclone/gophish_templates/ matching the target.

    Best-effort only: returns "" when the library is missing so enrichment
    never breaks. Used to ground the LLM prompt in real subject/sender style.
    """
    try:
        idx = REPO_ROOT / "signclone" / "gophish_templates" / "index.csv"
        if not idx.is_file():
            return ""
        comp = (profile.get("Company") or "").lower()
        pos = (profile.get("Current_Position") or "").lower()
        cn = re.sub(r"[^a-z0-9]", "", comp)
        scored = []
        with open(idx, newline="", encoding="utf-8-sig") as f:
            for r in csv.DictReader(f):
                brand = (r.get("brand") or "").lower()
                disp = (r.get("display") or "").lower()
                dom = (r.get("domain") or "").lower()
                s = 0
                for cand in {brand, re.sub(r"[^a-z0-9]", "", disp)}:
                    if len(cand) >= 4 and cand and (cand in cn or cn in cand):
                        s += 100
                if dom:
                    root = re.sub(r"[^a-z0-9]", "", dom.split(".")[0])
                    if len(root) >= 4 and root in cn:
                        s += 100
                # light position boost so students get labs, job-seekers get jobs
                text = f"{pos} {comp}"
                cat = ""
                if any(w in text for w in ["soc", "pentest", "cyber", "secur", "student", "trainee", "iti", "nti"]):
                    cat = "learn"
                elif any(w in text for w in ["bank", "finance", "account"]):
                    cat = "finance"
                elif any(w in text for w in ["recruit", "seeking", "fresh grad", "hr "]):
                    cat = "job"
                try:
                    s += min(int(r.get("footer_chars") or 0) // 100, 5)
                except ValueError:
                    pass
                r["_score"] = s
                r["_cat"] = cat
                scored.append(r)
        scored.sort(key=lambda r: r["_score"], reverse=True)
        picks = [r for r in scored if r["_score"] >= 100][:limit]
        if not picks:
            picks = scored[:limit]
        lines = []
        for r in picks:
            lines.append(f"- {r.get('display')} <{r.get('envelope_sender')}> | subject: {r.get('subject')}")
        return "\n".join(lines)
    except Exception:
        return ""


def mail_category(profile: dict) -> str:
    """Human-readable industry category for the expert prompt header."""
    text = (f"{profile.get('Current_Position') or ''} "
            f"{profile.get('Company') or ''} "
            f"{profile.get('Industry') or ''}").lower()
    if any(w in text for w in ["soc", "threat", "pentest", "cyber", "dfir",
                               "secur", "malware", "forensic", "red team"]):
        return "Cybersecurity / Threat Operations"
    if any(w in text for w in ["bank", "finance", "account", "audit"]):
        return "Banking / Finance"
    if any(w in text for w in ["student", "intern", "trainee", "iti", "nti"]):
        return "Education / Early Careers"
    if any(w in text for w in ["recruit", "hr ", "human resources", "talent"]):
        return "Human Resources / Talent"
    if any(w in text for w in ["sale", "market", "account executive"]):
        return "Sales / Marketing"
    if any(w in text for w in ["engineer", "developer", "devops", "it ", "software"]):
        return "Technology / Engineering"
    return "General Corporate"


def default_prompt(profile: dict, channel: str, sender: str,
                   lang: str = "en") -> str:
    who = profile.get("Name") or "the target"
    pos = profile.get("Current_Position") or "their role"
    comp = profile.get("Company") or "their company"
    if channel == "sms":
        if lang == "ar":
            return (
                f"Write a short, professional SMS in Arabic (max 300 "
                f"characters, plain text, landing URL placeholder {{URL}}) "
                f"addressed to {who} ({pos} at {comp}). It is a legitimate, "
                f"clearly-identified security-awareness exercise message from "
                f"{sender or 'the security team'}. Plain wording, no urgency "
                f"threats, no credential requests. Output only the Arabic "
                f"SMS text, nothing else."
            )
        return (
            f"Write a short, professional SMS (max 300 characters, plain text, "
            f"no links shortened beyond the landing URL placeholder {{URL}}) "
            f"addressed to {who} ({pos} at {comp}). It is a legitimate, "
            f"clearly-identified security-awareness exercise message from "
            f"{sender or 'the security team'}. Plain wording, no urgency "
            f"threats, no credential requests. Output only the SMS text."
        )
    hint = library_hint(profile)
    if hint:
        lib = (f"\n\n### Context & Inspiration (Top matching templates from our library "
               f"to mimic their professional tone, subject structure, and formatting style):\n{hint}")
    else:
        lib = ("\n\n### Context & Inspiration:\nNo close library match — "
               "use a clean corporate security-awareness tone.")
    category = mail_category(profile)
    return (
        f"You are an expert Red Teamer and Social Engineering Simulation specialist "
        f"designing authorized, high-fidelity security awareness campaigns.\n"
        f"\n### Task:\nWrite a realistic, highly engaging phishing simulation email "
        f"tailored to the specific target profile and industry context provided below.\n"
        f"\n### Target Profile:\n- Name: {who}\n- Position: {pos}\n"
        f"- Company: {comp}\n- Industry Category: {category}\n"
        f"- Sender to sign off as: {sender or 'the security team'}"
        f"{lib}\n"
        f"\n### Strict Requirements:\n"
        f"1. Personalize the opening line and hook based on the recipient's exact role and company context.\n"
        f"2. Keep it professional, realistic, and strictly part of an authorized awareness test "
        f"(no malicious threats, no account lockouts, no urgent password demands).\n"
        f"3. You MUST include the exact landing page placeholder: {{{{URL}}}}\n"
        f"4. Output format must strictly follow this structure:\n"
        f"\nSUBJECT: <compelling, relevant subject line>\n\n"
        f"<professional email body with the {{{{URL}}}} link woven in naturally>"
    )


def template_result(profile: dict, channel: str, sender: str,
                    lang: str = "en") -> tuple[str, str]:
    if channel == "sms" and lang == "ar":
        first = (profile.get("Name") or "").split()
        first = first[0] if first else ""
        comp = profile.get("Company") or "مؤسستك"
        sender = sender or "فريق الأمن"
        greet = f"أهلاً {first}، " if first else "أهلاً، "
        body = (f"{greet}معاك {sender} في {comp}. ضمن برنامج التوعية "
                f"الأمنية المعتمد، من فضلك راجع الصفحة دي أول ما تقدر: "
                f"{{URL}} - للانسحاب ابعت STOP.")
        return "", body
    first = (profile.get("Name") or "there").split()[0]
    comp = profile.get("Company") or "your organization"
    sender = sender or "Security Team"
    if channel == "sms":
        body = (f"Hi {first}, this is {sender} at {comp}. As part of our "
                f"authorized security-awareness exercise, please review this "
                f"page when you have a moment: {{URL}} - reply STOP to opt out.")
        return "", body
    subject = f"{comp}: quick security-awareness check for {first}"
    body = (f"Hi {first},\n\nAs part of our authorized security-awareness "
            f"program at {comp}, please take a minute to review the following "
            f"page and confirm your details:\n\n{{URL}}\n\nThanks,\n{sender}")
    return subject, body


def call_llm(prompt: str, timeout: int) -> tuple[str, str, str]:
    """Returns (generator, subject, body). Raises RuntimeError when unusable."""
    groq_key = os.environ.get("GROQ_API_KEY", "").strip()
    openai_key = os.environ.get("OPENAI_API_KEY", "").strip()
    groq_model = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile").strip()
    openai_model = os.environ.get("OPENAI_MODEL", "gpt-4o-mini").strip()
    try:
        import requests
    except ImportError as e:
        raise RuntimeError(f"requests library missing: {e}")

    if groq_key:
        try:
            r = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {groq_key}"},
                json={"model": groq_model,
                      "messages": [{"role": "user", "content": prompt}],
                      "temperature": 0.7, "max_tokens": 800},
                timeout=timeout,
            )
            r.raise_for_status()
            return "groq", *split_subject(
                r.json()["choices"][0]["message"]["content"])
        except Exception as e:
            last = f"groq failed: {e}"
    else:
        last = "GROQ_API_KEY not set"
    if openai_key:
        try:
            r = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {openai_key}"},
                json={"model": openai_model,
                      "messages": [{"role": "user", "content": prompt}],
                      "temperature": 0.7, "max_tokens": 800},
                timeout=timeout,
            )
            r.raise_for_status()
            return "openai", *split_subject(
                r.json()["choices"][0]["message"]["content"])
        except Exception as e:
            last = f"{last}; openai failed: {e}"
    else:
        last = f"{last}; OPENAI_API_KEY not set"
    raise RuntimeError(last)


def split_subject(text: str) -> tuple[str, str]:
    lines = (text or "").strip().splitlines()
    if lines and lines[0].strip().upper().startswith("SUBJECT:"):
        return lines[0].split(":", 1)[1].strip(), "\n".join(lines[1:]).strip()
    return "", (text or "").strip()


def company_domain(company: str, timeout: int = 20) -> str:
    """Resolve a company name to its domain via Clearbit autocomplete.

    Free, no key needed. Returns "" when nothing sensible matches.
    """
    company = (company or "").strip()
    if not company:
        return ""
    try:
        import requests
    except ImportError:
        return ""
    try:
        r = requests.get(
            "https://autocomplete.clearbit.com/v1/companies/suggest",
            params={"query": company}, timeout=timeout)
        r.raise_for_status()
        items = r.json()
    except Exception:
        return ""
    if not items or not isinstance(items, list):
        return ""
    # Pick the candidate whose domain truly matches the company — the first
    # result is often a sibling brand (e.g. Office for Microsoft).
    stop = {"inc", "incorporated", "corp", "corporation", "ltd", "limited",
            "llc", "gmbh", "plc", "co", "company", "group", "technologies",
            "technology", "tech", "systems", "solutions", "services",
            "partners", "holdings", "international", "global"}
    core = [t for t in re.split(r"[^a-z0-9]+", company.lower())
            if t and t not in stop and len(t) > 2]
    if not core:
        return ""
    best, best_score = "", -1
    for item in items[:6]:
        if not isinstance(item, dict):
            continue
        domain = str(item.get("domain") or "").strip().lower()
        if not domain or "." not in domain:
            continue
        sld = domain.split(".")[0]
        if not sld:
            continue
        score = -1
        for tok in core:
            if tok == sld:
                score = max(score, 100 + len(tok))
            elif tok in sld or sld in tok:
                score = max(score, len(tok))
        if score > best_score:
            best, best_score = domain, score
    return best if best_score >= 0 else ""


def hunter_find_email(first: str, last: str, domain: str,
                      timeout: int = 20) -> tuple[str, str]:
    """Find a work email via Hunter.io Email Finder.

    Needs HUNTER_API_KEY (free tier: 25 lookups/month — plenty for 1:1
    spear targets). Returns (email, confidence) or ("", "").
    Raises RuntimeError with the provider message on hard failures.
    """
    key = os.environ.get("HUNTER_API_KEY", "").strip()
    if not key:
        raise RuntimeError("HUNTER_API_KEY not set")
    try:
        import requests
    except ImportError as e:
        raise RuntimeError(f"requests library missing: {e}")
    try:
        r = requests.get(
            "https://api.hunter.io/v2/email-finder",
            params={"domain": domain, "first_name": first,
                    "last_name": last, "api_key": key},
            timeout=timeout)
    except Exception as e:
        raise RuntimeError(f"hunter request failed: {e}")
    try:
        data = r.json()
    except Exception:
        raise RuntimeError(f"hunter HTTP {r.status_code}")
    if r.status_code == 401:
        raise RuntimeError("hunter rejected the API key (401)")
    if r.status_code == 429:
        raise RuntimeError("hunter monthly quota exhausted (429)")
    if r.status_code != 200:
        err = ""
        try:
            errs = data.get("errors") or []
            if errs and isinstance(errs[0], dict):
                err = str(errs[0].get("details") or "")
        except Exception:
            pass
        raise RuntimeError(f"hunter HTTP {r.status_code} {err}".strip())
    payload = data.get("data") or {}
    email = str(payload.get("email") or "").strip()
    score = payload.get("score")
    try:
        confidence = str(int(score))
    except (TypeError, ValueError):
        confidence = ""
    return email, confidence


def maybe_autofill_email(profile: dict, notes: list) -> None:
    """Fill a missing email from Name + Company via Clearbit + Hunter.

    Runs only when the email is blank but name and company exist. Never
    overwrites a captured email. All outcomes land in notes.
    """
    if (profile.get("Email") or "").strip():
        return
    first, last = split_name(profile.get("Name", ""))
    company = (profile.get("Company") or "").strip()
    if not first or not last or not company:
        notes.append("Email auto-find skipped (need name + company).")
        return
    domain = company_domain(company)
    if not domain:
        notes.append(f"Email auto-find skipped (no domain found for {company}).")
        return
    try:
        email, confidence = hunter_find_email(first, last, domain)
    except RuntimeError as e:
        notes.append(f"Email auto-find failed: {e}.")
        return
    if not email:
        notes.append(f"Email auto-find found nothing at {domain}.")
        return
    profile["Email"] = email
    profile["Email_Confidence"] = confidence
    profile["Email_Source"] = f"hunter ({domain})"
    msg = f"Email auto-filled from Hunter ({domain})"
    if confidence:
        msg += f", confidence {confidence}"
        try:
            if int(confidence) < 50:
                msg += " — low, verify before launching"
        except ValueError:
            pass
    notes.append(msg + ".")


def load_custom_prompt(args) -> str:
    if args.prompt_file:
        try:
            return Path(args.prompt_file).read_text(
                encoding="utf-8").strip()
        except OSError as e:
            raise ValueError(f"Cannot read prompt file: {e}")
    return (args.prompt or "").strip()


def generate_message(profile: dict, channel: str, sender: str, custom: str,
                     no_llm: bool, timeout: int, lang: str,
                     notes: list) -> tuple[str, str, str]:
    """Returns (generator, subject, body) for the (possibly edited) prompt."""
    prompt_default = default_prompt(profile, channel, sender, lang)
    prompt_used = custom or prompt_default
    generator = "template"
    if no_llm:
        notes.append("--no-llm: template used without calling any model.")
        subject, body = template_result(profile, channel, sender, lang)
    else:
        try:
            generator, subject, body = call_llm(prompt_used,
                                                min(timeout, 120))
        except RuntimeError as e:
            notes.append(f"LLM unavailable ({e}) — template fallback used.")
            subject, body = template_result(profile, channel, sender, lang)
    if not body.strip():
        notes.append("Empty model output — template fallback used.")
        generator = "template"
        subject, body = template_result(profile, channel, sender, lang)
    return generator, subject, body, prompt_default, prompt_used


def build_target(profile: dict) -> dict:
    first, last = split_name(profile.get("Name", ""))
    position = profile.get("Current_Position", "")
    if profile.get("Company"):
        position = f"{position} at {profile['Company']}".strip(" at")
    return {"first_name": first, "last_name": last,
            "email": profile.get("Email", ""), "position": position}


def write_report(out: str, report: dict) -> None:
    Path(out).write_text(json.dumps(report, ensure_ascii=False, indent=2),
                         encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Enrich one LinkedIn target.")
    ap.add_argument("--linkedin", default="",
                    help="Target LinkedIn URL (required unless --generate-only)")
    ap.add_argument("--out", required=True, help="Report JSON path")
    ap.add_argument("--pipeline", default=str(DEFAULT_PIPELINE))
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("--channel", choices=("mail", "sms"), default=None)
    ap.add_argument("--lang", choices=("ar", "en"), default=None,
                    help="Message language (SMS shows an Arabic/English picker)")
    ap.add_argument("--sender", default="")
    ap.add_argument("--prompt", default="",
                    help="Operator-edited prompt (overrides the default)")
    ap.add_argument("--prompt-file", default="")
    ap.add_argument("--no-llm", action="store_true",
                    help="Skip LLM, use the template directly")
    ap.add_argument("--enrich-only", action="store_true",
                    help="Run enrichment only; leave subject/body empty")
    ap.add_argument("--generate-only", action="store_true",
                    help="Skip enrichment; generate from --report-in")
    ap.add_argument("--report-in", default="",
                    help="Input report for --generate-only")
    ap.add_argument("--refresh", action="store_true",
                    help="Ignore the local profile cache and re-fetch (consumes quota)")
    ap.add_argument("--cache-ttl-days", type=int, default=DEFAULT_CACHE_TTL_DAYS,
                    help="Local cache freshness in days (default %(default)s)")
    args = ap.parse_args(argv)
    load_dotenv()

    try:
        custom = load_custom_prompt(args)
    except ValueError as e:
        return fail(args.out, str(e), 2)
    pipeline = Path(args.pipeline)
    if not pipeline.is_file():
        return fail(args.out, f"Pipeline not found: {pipeline}", 2)

    # ---- generate-only: no pipeline run, profile comes from the report ----
    if args.generate_only:
        if not args.report_in:
            return fail(args.out, "--generate-only needs --report-in.", 2)
        try:
            report = json.loads(Path(args.report_in).read_text(
                encoding="utf-8"))
        except (OSError, ValueError) as e:
            return fail(args.out, f"Cannot read report: {e}", 2)
        profile = report.get("profile", {})
        channel = args.channel or report.get("channel", "mail")
        lang = args.lang or report.get("lang", "en")
        sender = args.sender or ""
        notes = report.get("notes", [])
        maybe_autofill_email(profile, notes)
        report["profile"] = profile
        report["target"] = build_target(profile)
        generator, subject, body, prompt_default, prompt_used = \
            generate_message(profile, channel, sender, custom,
                             args.no_llm, args.timeout, lang, notes)
        report.update({"channel": channel, "lang": lang,
                       "prompt_default": prompt_default,
                       "prompt_used": prompt_used,
                       "custom_prompt": bool(custom), "subject": subject,
                       "body": body, "generator": generator, "notes": notes})
        report.pop("err", None)
        try:
            write_report(args.out, report)
        except OSError as e:
            return fail(None, f"Cannot write report: {e}", 1)
        print(f"spear_enrich: ok (generator={generator})")
        return 0

    # ---- enrich (+ optional generate) ----
    url = valid_linkedin(args.linkedin)
    if not url:
        return fail(args.out, "Provide a valid LinkedIn profile URL.", 2)
    channel = args.channel or "mail"
    lang = args.lang or "en"

    notes: list[str] = []
    profile: dict = {}
    cache_hit = False
    if not args.refresh:
        cached, age_note = cache_load(url, args.cache_ttl_days)
        if cached is not None:
            profile = cached
            cache_hit = True
            notes.append(
                f"Profile loaded from local cache ({age_note}) — no quota "
                f"consumed. Re-run with --refresh for a live lookup.")
    if not cache_hit:
        try:
            with tempfile.TemporaryDirectory(prefix="spear_") as tmp:
                tmpdir = Path(tmp)
                in_xlsx = tmpdir / "in.xlsx"
                enriched = tmpdir / "enriched.xlsx"
                write_input_xlsx(url, in_xlsx)
                cmd = [sys.executable, str(pipeline), "--input", str(in_xlsx),
                       "--output", str(enriched), "--no-interactive", "--no-llm"]
                try:
                    proc = subprocess.run(
                        cmd, cwd=str(PIPELINE_CWD), capture_output=True,
                        text=True, timeout=args.timeout)
                except subprocess.TimeoutExpired:
                    return fail(args.out,
                                f"Enrichment timed out after {args.timeout}s.", 1)
                if proc.returncode != 0 or not enriched.is_file():
                    tail = (proc.stderr or proc.stdout or "")[-2000:]
                    return fail(args.out, f"Enrichment failed: {tail.strip()}", 1)
                profile = read_profile_retry(enriched)
        except Exception as e:
            return fail(args.out, f"Enrichment crashed: {e}", 1)
        if cache_save(url, profile):
            notes.append("Profile saved to local cache for reuse.")

    raw_name = profile.get("Name", "")
    if raw_name.upper().startswith("ERROR"):
        # The provider answered with an error payload (e.g. bad key/quota);
        # never let it masquerade as the target's name.
        profile["Name"] = ""
        notes.append(f"Profile fetch failed against the provider ({raw_name}) — "
                     "check the RAPIDAPI key, host and quota; fields left "
                     "blank for manual review.")
    elif not raw_name:
        notes.append("Live profile fetch unavailable (no API key/cache) — "
                     "fields left blank for manual review.")
    profile["LinkedIn_URL"] = profile.get("LinkedIn_URL") or url
    maybe_autofill_email(profile, notes)
    target = build_target(profile)

    if args.enrich_only:
        notes.append("Enrichment only — generate the message next.")
        report = {"linkedin": url, "profile": profile, "target": target,
                  "channel": channel, "lang": lang,
                  "prompt_default": default_prompt(profile, channel,
                                                   args.sender, lang),
                  "prompt_used": "", "custom_prompt": False, "subject": "",
                  "body": "", "generator": "none", "notes": notes}
    else:
        generator, subject, body, prompt_default, prompt_used = \
            generate_message(profile, channel, args.sender, custom,
                             args.no_llm, args.timeout, lang, notes)
        report = {"linkedin": url, "profile": profile, "target": target,
                  "channel": channel, "lang": lang,
                  "prompt_default": prompt_default,
                  "prompt_used": prompt_used,
                  "custom_prompt": bool(custom), "subject": subject,
                  "body": body, "generator": generator, "notes": notes}
    try:
        write_report(args.out, report)
    except OSError as e:
        return fail(None, f"Cannot write report: {e}", 1)
    print(f"spear_enrich: ok (generator={report['generator']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
