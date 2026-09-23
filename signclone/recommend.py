#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
recommend.py — ترشيح افضل 3 قوالب من gophish_templates/ حسب بروفايل التارجت.
Inputs: spear report.json او profile يدوي. Output: جدول + JSON + prompt snippet للـ LLM.

Usage:
  py recommend.py --name "Ahmed Ali" --position "SOC Analyst" --company "Banque Misr" --email a@x.com
  py recommend.py --report-in report.json
  py recommend.py --profile profile.json --top 3 --json-out rec.json --prompt-out prompt.txt
"""
import argparse
import csv
import json
import re
from pathlib import Path

BASE = Path(__file__).parent
TPLS = BASE / "gophish_templates"
INDEX = TPLS / "index.csv"

JOB_KW = {"soc": "learn", "analyst": "learn", "pentest": "learn", "penetration": "learn",
    "security": "learn", "cyber": "learn", "dfir": "learn", "student": "learn", "iti": "learn",
    "nti": "learn", "depi": "learn", "intern": "job", "fresh": "job", "graduate": "job",
    "hr": "job", "recruit": "job", "sales": "job", "marketing": "job", "accountant": "finance",
    "finance": "finance", "bank": "finance", "teller": "finance", "hr ": "job"}
JOB_BRANDS = {"wuzzuf", "bayt", "linkedin", "hire", "talent", "career", "careers", "jobright",
    "naukrigulf", "forasna", "manatal", "successfactors", "icims", "recruitment", "taleez", "zety"}
FINANCE_BRANDS = {"banquemisr", "vodafone", "stripe", "taptapsend", "luno", "payments", "statement", "noon"}
LEARN_BRANDS = {"tryhackme", "hackthebox", "cybertalents", "letsdefend", "immersivelabs", "cyberdefenders",
    "rangeforce", "sans", "isc2", "eccouncil", "nti", "iti", "depi", "maharatech", "hackerrank", "udacity"}


def norm(s):
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def guess_category(position, company):
    text = f"{position} {company}".lower()
    scores = {"job": 0, "finance": 0, "learn": 0, "social": 0}
    for kw, cat in JOB_KW.items():
        if kw in text:
            scores[cat] += 10
    # كلمات مباشرة
    if any(w in text for w in ["soc", "pentest", "cyber", "security", "student", "trainee"]):
        scores["learn"] += 5
    if any(w in text for w in ["bank", "finance", "account"]):
        scores["finance"] += 5
    if any(w in text for w in ["seeking", "looking for job", "fresh grad"]):
        scores["job"] += 5
    best = max(scores, key=scores.get)
    return best if scores[best] > 0 else "generic"


def brand_category(brand):
    b = (brand or "").lower()
    if b in JOB_BRANDS:
        return "job"
    if b in FINANCE_BRANDS:
        return "finance"
    if b in LEARN_BRANDS:
        return "learn"
    return "generic"


def load_index():
    rows = []
    with open(INDEX, newline="", encoding="utf-8-sig") as f:
        for r in csv.DictReader(f):
            try:
                r["footer_chars"] = int(r.get("footer_chars") or 0)
            except ValueError:
                r["footer_chars"] = 0
            rows.append(r)
    return rows


def score_row(r, name, position, company, email, cat):
    s = 0
    reasons = []
    b = (r.get("brand") or "").lower()
    disp = (r.get("display") or "").lower()
    dom = (r.get("domain") or "").lower()
    # 1) الشركة مطابقة للبراند (اقوى اشارة spear) — لازم 3+ حروف عشان حرف واحد ميطابقش الكل
    cn = norm(company)
    matched = False
    for cand in {b, norm(disp)}:
        if len(cand) >= 3 and cand and (cand in cn or cn in cand):
            matched = True
    # مطابقة دومين: اول جزء من الدومين يظهر في اسم الشركة
    if not matched and dom:
        root = norm(dom.split(".")[0])
        if len(root) >= 4 and root in cn:
            matched = True
    if company and matched:
        s += 100
        reasons.append("company-match")
    # 2) نفس الكاتيجوري
    if brand_category(b) == cat:
        s += 50
        reasons.append(f"cat:{cat}")
    elif cat == "generic" and brand_category(b) == "generic":
        s += 20
    # 3) جودة الفوتر (موثوقية بصرية)
    s += min(r.get("footer_chars", 0) // 50, 10)
    # 4) دومين حقيقي قصير افضل من subdomain طويل
    if dom and dom.count(".") == 1:
        s += 5
    return s, reasons


def main():
    ap = argparse.ArgumentParser(description="Recommend templates for a spear target")
    ap.add_argument("--name", default="")
    ap.add_argument("--position", default="")
    ap.add_argument("--company", default="")
    ap.add_argument("--email", default="")
    ap.add_argument("--profile", default="", help="JSON فيه Name/Current_Position/Company/Email")
    ap.add_argument("--report-in", default="", help="report.json بتاع spear_enrich.py")
    ap.add_argument("--top", type=int, default=3)
    ap.add_argument("--json-out", default="")
    ap.add_argument("--prompt-out", default="")
    a = ap.parse_args()

    if a.report_in:
        rep = json.loads(Path(a.report_in).read_text(encoding="utf-8"))
        prof = rep.get("profile", rep.get("Profile", {}))
        name = prof.get("Name", "")
        position = prof.get("Current_Position", "") or rep.get("target", {}).get("position", "")
        company = prof.get("Company", "")
        email = prof.get("Email", "")
    elif a.profile:
        prof = json.loads(Path(a.profile).read_text(encoding="utf-8"))
        name = prof.get("Name", a.name)
        position = prof.get("Current_Position", prof.get("position", a.position))
        company = prof.get("Company", prof.get("company", a.company))
        email = prof.get("Email", prof.get("email", a.email))
    else:
        name, position, company, email = a.name, a.position, a.company, a.email

    cat = guess_category(position, company)
    rows = load_index()
    scored = []
    for r in rows:
        s, reasons = score_row(r, name, position, company, email, cat)
        scored.append((s, r.get("footer_chars", 0), r, reasons))
    scored.sort(key=lambda x: (x[0], x[1]), reverse=True)
    top = scored[: a.top]

    print(f"[*] Target: {name} | {position} at {company} | {email}")
    print(f"[*] Guessed category: {cat} | library: {len(rows)} templates")
    for i, (s, _, r, reasons) in enumerate(top, 1):
        print(f"  [{i}] {r['display']} ({r['domain']}) score={s} [{','.join(reasons)}]")
        print(f"      subject: {r['subject'][:70]}")
        print(f"      html: gophish_templates/{r['html_file']}")

    out = {"target": {"name": name, "position": position, "company": company,
                      "email": email, "category": cat},
           "recommendations": [
               {"rank": i, "score": s, "reasons": reasons,
                "brand": r["brand"], "display": r["display"], "domain": r["domain"],
                "color": r.get("color", ""), "logo": r.get("logo", ""),
                "subject": r["subject"], "envelope_sender": r["envelope_sender"],
                "html_file": f"gophish_templates/{r['html_file']}",
                "json_file": f"gophish_templates/{r['json_file']}"}
               for i, (s, _, r, reasons) in enumerate(top, 1)]}
    if a.json_out:
        Path(a.json_out).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[*] JSON -> {a.json_out}")

    # snippet جاهز يتحقن في برومبت الـ LLM عشان يطلع شبه الحقيقي
    prompt = (f"Target: {name} ({position} at {company}, email {email}). "
              f"Category: {cat}. Mimic these real senders (subject + footer style), "
              f"keep placeholder {{{{URL}}}} for the landing link:\n")
    for rec in out["recommendations"]:
        prompt += f"- {rec['display']} <{rec['envelope_sender']}> | subject: {rec['subject']}\n"
    if a.prompt_out:
        Path(a.prompt_out).write_text(prompt, encoding="utf-8")
        print(f"[*] Prompt -> {a.prompt_out}")
    else:
        print("[*] Prompt snippet:")
        print(prompt)


if __name__ == "__main__":
    main()
