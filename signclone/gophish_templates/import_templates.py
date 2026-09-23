#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""رفع القوالب ل GoPhish عبر API.
الاستخدام:
  py import_templates.py --api http://localhost:3333 --key YOUR_API_KEY
  py import_templates.py --api http://localhost:3333 --key KEY --only linkedin,wuzzuf
"""
import json, argparse, pathlib
try:
    import requests
except ImportError:
    raise SystemExit("نزل requests الاول: py -m pip install requests")

BASE = pathlib.Path(__file__).parent
parser = argparse.ArgumentParser()
parser.add_argument("--api", default="http://localhost:3333", help="رابط GoPhish admin")
parser.add_argument("--key", required=True, help="API key من Account Settings")
parser.add_argument("--only", default="", help="brand1,brand2 (اختياري)")
parser.add_argument("--input", default=str(BASE / "templates_import.json"))
a = parser.parse_args()
only = {x.strip().lower() for x in a.only.split(",") if x.strip()}

templates = json.loads(pathlib.Path(a.input).read_text(encoding="utf-8"))
ok = fail = skip = 0
for t in templates:
    # استخرج brand من الاسم للمقارنة
    brand = t["name"].split(" - ")[-1].split(" ")[0].lower() if " - " in t["name"] else ""
    if only and brand not in only:
        skip += 1
        continue
    payload = {k: t[k] for k in ("name", "envelope_sender", "subject", "html", "text") if k in t}
    payload["attachments"] = []
    r = requests.post(f"{a.api}/api/templates/?api_key={a.key}", json=payload, timeout=30)
    if r.status_code == 201:
        print(f"[+] uploaded {t['name']}")
        ok += 1
    elif r.status_code == 409:
        print(f"[=] exists {t['name']}")
        skip += 1
    else:
        print(f"[!] {t['name']} -> {r.status_code} {r.text[:200]}")
        fail += 1
print(f"\nDone: ok={ok} exists/skip={skip} fail={fail}")
