#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
check_assets.py — يفحص صور ولينكات قوالب gophish_templates قبل الاستخدام.
يكشف Clearbit الميت والصور المكسورة قبل ما توصل للتارجت.

Usage:
  py check_assets.py                  -> فحص الكل + تقرير
  py check_assets.py --only linkedin,banquemisr
  py check_assets.py --no-fail        -> exit 0 حتى لو فيه ميت (للمراجعة فقط)

المخرجات: gophish_templates/assets_report.csv
"""
import argparse
import csv
import json
import re
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

BASE = Path(__file__).parent
JSON_DIR = BASE / "gophish_templates" / "json"
OUT_CSV = BASE / "gophish_templates" / "assets_report.csv"

IMG_RE = re.compile(r'<img[^>]*?\ssrc=["\'](https?://[^"\']+)["\']', re.I)
HREF_RE = re.compile(r'<a[^>]+href=["\'](https?://[^"\']+)["\']', re.I)


def check_url(url: str, timeout: int = 8) -> tuple:
    """(status:int|None, note:str) — HEAD أولًا ثم GET عند الحاجة."""
    for method in ("HEAD", "GET"):
        try:
            req = urllib.request.Request(
                url, method=method,
                headers={"User-Agent": "Mozilla/5.0 (template-asset-check)"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                code = r.status or 200
                if code < 400:
                    return code, "ok"
                if method == "HEAD" and code in (403, 405):
                    continue  # جرّب GET — سيرفرات بترفض HEAD
                return code, f"http-{code}"
        except Exception as e:
            if method == "HEAD":
                continue
            msg = str(e)
            if "timed out" in msg or "Timeout" in type(e).__name__:
                return None, "timeout"
            if "NameResolution" in type(e).__name__ or "nodename" in msg or "getaddrinfo" in msg:
                return None, "dns"
            return None, f"error:{type(e).__name__}"
    return None, "unreachable"


def main():
    ap = argparse.ArgumentParser(description="Check template assets (images/links)")
    ap.add_argument("--only", default="", help="brand1,brand2")
    ap.add_argument("--timeout", type=int, default=8)
    ap.add_argument("--no-fail", action="store_true", help="exit 0 حتى مع وجود ميت")
    ap.add_argument("--workers", type=int, default=10)
    a = ap.parse_args()

    only = {x.strip().lower() for x in a.only.split(",") if x.strip()}
    files = sorted(JSON_DIR.glob("*.json"))
    if only:
        files = [f for f in files if f.stem.lower() in only]
    print(f"[*] Scanning {len(files)} templates...")

    jobs = []  # (brand, kind, url)
    seen = set()
    for f in files:
        try:
            tpl = json.loads(f.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"[!] {f.name}: invalid JSON ({e})")
            continue
        for kind, rx in (("img", IMG_RE), ("link", HREF_RE)):
            for m in rx.finditer(tpl.get("html", "")):
                url = m.group(1)
                if "{{" in url or "}}" in url:
                    continue  # placeholder GoPhish — يتحل وقت الإرسال
                key = (kind, url)
                if key not in seen:
                    seen.add(key)
                    jobs.append((f.stem, kind, url))

    print(f"[*] Checking {len(jobs)} unique asset URLs...")
    results = {}

    def run(job):
        brand, kind, url = job
        code, note = check_url(url, a.timeout)
        return (brand, kind, url, code, note)

    with ThreadPoolExecutor(max_workers=a.workers) as ex:
        for brand, kind, url, code, note in ex.map(run, jobs):
            results.setdefault(brand, []).append((kind, url, code, note))

    dead = total = 0
    with open(OUT_CSV, "w", newline="", encoding="utf-8-sig") as cf:
        w = csv.writer(cf)
        w.writerow(["template", "type", "url", "status", "result"])
        for brand in sorted(results):
            for kind, url, code, note in results[brand]:
                total += 1
                ok = code is not None and code < 400
                if not ok:
                    dead += 1
                w.writerow([brand, kind, url, code or "", "OK" if ok else f"DEAD:{note}"])

    print(f"\n[*] Assets: {total} checked, {dead} dead -> {OUT_CSV}")
    if dead:
        print("[!] Dead assets (fix template or self-host the logo):")
        for brand in sorted(results):
            for kind, url, code, note in results[brand]:
                if code is None or code >= 400:
                    print(f"    {brand} [{kind}] {url} -> {code or note}")
    if dead and not a.no_fail:
        raise SystemExit(1)
    print("[OK] done")


if __name__ == "__main__":
    main()
