#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
embed_logos.py — يضمّن لوجو كل قالب كـ Base64 data URI بدل اللينك الخارجي،
ويوحّد ألوان الهيدر/الزرار على لون البراند، بدون لمس placeholders او التتبع.

Usage:
  py embed_logos.py --only linkedin,banquemisr   # تجربة
  py embed_logos.py                              # الكل (226)
  py embed_logos.py --max-bytes 102400 --no-color-fix

القواعد:
- badge-only (مفيش <img>) يتساب كما هو + يتسجل skipped.
- أي placeholder من PLACEHOLDERS لازم يفضل موجود بعد المعالجة والا القالب يترفض.
- توازن <table> قبل/بعد لازم يتساوى والا القالب يترفض.
"""
import argparse
import base64
import csv
import io
import json
import re
import urllib.request
from pathlib import Path

BASE = Path(__file__).parent
TPL = BASE / "gophish_templates"
HTML_DIR = TPL / "html"
JSON_DIR = TPL / "json"
LOGOS_DIR = TPL / "logos"

PLACEHOLDERS = ("{{.URL}}", "{{.Tracker}}", "{{.RId}}", "{{.Email}}")
IMG_RE = re.compile(r'<img[^>]*?\ssrc=["\'](https?://[^"\']+)["\']', re.I)


def fetch_image(url, timeout=10, max_bytes=102400):
    """(mime, bytes) او (None, None). يقبل الصور فقط وتحت الحد."""
    req = urllib.request.Request(
        url, headers={"User-Agent": "Mozilla/5.0 (template-builder)"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        if (r.status or 200) >= 400:
            return None, None
        ctype = (r.headers.get("Content-Type") or "").lower().split(";")[0].strip()
        if not ctype.startswith("image/"):
            return None, None
        data = r.read(max_bytes + 1)
    if len(data) > max_bytes or len(data) < 512:
        return None, None
    return ctype, data


def logo_bytes(brand, url, timeout, max_bytes):
    """يرجع (mime, bytes): من الكاش المحلي أولًا ثم التحميل."""
    local = LOGOS_DIR / f"{brand}.png"
    if local.is_file():
        try:
            data = local.read_bytes()
            if 512 <= len(data) <= max_bytes:
                return "image/png", data
        except OSError:
            pass
    if not url:
        return None, None
    mime, data = fetch_image(url, timeout, max_bytes)
    if data:
        try:
            LOGOS_DIR.mkdir(parents=True, exist_ok=True)
            local.write_bytes(data)
        except OSError:
            pass
    return mime, data


def harmonize_colors(html_text, color):
    """يوحد لون خلية اللوجو + شريط الهيدر + زرار CTA على لون البراند.

    يقتصر على أماكن الهيكل المعروفة فقط (لا يلمس محتوى القصة).
    يرجع (html, fixes_count).
    """
    fixes = 0

    def sub_bg_cell(m):
        nonlocal fixes
        if m.group(1).lower() != color.lower():
            fixes += 1
            return f"<td width=\"48\" align=\"center\" valign=\"middle\" style=\"background:{color};"
        return m.group(0)

    html_text = re.sub(
        r'<td width="48" align="center" valign="middle" style="background:(#[0-9a-fA-F]{3,8});',
        sub_bg_cell, html_text)

    def sub_accent(m):
        nonlocal fixes
        if m.group(1).lower() != color.lower():
            fixes += 1
            return f'<td style="background:{color};font-size:0;'
        return m.group(0)

    html_text = re.sub(
        r'<td style="background:(#[0-9a-fA-F]{3,8});font-size:0;',
        sub_accent, html_text)

    def sub_btn(m):
        nonlocal fixes
        if m.group(1).lower() != color.lower():
            fixes += 1
            return f'<td align="center" bgcolor="{color}"'
        return m.group(0)

    html_text = re.sub(
        r'<td align="center" bgcolor="(#[0-9a-fA-F]{3,8})"',
        sub_btn, html_text)
    return html_text, fixes


def process_brand(brand, meta, args):
    """يرجع dict بالنتيجة. لا يكتب ملفات."""
    html_path = HTML_DIR / f"{brand}.html"
    json_path = JSON_DIR / f"{brand}.json"
    if not html_path.is_file() or not json_path.is_file():
        return {"brand": brand, "status": "missing-files"}
    html_text = html_path.read_text(encoding="utf-8")
    before_tables = html_text.lower().count("<table")

    m = IMG_RE.search(html_text)
    if not m:
        return {"brand": brand, "status": "skipped-badge"}
    old_src = m.group(1)
    mime, data = logo_bytes(brand, old_src, args.timeout, args.max_bytes)
    if not data:
        return {"brand": brand, "status": "fetch-failed", "url": old_src}

    data_uri = "data:%s;base64,%s" % (
        mime, base64.b64encode(data).decode("ascii"))
    new_text = html_text[:m.start(1)] + data_uri + html_text[m.end(1):]

    fixes = 0
    if not args.no_color_fix and meta.get("color"):
        new_text, fixes = harmonize_colors(new_text, meta["color"])

    for ph in PLACEHOLDERS:
        if ph not in new_text:
            return {"brand": brand, "status": "placeholder-lost", "detail": ph}
    if new_text.lower().count("<table") != before_tables:
        return {"brand": brand, "status": "layout-changed"}

    (HTML_DIR / f"{brand}.html").write_text(new_text, encoding="utf-8")
    tpl = json.loads(json_path.read_text(encoding="utf-8"))
    tpl["html"] = new_text
    json_path.write_text(json.dumps(tpl, ensure_ascii=False, indent=2),
                         encoding="utf-8")
    return {"brand": brand, "status": "embedded",
            "bytes": len(data_uri), "color_fixes": fixes}


def main():
    ap = argparse.ArgumentParser(description="Embed Base64 logos into templates")
    ap.add_argument("--only", default="")
    ap.add_argument("--timeout", type=int, default=10)
    ap.add_argument("--max-bytes", type=int, default=102400)
    ap.add_argument("--no-color-fix", action="store_true")
    args = ap.parse_args()

    only = {x.strip().lower() for x in args.only.split(",") if x.strip()}
    metas = {}
    with open(TPL / "index.csv", newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            metas[row["brand"].lower()] = row

    brands = sorted(metas)
    if only:
        brands = [b for b in brands if b in only]
    print(f"[*] Processing {len(brands)} templates...")

    results = [process_brand(b, metas[b], args) for b in brands]
    counts = {}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
        if r["status"] not in ("embedded", "skipped-badge"):
            print("    [%s] %s %s" % (
                r["status"], r["brand"], r.get("url", r.get("detail", ""))))

    # rebuild bulk import من الـ JSONs المحدثة
    if not only:
        bulk = []
        for b in sorted(metas):
            jp = JSON_DIR / f"{b}.json"
            if jp.is_file():
                bulk.append(json.loads(jp.read_text(encoding="utf-8")))
        (TPL / "templates_import.json").write_text(
            json.dumps(bulk, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[*] Bulk rebuilt: {len(bulk)} templates")

    emb = [r for r in results if r["status"] == "embedded"]
    if emb:
        total_uri = sum(r["bytes"] for r in emb)
        print("[*] Embedded: %d, avg data-URI %.1f KB, color fixes: %d" % (
            len(emb), total_uri / max(len(emb), 1) / 1024,
            sum(r["color_fixes"] for r in emb)))
    print("[OK]", counts)


if __name__ == "__main__":
    main()
