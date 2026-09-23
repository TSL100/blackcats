#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
convert_to_gophish.py
يحول company_signatures/*.txt (ناتج sign.py) إلى قوالب GoPhish جاهزة.

المخرجات في signclone/gophish_templates/ :
  html/<brand>.html          -> انسخ والصق في GoPhish GUI > Email Templates > HTML
  json/<brand>.json          -> قالب واحد بصيغة API (POST /api/templates/)
  templates_import.json      -> كل القوالب في ملف واحد
  index.csv                  -> فهرس للبحث السريع
  import_templates.py        -> سكريبت رفع جماعي عبر API

الاستخدام:
  py convert_to_gophish.py
  py convert_to_gophish.py --min-len 30 --limit 0
  py convert_to_gophish.py --only linkedin,wuzzuf,bayb,banquemisr,microsoft

ملحوظة قانونية: للاستخدام المصرح به فقط (Red Team / pentest بتصريح كتابي).
"""
import os
import re
import json
import csv
import html
import argparse
from pathlib import Path

BASE = Path(__file__).parent
SIG_DIR = BASE / "company_signatures"
OUT_DIR = BASE / "gophish_templates"
HTML_DIR = OUT_DIR / "html"
JSON_DIR = OUT_DIR / "json"
LOGOS_DIR = OUT_DIR / "logos"

# كلمات مفتاحية لتصنيف البراند واقتراح Subject مقنع
JOB_BRANDS = {"wuzzuf", "bayt", "linkedin", "hire", "talent", "career", "careers", "jobright", "naukrigulf", "forasna", "gizasystemscareers", "robustastudio", "manatal", "smartrecruiters", "greenhouse-mail", "myworkday", "successfactors", "icims", "ashbyhq", "recruitment", "recruitera", "candidates", "applytojob", "townteam", "inco-group", "itworx", "crossworkersegyptlimited", "redskyconsulting", "remoterecruitment", "viazohorecruit", "taleez", "loopcv", "kickresume", "zety", "resumegenius", "resumeworded", "jobscan", "hays", "kariera"}
FINANCE_BRANDS = {"banquemisr", "vodafone", "stripe", "taptapsend", "luno", "mega", "payments", "statement", "noon", "shop", "commerce"}
LEARN_BRANDS = {"tryhackme", "hackthebox", "cybertalents", "letsdefend", "immersivelabs", "cyberdefenders", "rangeforce", "tcm-sec", "sans", "isc2", "eccouncil", "comptia", "coursera", "udacity", "iti", "nti", "depi", "maharatech", "hackerrank", "codeforces", "coderedpro", "portswigger", "root-me", "ctflearn", "cybrary", "desec", "offensiox"}
SOCIAL_BRANDS = {"linkedin", "facebookmail", "instagram", "threads", "telegram", "discord", "twitter", "youtube", "medium", "notion", "zoom"}

WEAK_PHRASES = {"regards,", "regards", "best,", "best", "thanks,", "thanks", "hello,", "hello", "cheers", "sincerely"}

# اسماء عرض صحيحة + الوان البراندات الحقيقية (عشان كل ايميل يبقى شبه الشركة الاصلية)
PROPER_NAMES = {
    "linkedin": "LinkedIn", "microsoft": "Microsoft", "google": "Google", "facebookmail": "Facebook",
    "instagram": "Instagram", "banquemisr": "Banque Misr", "vodafone": "Vodafone", "wuzzuf": "Wuzzuf",
    "bayt": "Bayt.com", "tryhackme": "TryHackMe", "hackthebox": "Hack The Box", "cybertalents": "CyberTalents",
    "openai": "OpenAI", "stripe": "Stripe", "zoom": "Zoom", "uber": "Uber", "ibm": "IBM", "sans": "SANS Institute",
    "isc2": "ISC2", "eccouncil": "EC-Council", "comptia": "CompTIA", "udacity": "Udacity", "coursera": "Coursera",
    "telegram": "Telegram", "discord": "Discord", "youtube": "YouTube", "medium": "Medium", "notion": "Notion",
    "adobe": "Adobe", "github": "GitHub", "gitlab": "GitLab", "amazon": "Amazon", "noon": "Noon", "pearson": "Pearson",
    "vodafone": "Vodafone", "siemens": "Siemens", "oracle": "Oracle", "cisco": "Cisco", "iti": "ITI", "nti": "NTI",
    "depi": "DEPI", "maharatech": "MaharaTech", "hackerrank": "HackerRank", "codeforces": "Codeforces",
    "letsdefend": "LetsDefend", "immersivelabs": "Immersive Labs", "cyberdefenders": "CyberDefenders",
}

BRAND_COLORS = {
    "linkedin": "#0A66C2", "microsoft": "#00A4EF", "google": "#4285F4", "facebookmail": "#1877F2",
    "instagram": "#E1306C", "banquemisr": "#C8102E", "vodafone": "#E60000", "wuzzuf": "#2E5AAC",
    "bayt": "#00A651", "tryhackme": "#212C42", "hackthebox": "#9FEF00", "cybertalents": "#00B4D8",
    "openai": "#10A37F", "stripe": "#635BFF", "zoom": "#2D8CFF", "uber": "#000000", "ibm": "#0F62FE",
    "sans": "#003057", "isc2": "#007A33", "adobe": "#FA0F00", "github": "#24292F", "noon": "#FEEE00",
    "siemens": "#009999", "udacity": "#02B3E4", "telegram": "#229ED9", "discord": "#5865F2",
    "youtube": "#FF0000", "medium": "#000000", "notion": "#000000",
}

# باليت fallback للبراندات اللي مش متسجلة — لون ثابت لكل براند من hash الاسم
FALLBACK_PALETTE = ["#0A66C2", "#00A4EF", "#10A37F", "#635BFF", "#E60000", "#00A651", "#E1306C", "#0F62FE", "#003057", "#007A33"]

def get_brand_style(brand: str, domain: str) -> tuple:
    """يرجع (display_name, primary_color, logo_url, fallback_url)"""
    b = (brand or "").lower()
    display = PROPER_NAMES.get(b, (brand or "Notification").capitalize())
    color = BRAND_COLORS.get(b)
    if not color:
        import hashlib
        h = int(hashlib.md5(b.encode()).hexdigest(), 16)
        color = FALLBACK_PALETTE[h % len(FALLBACK_PALETTE)]
    # اللوجو الاساسي: Google favicon (شغال وموثوق). Clearbit اتشال لانه ميت
    # على مستوى DNS (logo.clearbit.com لم يعد يحل) — لا تعتمد عليه.
    # للموثوقية القصوى: --download-logos + --logo-base-url للـ self-hosting.
    logo = fav = ""
    if domain:
        logo = f"https://www.google.com/s2/favicons?domain={domain}&sz=64"
        fav = ""
    # overrides يدوية: ملف brand_overrides.json جنب السكريبت يصلح اي لوجو غلط
    # مثال: {"linkedin": {"display": "LinkedIn", "color": "#0A66C2", "logo": "https://..."}}
    try:
        ov_path = BASE / "brand_overrides.json"
        if ov_path.exists():
            import json as _j
            ov = _j.loads(ov_path.read_text(encoding="utf-8")).get(b)
            if ov:
                display = ov.get("display", display)
                color = ov.get("color", color)
                logo = ov.get("logo", logo)
    except Exception:
        pass
    return display, color, logo, fav

def parse_sig_file(path: Path):
    """يرجع dict فيه sender, brand, domain, body"""
    try:
        raw = path.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        return None
    sender = ""
    brand = path.stem
    domain = ""
    for line in raw.splitlines()[:8]:
        if line.startswith("Sender:"):
            sender = line.split("Sender:", 1)[1].strip()
        elif line.startswith("Clean Brand Name:"):
            brand = line.split(":", 1)[1].strip().lower().replace(" ", "")
        elif line.startswith("Full Domain:"):
            domain = line.split(":", 1)[1].strip().lower()
    if "========================================" in raw:
        body = raw.split("========================================", 1)[1].strip()
    else:
        # ملفات قديمة بصيغة signatures_output.json style
        body = raw.strip()
    # تنضيف HTML خام لو اتسرب (زي statement.txt)
    if body.lstrip().lower().startswith("<!doctype") or "<html" in body.lower()[:500]:
        # شيل التاجز وخلي النص فقط
        body = re.sub(r"<script.*?</script>", "", body, flags=re.I | re.S)
        body = re.sub(r"<style.*?</style>", "", body, flags=re.I | re.S)
        body = re.sub(r"<[^>]+>", "\n", body)
        body = html.unescape(body)
        body = re.sub(r"\n{3,}", "\n\n", body).strip()
        # لو لسه طويل جدا قصه (فوتر فقط)
        if len(body) > 1500:
            lines = [l.strip() for l in body.splitlines() if l.strip()]
            body = "\n".join(lines[-12:])
    return {"file": path.name, "sender": sender, "brand": brand, "domain": domain, "body": body}

def select_logo(brand: str, logo_url: str, args, alive: bool = True) -> tuple:
    """(img_src, status) — status in {"selfhosted","live","badge"}.

    Dead remote logos NEVER ship as <img>: they become a pure CSS initial
    badge so no client can ever render a broken-image icon.
    """
    base = ((getattr(args, "logo_base_url", "") or "").rstrip("/") + "/"
            if getattr(args, "logo_base_url", "") else "")
    local = LOGOS_DIR / f"{brand}.png"
    if getattr(args, "download_logos", False) and logo_url:
        download_logo(logo_url, local)
    if base and local.is_file():
        return base + f"{brand}.png", "selfhosted"
    if logo_url and alive:
        return logo_url, "live"
    return "", "badge"


def logo_alive(url: str, timeout: int = 8) -> bool:
    """GET-verified liveness: True only on HTTP < 400 with an image payload.

    (HEAD alone lies on some favicon frontends — 200 on HEAD, 404 on GET —
    so always verify what a real client would download.)
    """
    import urllib.request
    if not url:
        return False
    try:
        req = urllib.request.Request(
            url, method="GET",
            headers={"User-Agent": "Mozilla/5.0 (template-builder)"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            if (r.status or 200) >= 400:
                return False
            ctype = (r.headers.get("Content-Type") or "").lower()
            if "image" not in ctype:
                return False
            return len(r.read(300 * 1024)) >= 512
    except Exception:
        return False
    return False


def resolve_logo_src_fallback(logo_url: str, fav_url: str) -> str:
    """Legacy path (no liveness info): prefer remote URL, badge handled by caller."""
    return logo_url or fav_url or ""

def download_logo(url: str, dest: Path) -> bool:
    """Fetch one logo to dest. True on a real image file, False otherwise."""
    import urllib.request
    if not url or not dest:
        return False
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (template-builder)"})
        with urllib.request.urlopen(req, timeout=10) as r:
            if (r.status or 200) >= 400:
                return False
            ctype = (r.headers.get("Content-Type") or "").lower()
            data = r.read(300 * 1024)
        if "image" not in ctype or len(data) < 1024:
            return False
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        return True
    except Exception:
        return False

def extract_email(sender: str, domain: str) -> str:
    m = re.search(r"<([^>]+@[^>]+)>", sender or "")
    if m:
        return m.group(1).strip()
    m = re.search(r"[\w.\-+%]+@[\w.\-]+\.\w+", sender or "")
    if m:
        return m.group(0)
    if domain:
        return f"no-reply@{domain}"
    return ""

def envelope_from(domain: str, orig_email: str) -> str:
    # GoPhish لازم EnvelopeSender يكون ايميل صحيح، نستخدم الاصلي لو موجود
    if orig_email and "@" in orig_email:
        return orig_email
    if domain:
        return f"no-reply@{domain}"
    return ""

CUSTOM_TEMPLATES = {"tryhackme", "deepseek", "isc2", "maltego", "uber", "wuzzuf"}  # براندات بتصميم يدوي ثابت — لا تعيد توليدها تلقائيًا (markers بالأسفل)

def suggest_subject(brand: str, domain: str) -> str:
    b = (brand or "").lower()
    pretty = brand.capitalize() if brand else "Notification"
    if b == "tryhackme":
        return "We need to talk. \U0001F494"
    if b == "deepseek":
        return "Your DeepSeek verification code: 816074"
    if b == "isc2":
        return "You're invited to become an ISC2 Candidate"
    if b == "maltego":
        return "Activate your Maltego CE account"
    if b == "uber":
        return "أهلاً {{.FirstName}} — أكّد بريدك الإلكتروني"
    if b == "wuzzuf":
        return "{{.FirstName}}, your weekly job matches on Wuzzuf"
    if b in JOB_BRANDS:
        return f"{{{{.FirstName}}}} - New job matches at {pretty} (action required)"
    if b in FINANCE_BRANDS:
        return f"Security alert: verify your {pretty} account {{{{.LastName}}}}"
    if b in LEARN_BRANDS:
        return f"Your {pretty} certificate / lab access is ready"
    if b in SOCIAL_BRANDS:
        return f"You have 3 new notifications on {pretty}"
    if "verify" in b or "otp" in b or "auth" in b or "account" in b:
        return f"Verification code: confirm your {pretty} account"
    if "newsletter" in b or "news" in b or "notify" in b or "update" in b:
        return f"{pretty} weekly update for {{{{.FirstName}}}}" 
    return f"Action required: confirm your {pretty} account"

def pretext_for(brand: str) -> tuple:
    """يرجع (headline, html_body, text_body, cta) - بدي غني حسب السياق"""
    b = (brand or "").lower()
    pretty = brand.capitalize() if brand else "our platform"

    if b in JOB_BRANDS:
        headline = f"You have 3 new job matches on {pretty}"
        html_body = """<p>Hi {{.FirstName}},</p>
<p>Great news — our matching engine reviewed your profile (<b>{{.Email}}</b>, title: <b>{{.Position}}</b>) and found <b>3 roles</b> that fit your experience in Cairo / Giza / Remote. Employers are actively shortlisting this week.</p>
<table style="width:100%;border-collapse:collapse;margin:16px 0;font-size:13px;">
<tr style="background:#f1f5f9;"><td style="padding:10px;border:1px solid #e2e8f0;"><b>1. SOC Analyst (L1)</b><br>Qoala Tech — Maadi, Cairo — 12-18k EGP</td></tr>
<tr><td style="padding:10px;border:1px solid #e2e8f0;"><b>2. Junior Penetration Tester</b><br>SecureOps EG — Nasr City / Hybrid — 15-22k EGP</td></tr>
<tr style="background:#f1f5f9;"><td style="padding:10px;border:1px solid #e2e8f0;"><b>3. IT Helpdesk + Security</b><br>Banque Misr Vendor — Downtown — 10-14k EGP</td></tr>
</table>
<p>Your profile visibility is currently <b>35%</b> — incomplete profiles are hidden from recruiters after <b>48 hours</b>. To keep your applications active:</p>
<ol style="margin:0 0 16px 20px;padding:0;">
<li>Confirm your email address (30 seconds)</li>
<li>Update your phone number and CV</li>
<li>Click Apply on the roles above</li>
</ol>
<p style="font-size:12px;color:#555;">Reference ID: {{.RId}} — This invitation was sent to {{.Email}} because you created a job-seeker account.</p>"""
        text_body = """Hi {{.FirstName}},

Great news — our matching engine reviewed your profile ({{.Email}}, title: {{.Position}}) and found 3 roles that fit your experience in Cairo / Giza / Remote. Employers are actively shortlisting this week.

1. SOC Analyst (L1) — Qoala Tech, Maadi Cairo, 12-18k EGP
2. Junior Penetration Tester — SecureOps EG, Nasr City/Hybrid, 15-22k EGP
3. IT Helpdesk + Security — Banque Misr Vendor, Downtown, 10-14k EGP

Your profile visibility is currently 35% — incomplete profiles are hidden after 48 hours. To keep applications active:
1. Confirm your email (30 seconds)
2. Update phone + CV
3. Click Apply on roles above

Reference ID: {{.RId}} — sent to {{.Email}}."""
        return headline, html_body, text_body, "View & Apply Now"

    if b in FINANCE_BRANDS:
        headline = f"Security alert: unusual activity on your {pretty} account"
        html_body = """<p>Dear {{.FirstName}} {{.LastName}},</p>
<p>We detected a sign-in attempt to your <b>{{.Email}}</b> account that doesn't match your usual pattern. For your protection we temporarily limited outgoing transfers.</p>
<table style="width:100%;border-collapse:collapse;margin:16px 0;font-size:13px;">
<tr style="background:#fef2f2;"><td style="padding:8px;border:1px solid #fecaca;"><b>Date:</b> Today, 09:42 Cairo time</td></tr>
<tr><td style="padding:8px;border:1px solid #fecaca;"><b>Device:</b> Chrome / Windows — IP 197.XXX.XX.15 (Alexandria, EG)</td></tr>
<tr style="background:#fef2f2;"><td style="padding:8px;border:1px solid #fecaca;"><b>Action:</b> Password reset + EGP 4,800 transfer request</td></tr>
</table>
<p>If this was <b>you</b>, no action is needed — your account will auto-unlock in 24h. If this was <b>not you</b>, you must review and secure your account immediately, otherwise the pending request will be approved.</p>
<ul style="margin:0 0 16px 20px;padding:0;">
<li>Never share your OTP with anyone claiming to be support</li>
<li>Check your last 5 transactions after login</li>
<li>Enable 2-step verification if not active</li>
</ul>
<p style="font-size:12px;color:#555;">Case ID: {{.RId}} — If you ignore this, liability for unauthorized transactions may shift to you per account terms.</p>"""
        text_body = """Dear {{.FirstName}} {{.LastName}},

We detected a sign-in to {{.Email}} that doesn't match your usual pattern. We temporarily limited outgoing transfers.

Date: Today 09:42 Cairo time
Device: Chrome/Windows — IP 197.XXX.XX.15 (Alexandria, EG)
Action: Password reset + EGP 4,800 transfer request

If this was you, ignore — auto-unlock in 24h. If NOT you, review and secure immediately or pending request will be approved.

- Never share OTP with anyone
- Check last 5 transactions after login
- Enable 2-step verification

Case ID: {{.RId}}."""
        return headline, html_body, text_body, "Review Activity Now"

    if b in LEARN_BRANDS:
        headline = f"Your {pretty} enrollment is confirmed — activate your lab"
        html_body = """<p>Hi {{.FirstName}},</p>
<p>Congratulations! Your seat for <b>{{.Position}} track — 2026 intake</b> is reserved under {{.Email}}. Your dashboard, labs, and exam voucher are ready, but your access link expires in <b>24 hours</b>.</p>
<p><b>What you get:</b></p>
<ul style="margin:0 0 16px 20px;padding:0;">
<li>40+ hands-on labs (SOC / Pentest / DFIR) + browser VPN</li>
<li>Official PDF + practice exams + completion certificate</li>
<li>Private Discord/WhatsApp study group + mentor hours</li>
</ul>
<p><b>To activate (2 minutes):</b></p>
<ol style="margin:0 0 16px 20px;padding:0;">
<li>Click below and sign in with {{.Email}}</li>
<li>Set your lab password and download VPN pack</li>
<li>Start Module 1 — your progress is tracked for the certificate</li>
</ol>
<p style="font-size:12px;color:#555;">Student ID: {{.RId}} — 2,300+ Egyptian students joined this round. Unclaimed seats are released automatically.</p>"""
        text_body = """Hi {{.FirstName}},

Congratulations! Your seat for {{.Position}} track 2026 is reserved under {{.Email}}. Labs + exam voucher ready, link expires in 24h.

What you get:
- 40+ hands-on labs (SOC/Pentest/DFIR)
- PDF + practice exams + certificate
- Study group + mentor hours

To activate (2 min):
1. Click below, sign in with {{.Email}}
2. Set lab password, download VPN
3. Start Module 1

Student ID: {{.RId}}."""
        return headline, html_body, text_body, "Activate My Lab"

    if b in SOCIAL_BRANDS:
        headline = f"You have 5 new interactions on {pretty}"
        html_body = """<p>Hi {{.FirstName}},</p>
<p>While you were away, your profile got attention. Here's your summary for this week:</p>
<ul style="margin:0 0 16px 20px;padding:0;list-style:none;">
<li style="padding:8px;background:#f8fafc;border:1px solid #e2e8f0;margin-bottom:6px;border-radius:6px;">👁️ <b>12 people</b> viewed your profile — including 2 recruiters</li>
<li style="padding:8px;background:#f8fafc;border:1px solid #e2e8f0;margin-bottom:6px;border-radius:6px;">💬 <b>3 unread messages</b> — latest: "Hi {{.FirstName}}, are you open to a quick call tomorrow?"</li>
<li style="padding:8px;background:#f8fafc;border:1px solid #e2e8f0;margin-bottom:6px;border-radius:6px;">🤝 <b>2 connection requests</b> pending approval</li>
</ul>
<p>Messages from non-connections are auto-deleted after <b>7 days</b>. Log in now to read and reply before they expire. Someone searching for "<b>{{.Position}}</b>" in Egypt found you.</p>
<p style="font-size:12px;color:#555;">Account: {{.Email}} — Notification ID: {{.RId}} — Manage preferences anytime.</p>"""
        text_body = """Hi {{.FirstName}},

While away, your profile got attention:
- 12 views incl. 2 recruiters
- 3 unread messages, latest: "Hi, open to quick call tomorrow?"
- 2 connection requests pending

Non-connection messages auto-delete after 7 days. Login to reply. Someone searching "{{.Position}}" in Egypt found you.

Account {{.Email}} ID {{.RId}}."""
        return headline, html_body, text_body, "View Notifications"

    # default: account verification / IT
    headline = f"Action required: verify your {pretty} account"
    html_body = """<p>Hi {{.FirstName}} {{.LastName}},</p>
<p>As part of our routine security review, we need you to re-confirm ownership of <b>{{.Email}}</b> (role: {{.Position}}). This keeps your mailbox, files, and single sign-on active.</p>
<p><b>Why you received this:</b> your password is 180+ days old and your session was accessed from a new device. Unverified accounts are moved to <b>restricted mode</b> (no send/receive) within 72 hours per IT policy.</p>
<p><b>What to do (under a minute):</b></p>
<ol style="margin:0 0 16px 20px;padding:0;">
<li>Click the button below and sign in as {{.Email}}</li>
<li>Approve the push notification / enter OTP</li>
<li>You'll see "Verification complete" — nothing else to install</li>
</ol>
<p style="font-size:12px;color:#555;">Ticket: {{.RId}} — If you already verified in the last 7 days, ignore this reminder.</p>"""
    text_body = """Hi {{.FirstName}} {{.LastName}},

Routine review: re-confirm ownership of {{.Email}} ({{.Position}}) to keep mailbox/files/SSO active.

Why: password 180+ days old + new device login. Unverified = restricted mode in 72h.

Steps (<1 min):
1. Click below, sign in as {{.Email}}
2. Approve push / enter OTP
3. Done.

Ticket {{.RId}} — ignore if verified last 7 days."""
    return headline, html_body, text_body, "Verify My Account"

def build_html(brand: str, domain: str, sig_body: str, subject: str, args=None, img_src: str = None) -> str:
    display, color, logo_url, fav_url = get_brand_style(brand, domain)
    # زرار فاتح (اصفر/اخضر فاتح) لازم نص اسود عشان يتقري
    btn_text = "#000" if color.upper() in {"#9FEF00", "#FEEE00", "#FFEB3B"} else "#fff"
    headline, story_html, _, cta = pretext_for(brand)
    sig_html = html.escape(sig_body).replace("\n", "<br>")
    # دومين العرض (للتمويه البصري فقط - الرابط الحقيقي هو {{.URL}})
    display_domain = domain or f"{brand}.com"
    initial = (display[:1] or "N").upper()
    if img_src is None:
        img_src = resolve_logo_src_fallback(logo_url, fav_url)
    # طبقات اللوجو (bulletproof, Outlook-safe):
    # 1) primary img (favicon حي او self-hosted)  2) favicon بديل (onerror, لو مختلف)
    # 3) CSS initial badge (JS swap حيث مسموح)  4) styled alt letter على لون البراند
    # 5) اسم البراند نص (دايمًا ظاهر — الضمان الحقيقي لما الصور مقفولة).
    # ملحوظة: Gmail/Outlook بيمنعوا JS وبيقفلوا الصور افتراضيًا — عشان كده اسم
    # البراند نص دايمًا موجود، والـ alt متستايل بحرف اول ابيض على لون البراند.
    if img_src:
        if fav_url and fav_url != img_src:
            onerr = (f" onerror=\"this.onerror=null;this.src='{fav_url}';"
                     f"this.onerror=function(){{this.style.display='none';"
                     f"var b=this.parentNode.querySelector('.logo-fallback');"
                     f"if(b){{b.style.display='inline-block';}}}};\"")
        else:
            onerr = (" onerror=\"this.style.display='none';"
                     "var b=this.parentNode.querySelector('.logo-fallback');"
                     "if(b){b.style.display='inline-block';};\"")
        logo_cell = (
            f'<img src="{img_src}" width="36" height="36" alt="{html.escape(initial)}" '
            f'style="display:block;border:0;outline:none;text-decoration:none;'
            f'font-family:Arial,sans-serif;font-size:20px;font-weight:bold;color:#ffffff;"'
            + onerr +
            " />"
            f'<span class="logo-fallback" style="display:none;width:36px;height:36px;'
            f'line-height:36px;text-align:center;font-family:Arial,sans-serif;'
            f'font-weight:bold;font-size:20px;color:#ffffff;">{html.escape(initial)}</span>'
        )
    else:
        logo_cell = (
            f'<span style="display:inline-block;width:36px;height:36px;line-height:36px;'
            f'text-align:center;font-family:Arial,sans-serif;font-weight:bold;'
            f'font-size:20px;color:#ffffff;">{html.escape(initial)}</span>'
        )
    return f"""<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{html.escape(subject)}</title></head>
<body style="margin:0;padding:0;background:#f4f4f4;font-family:Arial,Helvetica,sans-serif;-webkit-text-size-adjust:100%;-ms-text-size-adjust:100%;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#f4f4f4;">
<tr><td align="center" style="padding:20px 10px;">
<table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0" style="background:#ffffff;border:1px solid #e0e0e0;border-radius:8px;max-width:600px;">
<tr><td style="background:{color};font-size:0;line-height:0;border-radius:8px 8px 0 0;">&nbsp;</td></tr>
<tr><td style="padding:16px 24px;border-bottom:1px solid #eeeeee;">
<table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>
<td width="48" align="center" valign="middle" style="background:{color};border-radius:8px;padding:6px;">{logo_cell}</td>
<td valign="middle" style="padding-left:12px;font-family:Arial,sans-serif;font-size:19px;font-weight:bold;color:#111111;">{html.escape(display)}<br><span style="font-weight:normal;font-size:11px;color:#999999;">{html.escape(display_domain)}</span></td>
</tr></table>
</td></tr>
<tr><td style="padding:28px 24px;color:#222222;font-family:Arial,sans-serif;font-size:14px;line-height:1.7;">
    <h2 style="margin:0 0 12px;font-size:19px;color:#111111;">{headline}</h2>
    {story_html}
    <!-- مهم: الرابط لازم يفضل {{{{.URL}}}} عشان GoPhish يحط لينك الـ lure المشفر بالـ rid -->
    <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:26px auto;"><tr>
    <td align="center" bgcolor="{color}" style="border-radius:6px;"><a href="{{{{.URL}}}}" style="display:inline-block;padding:13px 34px;font-family:Arial,sans-serif;font-size:15px;font-weight:bold;color:{btn_text};text-decoration:none;">{cta}</a></td>
    </tr></table>
    <p style="font-size:12px;color:#666666;">If the button doesn't work, copy this link:<br><span style="color:{color};">{{{{.URL}}}}</span></p>
    <p style="font-size:12px;color:#666666;">Recipient: {{{{.Email}}}} &nbsp;|&nbsp; ID: {{{{.RId}}}}</p>
    <hr style="border:none;border-top:1px solid #eeeeee;margin:22px 0;">
    <!-- فوتر حقيقي مسحوب من signclone/company_signatures/{brand}.txt -->
    <div style="font-size:11px;color:#888888;line-height:1.6;">{sig_html}<br><br>
    <span style="color:#aaaaaa;">{html.escape(display_domain)} &bull; To stop these emails: <a href="{{{{.BaseURL}}}}/unsubscribe?rid={{{{.RId}}}}" style="color:#aaaaaa;">unsubscribe</a></span>
    </div>
</td></tr>
<tr><td align="center" style="background:#f8fafc;padding:10px;font-family:Arial,sans-serif;font-size:11px;color:#999999;">This is an automated notification. Please do not reply.</td></tr>
</table>
</td></tr>
</table>
<!-- تتبع الفتح - لازم يفضل موجود -->
{{{{.Tracker}}}}
</body>
</html>"""

def build_text(brand: str, sig_body: str) -> str:
    display, _, _, _ = get_brand_style(brand, "")
    headline, _, story_text, cta = pretext_for(brand)
    return f"""{display} - {headline}

{story_text}

{cta}: {{{{.URL}}}}

Recipient: {{{{.Email}}}} | ID: {{{{.RId}}}}

--
{sig_body}

Unsubscribe: {{{{.BaseURL}}}}/unsubscribe?rid={{{{.RId}}}}"""

def main():
    ap = argparse.ArgumentParser(description="Convert company_signatures to GoPhish templates")
    ap.add_argument("--min-len", type=int, default=30, help="اقل طول للفوتر عشان يتقبل (default 30)")
    ap.add_argument("--limit", type=int, default=0, help="0 = الكل، او رقم للتجربة")
    ap.add_argument("--only", type=str, default="", help="brand1,brand2 للتحويل الجزئي")
    ap.add_argument("--download-logos", action="store_true",
                    help="نزل اللوجوهات محليًا في gophish_templates/logos/ (تدقيق + self-hosting)")
    ap.add_argument("--logo-base-url", type=str, default="",
                    help="رابط عام لمجلد logos (مثال https://login.example.com/assets/logos/) — الصور تشاور عليه بدل Clearbit")
    ap.add_argument("--no-logo-check", action="store_true",
                    help="تخطي فحص حياة اللوجوهات (للتشغيل الاوفلاين) — كل البراندات تاخد img")
    args = ap.parse_args()

    only = {x.strip().lower() for x in args.only.split(",") if x.strip()} if args.only else set()

    HTML_DIR.mkdir(parents=True, exist_ok=True)
    JSON_DIR.mkdir(parents=True, exist_ok=True)
    if args.download_logos:
        LOGOS_DIR.mkdir(parents=True, exist_ok=True)

    files = sorted(SIG_DIR.glob("*.txt"))
    print(f"[*] Found {len(files)} signature files in {SIG_DIR}")

    results = []
    skipped_weak = []
    count = 0

    # تجميع اولًا (parse + filter) عشان فحص اللوجوهات المتوازي
    pending = []
    for f in files:
        data = parse_sig_file(f)
        if not data:
            continue
        brand, domain, body, sender = data["brand"], data["domain"], data["body"], data["sender"]
        if only and brand.lower() not in only and f.stem.lower() not in only:
            continue
        body_len = len(body.strip())
        # فلترة الضعيف
        norm = body.strip().lower().rstrip(",.")
        if body_len < args.min_len or norm in WEAK_PHRASES:
            skipped_weak.append((f.name, body_len))
            continue
        display, color, logo_url, _fav = get_brand_style(brand, domain)
        pending.append({"brand": brand, "domain": domain, "body": body.strip(),
                        "sender": sender, "display": display, "color": color,
                        "logo_url": logo_url, "body_len": body_len})
        if args.limit and len(pending) >= args.limit:
            break

    # فحص حياة اللوجوهات (متوازي) — الميت يتحول badge تلقائيًا
    alive_map = {}
    if args.no_logo_check:
        print("[*] Logo liveness check skipped (--no-logo-check)")
    else:
        uniq = sorted({p["logo_url"] for p in pending if p["logo_url"]})
        print(f"[*] Checking {len(uniq)} unique logo URLs...")
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=10) as ex:
            for url, ok in zip(uniq, ex.map(logo_alive, uniq)):
                alive_map[url] = ok
        n_live = sum(1 for p in pending if alive_map.get(p["logo_url"], False))
        print(f"[*] Logos live: {n_live}/{len(pending)} (dead -> CSS badge, zero broken images)")

    for p in pending:
        brand, domain = p["brand"], p["domain"]
        img_src, logo_status = select_logo(
            brand, p["logo_url"], args,
            alive=alive_map.get(p["logo_url"], True) if not args.no_logo_check else True)

        orig_email = extract_email(p["sender"], domain)
        envelope = envelope_from(domain, orig_email)
        subject = suggest_subject(brand, domain)
        display, color = p["display"], p["color"]
        # قوالب مخصصة يدويًا: حافظ عليها ولا تعيد توليدها (marker مختلف لكل براند)
        if brand in CUSTOM_TEMPLATES:
            _markers = {"tryhackme": "We need to talk", "deepseek": "Verify my account \u2192", "isc2": "Your future. Secured.", "maltego": "ACTIVATE YOUR", "uber": "أهلاً {{.FirstName}}", "wuzzuf": "Explore a world of possibilities."}
            _ch = HTML_DIR / f"{brand}.html"
            _cj = JSON_DIR / f"{brand}.json"
            try:
                _existing_html = _ch.read_text(encoding="utf-8") if _ch.is_file() else ""
            except Exception:
                _existing_html = ""
            if _markers.get(brand, brand) in _existing_html and _cj.is_file():
                try:
                    _kept = json.loads(_cj.read_text(encoding="utf-8"))
                    html_content = _kept.get("html", _existing_html)
                    text_content = _kept.get("text", build_text(brand, p["body"]))
                    subject = _kept.get("subject", subject)
                    envelope = _kept.get("envelope_sender", envelope)
                except Exception:
                    html_content = _existing_html
                    text_content = build_text(brand, p["body"])
            else:
                html_content = build_html(brand, domain, p["body"], subject, args, img_src=img_src)
                text_content = build_text(brand, p["body"])
        else:
            html_content = build_html(brand, domain, p["body"], subject, args, img_src=img_src)
            text_content = build_text(brand, p["body"])

        name = f"Clone - {brand} ({domain or 'no-domain'})"

        tpl = {
            "name": name,
            "envelope_sender": envelope,
            "subject": subject,
            "html": html_content,
            "text": text_content,
            "attachments": [],
            "_meta": {
                "brand": brand,
                "display": display,
                "domain": domain,
                "color": color,
                "logo": img_src or "(badge)",
                "logo_ok": logo_status,
                "sender": p["sender"],
                "source_file": brand + ".txt",
                "footer_chars": p["body_len"],
            },
        }
        # شيل _meta قبل الحفظ للـ API (GoPhish هيرفض حقول زيادة؟ لا، بس ننضف)
        api_tpl = {k: v for k, v in tpl.items() if not k.startswith("_")}

        (HTML_DIR / f"{brand}.html").write_text(html_content, encoding="utf-8")
        (JSON_DIR / f"{brand}.json").write_text(json.dumps(api_tpl, ensure_ascii=False, indent=2), encoding="utf-8")

        results.append(tpl)
        count += 1
        try:
            print(f"  [+] {brand:25} | {domain:30} | {p['body_len']:4} chars | [{logo_status:10}] | {subject[:45]}")
        except UnicodeEncodeError:
            print(f"  [+] {brand} | {domain} | {p['body_len']} chars | [{logo_status}] | {subject[:45].encode('ascii', 'replace').decode()}")

    # ملف مجمع
    api_all = [{k: v for k, v in t.items() if not k.startswith("_")} for t in results]
    (OUT_DIR / "templates_import.json").write_text(json.dumps(api_all, ensure_ascii=False, indent=2), encoding="utf-8")

    # فهرس CSV
    with open(OUT_DIR / "index.csv", "w", newline="", encoding="utf-8-sig") as csvf:
        w = csv.writer(csvf)
        w.writerow(["name", "brand", "display", "domain", "color", "logo", "logo_ok", "sender", "envelope_sender", "subject", "footer_chars", "html_file", "json_file"])
        for t in results:
            m = t["_meta"]
            w.writerow([t["name"], m["brand"], m.get("display", ""), m["domain"], m.get("color", ""), m.get("logo", ""), m.get("logo_ok", ""), m["sender"], t["envelope_sender"], t["subject"], m["footer_chars"], f"html/{m['brand']}.html", f"json/{m['brand']}.json"])

    # ملف overrides مثال عشان تصلح اي لوجو غلط يدوي
    ov_example = BASE / "brand_overrides.example.json"
    if not ov_example.exists():
        ov_example.write_text(json.dumps({
            "linkedin": {"display": "LinkedIn", "color": "#0A66C2", "logo": "https://www.google.com/s2/favicons?domain=linkedin.com&sz=64"},
            "banquemisr": {"display": "Banque Misr", "color": "#C8102E", "logo": "https://www.google.com/s2/favicons?domain=banquemisr.com&sz=64"},
            "tryhackme": {"display": "TryHackMe", "color": "#212C42", "logo": "https://login.example.com/assets/logos/tryhackme.png"}
        }, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[*] Override example -> {ov_example} (copy to brand_overrides.json to fix logos)")

    # سكريبت الرفع عبر API
    importer = '''#!/usr/bin/env python3
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
print(f"\\nDone: ok={ok} exists/skip={skip} fail={fail}")
'''
    (OUT_DIR / "import_templates.py").write_text(importer, encoding="utf-8")

    print(f"\n[OK] Templates: {count}")
    print(f"[*] Skipped weak (<{args.min_len} chars or generic): {len(skipped_weak)}")
    if skipped_weak[:10]:
        print("    examples:", ", ".join(f"{n}({c})" for n, c in skipped_weak[:10]))
    print(f"[*] HTML -> {HTML_DIR}")
    print(f"[*] JSON -> {JSON_DIR}")
    print(f"[*] Bulk -> {OUT_DIR / 'templates_import.json'}")
    print(f"[*] Index -> {OUT_DIR / 'index.csv'}")
    print(f"[*] Uploader -> {OUT_DIR / 'import_templates.py'}")

if __name__ == "__main__":
    main()
