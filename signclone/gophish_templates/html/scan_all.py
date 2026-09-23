import os
import sys
import requests
from bs4 import BeautifulSoup

def test_single_file(file_path):
    issues = []
    checked_urls = set()
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            html_content = f.read()
    except Exception as e:
        return [{"type": "file_error", "detail": str(e)}]

    soup = BeautifulSoup(html_content, 'html.parser')

    # 1. فحص الصور واللوجوهات
    for img in soup.find_all('img'):
        src = img.get('src', '')
        if not src:
            issues.append({"type": "broken_image", "detail": "Image with empty src"})
            continue
        if src.startswith('data:image') or src.startswith('cid:'):
            continue
            
        if src.startswith('http://') or src.startswith('https://'):
            if src in checked_urls:
                continue
            checked_urls.add(src)
            try:
                response = requests.head(src, timeout=4, allow_redirects=True)
                if response.status_code >= 400:
                    issues.append({"type": "dead_image", "url": src, "status": response.status_code})
            except Exception:
                issues.append({"type": "unreachable_image", "url": src})

    # 2. فحص الروابط
    for link in soup.find_all('a'):
        href = link.get('href', '')
        if not href or '{{.URL}}' in href or '{{URL}}' in href or href.startswith('#') or href.startswith('mailto:'):
            continue
            
        if href.startswith('http://') or href.startswith('https://'):
            if href in checked_urls:
                continue
            checked_urls.add(href)
            try:
                response = requests.head(href, timeout=4, allow_redirects=True)
                if response.status_code >= 400:
                    issues.append({"type": "dead_link", "url": href, "status": response.status_code})
            except Exception:
                issues.append({"type": "unreachable_link", "url": href})

    # 3. التحقق من متغيرات جوفيش الإلزامية
    has_tracker = '{{.Tracker}}' in html_content or 'tracker' in html_content.lower()
    has_url = '{{.URL}}' in html_content or '{{URL}}' in html_content.lower()
    
    if not has_url:
        issues.append({"type": "missing_placeholder", "detail": "Missing {{.URL}}"})
    if not has_tracker:
        issues.append({"type": "missing_tracker", "detail": "Missing {{.Tracker}}"})

    return issues

def scan_folder(folder_path):
    if not os.path.exists(folder_path):
        print(f"[-] Error: Path '{folder_path}' does not exist.")
        return

    print(f"[*] Scanning folder: {os.path.abspath(folder_path)} ...\n")
    
    html_files = []
    for root, _, files in os.walk(folder_path):
        # نتخطى مجلدات النظام أو البيئة الافتراضية عشان ميعملش لูป طويل
        if '.git' in root or 'venv' in root or '__pycache__' in root:
            continue
        for file in files:
            if file.endswith(('.html', '.htm', '.csv', '.txt')):
                html_files.append(os.path.join(root, file))

    if not html_files:
        print("[-] No target files (.html, .htm, .csv, .txt) found in this directory.")
        return

    print(f"[*] Found {len(html_files)} files to process. Please wait...\n")
    
    total_issues = 0
    files_with_issues = 0

    for idx, file_path in enumerate(html_files, 1):
        rel_path = os.path.relpath(file_path, folder_path)
        issues = test_single_file(file_path)
        
        if issues:
            files_with_issues += 1
            total_issues += len(issues)
            print(f"[-] [{idx}/{len(html_files)}] Issues in: {rel_path}")
            for issue in issues:
                print(f"    -> Type: {issue.get('type')} | Detail: {issue.get('url', issue.get('detail'))} {f'(Status: {issue.get("status")})' if 'status' in issue else ''}")
        else:
            print(f"[+] [{idx}/{len(html_files)}] Clean: {rel_path}")

    print("\n" + "="*50)
    print("                 SCAN SUMMARY                 ")
    print("="*50)
    print(f" Total files scanned : {len(html_files)}")
    print(f" Files with issues   : {files_with_issues}")
    print(f" Total issues found  : {total_issues}")
    print("="*50)

if __name__ == "__main__":
    target_path = sys.argv[1] if len(sys.argv) > 1 else "."
    scan_folder(target_path)