import os
import argparse
import base64
import re
import time
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from bs4 import BeautifulSoup

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

def token_file_for_account(account_index):
    """One token file per account. Account 3 keeps the legacy token.json
    so existing setups don't re-auth; 4+ get their own token_N.json."""
    if account_index == 1:
        return 'token_1.json'
    if account_index == 2:
        return 'token_2.json'
    if account_index == 3:
        return 'token.json'
    return f'token_{account_index}.json'

def get_gmail_service_for_account(account_index):
    token_file = token_file_for_account(account_index)
    cred_file = 'credentials.json'
    
    creds = None
    if os.path.exists(token_file):
        creds = Credentials.from_authorized_user_file(token_file, SCOPES)
        
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
            except Exception:
                creds = None
                
        if not creds:
            print(f"\n[!] Authenticating Gmail Account #{account_index} using {token_file}...")
            flow = InstalledAppFlow.from_client_secrets_file(cred_file, SCOPES)
            creds = flow.run_local_server(port=0)
            
        with open(token_file, 'w') as token:
            token.write(creds.to_json())
            
    return build('gmail', 'v1', credentials=creds)

def extract_company_name(sender):
    email_match = re.search(r'<(.+?)>', sender)
    email = email_match.group(1) if email_match else sender
    
    if '@' in email:
        domain = email.split('@')[1].lower()
        
        free_domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'icloud.com', 'proton.me', 'protonmail.com']
        if domain in free_domains:
            return None, domain
            
        parts = domain.split('.')
        ignored_subparts = ['mail', 'newsletter', 'news', 'skills', 'courses', 'learning', 'us-skills', 'us-courses', 'us-learning', 'priority', 'security', 'notification', 'notifications', 'no-reply', 'noreply']
        
        clean_name = None
        for part in parts:
            if part not in ignored_subparts and len(part) > 2:
                clean_name = part
                break
                
        if not clean_name:
            clean_name = parts[0]
            
        return clean_name, domain
        
    return None, None

def extract_signature_from_html(html_content):
    soup = BeautifulSoup(html_content, 'html.parser')
    
    # 1. البحث بالطريقة الكلاسيكية عن وسوم الإمضاء
    sig_div = soup.find('div', class_=re.compile('gmail_signature|signature', re.I))
    if sig_div:
        clean_text = sig_div.get_text(separator='\n', strip=True)
        if len(clean_text) > 2:
            return clean_text

    text = soup.get_text(separator='\n')
    lines = [line.strip() for line in text.split('\n') if line.strip()]
    if not lines:
        return None
        
    keywords = ['regards', 'best', 'sincerely', 'thanks', 'cheers', 'مع خالص', 'تحياتي', 'مع فائق', 'regards,', 'best,', 'respectfully', 'tack', 'gracias']
    signature_lines = []
    capture = False
    lines_captured_count = 0
    
    for line in reversed(lines):
        line_lower = line.lower()
        if any(kw in line_lower for kw in keywords):
            capture = True
            signature_lines.insert(0, line)
            break
            
        if capture:
            signature_lines.insert(0, line)
            lines_captured_count += 1
            if lines_captured_count > 8:
                break
                
    # 2. لو ملقاش كلمات مفتاحية، بدل ما يرفض الإيميل، هناخد آخر أسطر كإمضاء احتياطي عشان مفيش شركة تضيع!
    if not signature_lines and len(lines) > 0:
        signature_lines = lines[-min(6, len(lines)):]
        
    return '\n'.join(signature_lines) if signature_lines else None

def harvest_all_messages(total_accounts=3):
    output_dir = 'company_signatures'
    os.makedirs(output_dir, exist_ok=True)

    processed_companies = set()
    saved_count = 0

    for i in range(1, total_accounts + 1):
        print(f"\n==========================================")
        print(f"[*] Deep Exhaustive Scan for Gmail Account #{i}")
        print(f"==========================================")
        try:
            service = get_gmail_service_for_account(i)
        except Exception as e:
            print(f"[!] Error authenticating account #{i}: {e}")
            continue
            
        # سحب كل الرسائل بدون قيود على العدد (Pagination عبر nextPageToken)
        messages = []
        request = service.users().messages().list(userId='me')
        while request is not None:
            response = request.execute()
            if 'messages' in response:
                messages.extend(response['messages'])
            request = service.users().messages().list_next(previous_request=request, previous_response=response)
            
        print(f"[*] Total messages found in Account #{i}: {len(messages)}")
        
        for msg in messages:
            try:
                txt = service.users().messages().get(userId='me', id=msg['id']).execute()
            except Exception as e:
                time.sleep(0.5)
                continue
                
            headers = txt.get('payload', {}).get('headers', [])
            sender = ""
            for header in headers:
                if header['name'] == 'From':
                    sender = header['value']
                    
            company, domain = extract_company_name(sender)
            
            if not company:
                continue

            payload = txt.get('payload', {})
            body_data = ""
            
            def parse_payload(p):
                nonlocal body_data
                if 'parts' in p:
                    for part in p['parts']:
                        parse_payload(part)
                elif p.get('mimeType') == 'text/html':
                    data = p.get('body', {}).get('data', '')
                    if data:
                        try:
                            body_data = base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
                        except Exception:
                            pass

            parse_payload(payload)
            
            if not body_data and 'body' in payload:
                data = payload['body'].get('data', '')
                if data:
                    try:
                        body_data = base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
                    except Exception:
                        pass

            if body_data:
                sig = extract_signature_from_html(body_data)
                if sig:
                    # لو الشركة دي مش موجودة أصلاً أو لو حابب نحدث ملفها القديم بمحتوى أشمل وأدق
                    file_path = os.path.join(output_dir, f"{company}.txt")
                    
                    # هنحفظ أو نحدث الملف فوراً لو فيه بيانات أفضل
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(f"Account Index: #{i}\n")
                        f.write(f"Sender: {sender}\n")
                        f.write(f"Clean Brand Name: {company}\n")
                        f.write(f"Full Domain: {domain}\n")
                        f.write("="*40 + "\n\n")
                        f.write(sig)
                        
                    if company not in processed_companies:
                        processed_companies.add(company)
                        saved_count += 1
                        print(f"  [+] Captured/Updated -> {company} (from {domain})")
            
            time.sleep(0.2)

    print(f"\n[✨] Finished Deep Scan! Total unique companies/signatures collected: {saved_count}")

if __name__ == '__main__':
    ap = argparse.ArgumentParser(description="Harvest company signatures from Gmail")
    ap.add_argument("--accounts", type=int, default=3,
                    help="number of Gmail accounts to scan (token_1..N, default 3)")
    args = ap.parse_args()
    harvest_all_messages(max(1, args.accounts))