# Import necessary libraries
import imaplib
import email
import re
import os
import time
import json
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, Response
import requests
from concurrent.futures import ThreadPoolExecutor
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch
from datetime import timedelta
import ssl

# Initialize Flask application
import logging
app = Flask(__name__)
app.secret_key = os.urandom(24)  
app.permanent_session_lifetime = timedelta(hours=1)  
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Strict'
)

def validate_credentials(email_addr, password):
    try:
        mail = imaplib.IMAP4_SSL("imap.gmail.com")
        mail.login(email_addr, password)
        mail.logout()
        return True
    except imaplib.IMAP4.error:
        return False
    
def initialize_phishing_model(model_path="phishing_model"):
    """
    Initialize the phishing detection model and tokenizer
    Returns the loaded model and tokenizer for reuse
    """
    tokenizer = AutoTokenizer.from_pretrained(model_path)
    model = AutoModelForSequenceClassification.from_pretrained(model_path)
    model.eval()
    return model, tokenizer

model, tokenizer = initialize_phishing_model()

def fetch_emails(page=1, emails_per_page=8, last_uid=None):
    """
    Fetch emails from Gmail inbox with pagination or check for new emails
    Args:
        page (int): Current page number for pagination
        emails_per_page (int): Number of emails to show per page
        last_uid (str): UID of the most recent email to check for newer emails
    Returns:
        tuple: (list of email dictionaries, latest UID)
    """
    email_addr = session.get('email')
    app_password = session.get('app_password')
    if not email_addr or not app_password:
        raise ValueError("Email or app password not set. Please log in.")

    emails = []
    
    mail = imaplib.IMAP4_SSL("imap.gmail.com")
    mail.login(email_addr, app_password)
    mail.select("inbox")

    status, messages = mail.uid('SEARCH', None, "ALL")
    email_uids = messages[0].split()
    latest_uid = email_uids[-1].decode() if email_uids else None

    if last_uid:
        # Check for emails newer than last_uid
        if email_uids and last_uid.encode() in email_uids:
            last_idx = email_uids.index(last_uid.encode())
            target_uids = email_uids[last_idx + 1:]  # Emails after last_uid
        else:
            target_uids = email_uids  # If last_uid not found, fetch all
    else:
        # Paginated fetch for initial load
        start_idx = max(0, len(email_uids) - (page * emails_per_page))
        end_idx = max(0, len(email_uids) - ((page - 1) * emails_per_page))
        target_uids = email_uids[start_idx:end_idx]

    for uid in target_uids:
        status, msg_data = mail.uid('FETCH', uid, "(RFC822)")
        
        for response_part in msg_data:
            if isinstance(response_part, tuple):
                msg = email.message_from_bytes(response_part[1])
                
                date = msg["date"]
                from_addr = msg["from"]
                subject = msg["subject"]

                body = ""
                if msg.is_multipart():
                    for part in msg.walk():
                        if (part.get_content_type() == "text/plain" and 
                            "attachment" not in str(part.get("Content-Disposition", ""))):
                            body = _decode_payload(part)
                            break
                else:
                    body = _decode_payload(msg)

                url_pattern = r"https?://[^\s]+"
                urls = re.findall(url_pattern, body)
                clean_body = body.strip()
                for url in urls:
                    clean_body = clean_body.replace(url, "(LINK)")

                emails.append({
                    "uid": uid.decode(),
                    "date": date,
                    "from": from_addr,
                    "subject": subject,
                    "message": clean_body
                })

    emails.reverse()
    mail.logout()
    return emails, latest_uid

def _decode_payload(part):
    """Helper function to decode email payload"""
    try:
        payload = part.get_payload(decode=True)
        return payload.decode() if payload else "Unable to decode message body"
    except:
        return "Unable to decode message body"

@app.route('/', methods=['GET', 'POST'])
def login():
    session.permanent = True
    
    if request.method == 'POST':
        email_addr = request.form.get('Email')
        app_password = request.form.get('APP_PASSWORD')
        
        if email_addr and app_password:
            print(f"Email: {email_addr}, APP_PASSWORD: {app_password}")
            if validate_credentials(email_addr, app_password):
                session['email'] = email_addr
                session['app_password'] = app_password
                session['logged_in'] = True
                return redirect(url_for('display_emails'))
            else:
                return render_template('index.html', error="Invalid credentials. Please try again.")
        else:
            return render_template('index.html', error="Please provide both email and password.")
    
    return render_template('index.html', error=None)

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('email', None)
    session.pop('app_password', None)
    session.pop('logged_in', None)
    session.pop('latest_uid', None)
    return redirect(url_for('login'))

@app.route('/inbox', methods=['GET', 'POST'])
def display_emails():
    if not session.get('logged_in') or not session.get('email') or not session.get('app_password'):
        return redirect(url_for('login'))

    if request.method == 'POST':
        if 'action' in request.form:
            current_page = int(request.form.get('current_page', 1))
            action = request.form.get('action')
            if action == 'next':
                current_page += 1
            elif action == 'prev' and current_page > 1:
                current_page -= 1
        elif 'uid' in request.form:
            uid = request.form.get('uid')
            current_page = int(request.form.get('current_page', 1))
            if 'open_email_button' in request.form:
                return redirect(url_for('view_email', uid=uid, page=current_page))
            elif 'scan_button' in request.form:
                return redirect(url_for('scan_email', uid=uid, page=current_page))
        else:
            current_page = 1
    else:
        current_page = int(request.args.get('page', 1))
    current_page = max(1, current_page)
    
    try:
        email_data, latest_uid = fetch_emails(current_page)
        session['latest_uid'] = latest_uid  # Store latest UID for streaming
    except ValueError as e:
        return redirect(url_for('login'))
    
    return render_template('inbox.html', emails=email_data, current_page=current_page, latest_uid=latest_uid)

@app.route('/stream_emails')
def stream_emails():
    if not session.get('logged_in') or not session.get('email') or not session.get('app_password'):
        return Response(json.dumps({"error": "User not logged in"}), status=401, mimetype='application/json')

    def generate():
        last_uid = session.get('latest_uid')
        while True:
            try:
                new_emails, latest_uid = fetch_emails(last_uid=last_uid)
                if new_emails:
                    session['latest_uid'] = latest_uid
                    data = {
                        "new_emails": new_emails,
                        "latest_uid": latest_uid
                    }
                    yield f"data: {json.dumps(data)}\n\n"
                else:
                    yield f"data: {json.dumps({'new_emails': [], 'latest_uid': last_uid})}\n\n"
                last_uid = latest_uid
                time.sleep(10)  # Check every 10 seconds
            except ValueError as e:
                yield f"data: {json.dumps({'error': str(e)})}\n\n"
                break
            except Exception as e:
                print(f"Error in stream_emails: {e}")
                yield f"data: {json.dumps({'error': 'Internal server error'})}\n\n"
                time.sleep(10)

    return Response(generate(), mimetype='text/event-stream')

@app.route('/view_email/<uid>', methods=['GET'])
def view_email(uid):
    if not session.get('logged_in') or not session.get('email') or not session.get('app_password'):
        return redirect(url_for('login'))

    mail = imaplib.IMAP4_SSL("imap.gmail.com")
    mail.login(session['email'], session['app_password'])
    mail.select("inbox")

    status, msg_data = mail.uid('FETCH', uid, "(RFC822)")
    email_data = {"uid": uid}
    
    for response_part in msg_data:
        if isinstance(response_part, tuple):
            msg = email.message_from_bytes(response_part[1])
            email_data["date"] = msg["date"]
            email_data["from"] = msg["from"]
            email_data["subject"] = msg["subject"]

            body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    if (part.get_content_type() == "text/plain" and 
                        "attachment" not in str(part.get("Content-Disposition", ""))):
                        body = _decode_payload(part)
                        break
            else:
                body = _decode_payload(msg)

            url_pattern = r"https?://[^\s]+"
            urls = re.findall(url_pattern, body)
            clean_body = body.strip()
            for url in urls:
                clean_body = clean_body.replace(url, f'<a href="{url}" target="_blank" class="email-link">(LINK)</a>')

            email_data["content"] = clean_body

    mail.logout()
    page = request.args.get('page', 1)
    return render_template('viewemail.html', email=email_data, current_page=page)

API_KEYS = ["PUT VIRUST TOTAL API KEYS HERE",""]

def GetEmailData(uid):
    try:
        mail = imaplib.IMAP4_SSL("imap.gmail.com")
        mail.login(session['email'], session['app_password'])
        mail.select("inbox")

        status, msg_data = mail.uid('FETCH', uid.encode(), '(RFC822)')
        if status != "OK":
            print(f"Failed to fetch email with UID {uid}")
            return None

        for response_part in msg_data:
            if isinstance(response_part, tuple):
                msg = email.message_from_bytes(response_part[1])

                from_addr = msg["from"]
                subject = msg["subject"]

                body = ""
                if msg.is_multipart():
                    for part in msg.walk():
                        if (part.get_content_type() == "text/plain" and 
                            "attachment" not in str(part.get("Content-Disposition", ""))):
                            try:
                                payload = part.get_payload(decode=True)
                                if payload:
                                    body = payload.decode(errors='replace')
                                else:
                                    body = "Unable to decode message body"
                            except Exception as part_error:
                                body = "Unable to decode message body"
                                print(f"Part decode error for UID {uid}: {part_error}")
                            break
                else:
                    try:
                        payload = msg.get_payload(decode=True)
                        if payload:
                            body = payload.decode(errors='replace')
                        else:
                            body = "Unable to decode message body"
                    except Exception as payload_error:
                        body = "Unable to decode message body"
                        print(f"Payload decode error for UID {uid}: {payload_error}")

                # Ensure body is a string before processing
                if not isinstance(body, str):
                    body = "Unable to decode message body"

                url_pattern = r"https?://[^\s]+"
                urls = re.findall(url_pattern, body)
                clean_body = body.strip()
                for url in urls:
                    clean_body = clean_body.replace(url, "(LINK)")

                return {
                    "from": from_addr,
                    "subject": subject,
                    "body": clean_body,
                    "links": urls
                }
                
        return None
        
    except imaplib.IMAP4.error as imap_error:
        print(f"IMAP error for UID {uid}: {imap_error}")
        return None
    except Exception as e:
        print(f"Unexpected error for UID {uid}: {e}")
        return None
    finally:
        try:
            mail.logout()
        except:
            pass

def scan_url_list(url_list):
    def submit_url(url, headers, scan_url):
        try:
            response = requests.post(scan_url, headers=headers, data={"url": url}, timeout=5)
            if response.status_code == 200:
                return response.json()["data"]["id"]
            return None
        except Exception:
            return None

    def check_result(analysis_id, headers, result_url_base):
        try:
            response = requests.get(f"{result_url_base}{analysis_id}", headers=headers, timeout=5)
            result = response.json()
            if result["data"]["attributes"]["status"] == "completed":
                stats = result["data"]["attributes"]["stats"]
                return stats["malicious"] > 0 or stats["suspicious"] > 0
            return None
        except Exception:
            return None

    def scan_batch(urls, api_key):
        headers = {
            "x-apikey": api_key,
            "accept": "application/json",
            "content-type": "application/x-www-form-urlencoded"
        }
        scan_url = "https://www.virustotal.com/api/v3/urls"
        result_url_base = "https://www.virustotal.com/api/v3/analyses/"
        batch_size = 4
        
        analysis_ids = {}
        with ThreadPoolExecutor(max_workers=batch_size) as executor:
            for i in range(0, len(urls), batch_size):
                batch = urls[i:i + batch_size]
                future_to_url = {executor.submit(submit_url, url, headers, scan_url): url for url in batch}
                for future in future_to_url:
                    url = future_to_url[future]
                    analysis_id = future.result()
                    if analysis_id:
                        analysis_ids[url] = analysis_id
                if i + batch_size < len(urls):
                    time.sleep(1)
        
        start_time = time.time()
        pending_ids = analysis_ids.copy()
        
        while pending_ids and (time.time() - start_time) < 20:
            with ThreadPoolExecutor(max_workers=batch_size) as executor:
                future_to_id = {
                    executor.submit(check_result, aid, headers, result_url_base): url 
                    for url, aid in pending_ids.items()
                }
                for future in future_to_id:
                    url = future_to_id[future]
                    result = future.result()
                    if result is not None:
                        if result:
                            return False
                        del pending_ids[url]
            time.sleep(1)
        
        return True if not pending_ids else False

    mid_point = len(url_list) // 2
    first_half = url_list[:mid_point]
    second_half = url_list[mid_point:]
    
    with ThreadPoolExecutor(max_workers=2) as executor:
        future1 = executor.submit(scan_batch, first_half, API_KEYS[0])
        future2 = executor.submit(scan_batch, second_half, API_KEYS[1])
        result1 = future1.result()
        result2 = future2.result()
    
    return "ALL SAFE" if result1 and result2 else "NOT SAFE"

def scan_domain(email_addr):
    api_keys = API_KEYS
    email_pattern = r'@([\w.-]+\.\w+)'
    match = re.search(email_pattern, email_addr)
    
    if not match:
        return "NO VALID DOMAIN FOUND"
    
    domain = match.group(1)
    results = []
    
    def check_domain(domain, api_key):
        headers = {"x-apikey": api_key, "accept": "application/json"}
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        
        try:
            response = requests.get(url, headers=headers, timeout=5)
            if response.status_code == 200:
                result = response.json()
                stats = result["data"]["attributes"]["last_analysis_stats"]
                vendor_results = result["data"]["attributes"]["last_analysis_results"]
                
                # Exclude Gridinsoft from malicious count
                gridinsoft_malicious = 0
                if "Gridinsoft" in vendor_results and vendor_results["Gridinsoft"]["category"] == "malicious":
                    gridinsoft_malicious = 1
                
                # Adjusted malicious count excluding Gridinsoft
                adjusted_malicious = stats["malicious"] - gridinsoft_malicious
                is_malicious = adjusted_malicious > 0
                
                # Print adjusted stats for clarity
                print(f"VirusTotal stats for domain {domain} with API key {api_key[:4]}... (excluding Gridinsoft): "
                      f"malicious={adjusted_malicious}, harmless={stats['harmless']}, "
                      f"suspicious={stats['suspicious']}, undetected={stats['undetected']}, timeout={stats['timeout']}")
                
                return {"domain": domain, "safe": not is_malicious, "stats": stats}
            print(f"VirusTotal error for domain {domain} with API key {api_key[:4]}...: Status code {response.status_code}")
            return {
                "domain": domain,
                "safe": True,
                "stats": None,
                "error": f"Status code: {response.status_code}"
            }
        except Exception as e:
            print(f"VirusTotal exception for domain {domain} with API key {api_key[:4]}...: {str(e)}")
            return {"domain": domain, "safe": True, "stats": None, "error": str(e)}

    with ThreadPoolExecutor(max_workers=2) as executor:
        future1 = executor.submit(check_domain, domain, api_keys[0])
        future2 = executor.submit(check_domain, domain, api_keys[1])
        
        results.append(future1.result())
        results.append(future2.result())
    
    return "ALL SAFE" if all(result["safe"] for result in results) else "NOT SAFE"

def scan_text(model, tokenizer, text_content, confidence_threshold=0.2):
    def clean_text(text):
        if not isinstance(text, str):
            return ""
        text = re.sub(r"http\S+|www.\S+", "", text)
        text = re.sub(r"[^a-zA-Z0-9\s]", "", text)
        return text.lower().strip()

    cleaned_text = clean_text(text_content)
    
    inputs = tokenizer(cleaned_text, return_tensors="pt", truncation=True, padding=True, max_length=512)
    
    with torch.no_grad():
        outputs = model(**inputs)
        logits = outputs.logits
        probabilities = torch.softmax(logits, dim=1)
    
    phishing_prob = probabilities[0][1].item()
    
    classification = "PHISHING" if phishing_prob >= confidence_threshold else "Normal"
    
    return {
        "text": cleaned_text,
        "phishing_probability": phishing_prob,
        "classification": classification
    }

def ScanByID(ID):
    if not session.get('email') or not session.get('app_password'):
        return "Error: User not logged in"

    Email = GetEmailData(ID)
    if not Email:
        return "Error: Failed to fetch email data"
    
    body_words = Email["body"].split() if isinstance(Email["body"], str) else []
    if len(body_words) <= 1:
        return "SAFE"
    
    domain_result = scan_domain(Email["from"])
    links_result = scan_url_list(Email["links"]) if Email["links"] else "ALL SAFE"
    body_result = scan_text(model, tokenizer, Email["body"])
    phishing_prob = body_result["phishing_probability"]

    print(domain_result, links_result, body_result)

    if (phishing_prob < 0.35 and 
        domain_result == "ALL SAFE" and 
        links_result == "ALL SAFE"):
        return "SAFE"
    
    elif(phishing_prob < 0.35 and ((domain_result == "NOT SAFE" and links_result == "ALL SAFE") or
        (domain_result == "ALL SAFE" and links_result == "NOT SAFE"))):
        reason = []
        if domain_result == "NOT SAFE":
            reason.append("untrusted domain")
        elif links_result == "NOT SAFE":
            reason.append("malicious URL")
        return f"SUSPICIOUS⚠️ (Reason: No phishing detected in content, but flagged due to {', '.join(reason)}."

    elif (0.35 <= phishing_prob < 0.7 and
        (domain_result == "NOT SAFE" and links_result == "ALL SAFE") or
        (domain_result == "ALL SAFE" and links_result == "NOT SAFE")):
        reason = []
        if domain_result == "NOT SAFE":
            reason.append("untrusted domain")
        elif links_result == "NOT SAFE":
            reason.append("malicious URL")
        elif domain_result == "NOT SAFE" and links_result == "NOT SAFE":
            reason.append("malicious URL and untrusted domain")
        return f"SUSPICIOUS (Reason: the email contain {', '.join(reason)})"

    elif (phishing_prob >= 0.7 or 
        (domain_result == "NOT SAFE" and links_result == "NOT SAFE") or 
        (phishing_prob >= 0.5 and (domain_result == "NOT SAFE" or links_result == "NOT SAFE"))):
        return "PHISHING EMAIL"

    return "SUSPICIOUS (Reason: potential phishing)"

@app.route('/scanemail/<uid>', methods=['GET'])
def scan_email(uid):
    if not session.get('logged_in') or not session.get('email') or not session.get('app_password'):
        return redirect(url_for('login'))

    mail = imaplib.IMAP4_SSL("imap.gmail.com")
    mail.login(session['email'], session['app_password'])
    mail.select("inbox")

    status, msg_data = mail.uid('FETCH', uid, "(RFC822)")
    email_data = {"uid": uid}
    
    for response_part in msg_data:
        if isinstance(response_part, tuple):
            msg = email.message_from_bytes(response_part[1])
            email_data["date"] = msg["date"]
            
            from_header = msg["from"]
            email_match = re.search(r'<([^>]+)>', from_header)
            if email_match:
                email_data["from"] = email_match.group(1)
            else:
                email_data["from"] = from_header
            
            email_data["subject"] = msg["subject"]
    
    mail.logout()
    page = request.args.get('page', 1)
    return render_template('scanemail.html', 
                        email_id=uid,
                        email_from=email_data["from"],
                        email_subject=email_data["subject"],
                        current_page=page)

@app.route('/get_scan_result/<uid>', methods=['GET'])
def get_scan_result(uid):
    if not session.get('logged_in') or not session.get('email') or not session.get('app_password'):
        return jsonify({"error": "User not logged in"}), 401

    result = ScanByID(uid)
    if result.startswith("Error"):
        return jsonify({"error": result}), 500

    # Move email to spam if result is not SAFE
    if result != "SAFE":
        try:
            mail = imaplib.IMAP4_SSL("imap.gmail.com")
            mail.login(session['email'], session['app_password'])
            mail.select("inbox")

            # Copy email to [Gmail]/Spam
            status, data = mail.uid('COPY', uid, '[Gmail]/Spam')
            if status == 'OK':
                # Mark email for deletion in inbox
                status, data = mail.uid('STORE', uid, '+FLAGS', '\\Deleted')
                if status == 'OK':
                    # Expunge to permanently delete from inbox
                    mail.expunge()
                    print(f"Email UID {uid} moved to spam and deleted from inbox")
                else:
                    print(f"Failed to delete email UID {uid} from inbox")
            else:
                print(f"Failed to copy email UID {uid} to spam")
            mail.logout()
        except imaplib.IMAP4.error as e:
            print(f"IMAP error while moving email UID {uid} to spam: {e}")
            return jsonify({"error": "Failed to move email to spam", "result": result}), 500
        except Exception as e:
            print(f"Unexpected error while moving email UID {uid} to spam: {e}")
            return jsonify({"error": "Unexpected error moving email to spam", "result": result}), 500

    return jsonify({"result": result})

# Utility route to check session status
@app.route('/keep_alive', methods=['GET'])
def keep_alive():
    if session.get('logged_in') and session.get('email') and session.get('app_password'):
        return jsonify({"status": "Session alive"}), 200
    return jsonify({"error": "Not logged in"}), 401

# Route to fetch the latest email UID for streaming
@app.route('/get_latest_uid')
def get_latest_uid():
    if not session.get('logged_in') or not session.get('email') or not session.get('app_password'):
        return jsonify({"error": "Not logged in"}), 401

    try:
        _, latest_uid = fetch_emails(page=1, emails_per_page=1)  # Just get latest UID
        return jsonify({"latest_uid": latest_uid})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
# Application entry point
if __name__ == '__main__':
    # Configure SSL context
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    
    # Point to your mkcert-generated files
    cert_file = '127.0.0.1+2.pem'  # or whatever name mkcert generated
    key_file = '127.0.0.1+2-key.pem'
    
    # Verify files exist
    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        raise FileNotFoundError(f"Certificate files missing. Run 'mkcert 127.0.0.1' first.")
    
    context.load_cert_chain(cert_file, key_file)
    
    # Security enhancements
    context.set_ciphers('HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP')
    context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
    
    # Run application with HTTPS
    app.run(
        host='127.0.0.1',
        port=5000,
        ssl_context=context,
        debug=True
    )