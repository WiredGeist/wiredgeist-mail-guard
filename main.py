import os.path
import base64
import hashlib
import socket
import email
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

import file_hash_analysis
import content_analysis
from cred import vt_api_key
import ai_ward

# If modifying these scopes, delete the file token.json.
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly', 'https://www.googleapis.com/auth/gmail.modify']

def get_gmail_service():
    """Shows basic usage of the Gmail API and handles file paths correctly."""
    creds = None
    # --- START OF CHANGES ---
    # Build paths relative to the script's location
    script_dir = os.path.dirname(__file__) # The directory the script is in
    token_path = os.path.join(script_dir, 'token.json')
    credentials_path = os.path.join(script_dir, 'credentials.json')
    # --- END OF CHANGES ---

    if os.path.exists(token_path):
        creds = Credentials.from_authorized_user_file(token_path, SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            # Use the full path to credentials.json
            flow = InstalledAppFlow.from_client_secrets_file(credentials_path, SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the token to the correct path
        with open(token_path, 'w') as token:
            token.write(creds.to_json())
    return build('gmail', 'v1', credentials=creds)

def resolve_ip(domain):
    """Resolve IP address from domain."""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


def subject_analysis(subject):
    """Analyze email subject for suspicious content and return a score."""
    suspicious_terms = {
        # High-Risk - Creates urgency and fear
        'urgent action required': 5,
        'account suspended': 5,
        'security warning': 5,
        'unusual activity': 5,
        
        # Medium-Risk
        'password change': 3,
        'verify your account': 3,
        'action required': 3,
        'update needed': 3,
    }
    
    total_score = 0
    reasons_found = []

    subject_lower = subject.lower()
    for term, score in suspicious_terms.items():
        if term in subject_lower:
            total_score += score
            reasons_found.append(f"Subject contained '{term}' (Score: +{score})")

    return total_score, reasons_found

def analyze_attachment(attachment_data):
    """Analyze email attachment and return its MD5 hash."""
    decoded_attachment = base64.urlsafe_b64decode(attachment_data.encode('UTF-8'))
    return hashlib.md5(decoded_attachment).hexdigest()

def process_attachment(md5_hash, api_key):
    """Process the attachment using VirusTotal API."""
    analysis_result = file_hash_analysis.analyze_file(api_key, md5_hash)
    print(f"Attachment analysis result: {analysis_result}")

# In main.py, replace your existing process_email function with this one.

def process_email(service, msg_id, api_key):
    """
    Processes an individual email using a hybrid approach:
    1. A fast keyword-based scan.
    2. A deep AI-powered analysis.
    It then combines the scores to make a final determination.
    """
    try:
        # STAGE 1: FETCH EMAIL DATA
        # -------------------------
        message = service.users().messages().get(userId='me', id=msg_id, format='full').execute()
        payload = message.get('payload', {})
        headers = payload.get('headers', [])
        subject = next((i['value'] for i in headers if i['name'] == 'Subject'), 'No Subject')
        sender = next((i['value'] for i in headers if i['name'] == 'From'), 'Unknown Sender')

        print(f"\n-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-")
        print(f"ANALYZING EMAIL:")
        print(f"  From: {sender}")
        print(f"  Subject: {subject}")
        print(f"-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-")

        email_body = ""
        attachment_md5 = None

        if 'parts' in payload:
            for part in payload['parts']:
                if part['mimeType'] == 'text/plain' and 'data' in part['body']:
                    email_body += base64.urlsafe_b64decode(part['body']['data']).decode('utf-8', 'ignore')
                if part.get('filename'):
                    if 'data' in part['body']:
                        attachment_data = part['body']['data']
                    else:
                        att_id = part['body']['attachmentId']
                        attachment = service.users().messages().attachments().get(userId='me', messageId=msg_id, id=att_id).execute()
                        attachment_data = attachment['data']
                    attachment_md5 = analyze_attachment(attachment_data)
        elif 'data' in payload.get('body', {}):
            email_body = base64.urlsafe_b64decode(payload['body']['data']).decode('utf-8', 'ignore')

        # STAGE 2: PERFORM ANALYSIS & CALCULATE SCORE
        # ---------------------------------------------
        SUSPICION_THRESHOLD = 8  # Threshold to classify an email as suspicious

        # Get score from traditional keyword analysis
        subject_score, subject_reasons = subject_analysis(subject)
        content_score, content_reasons = content_analysis.content_analysis(email_body)
        keyword_total_score = subject_score + content_score
        all_reasons = subject_reasons + content_reasons

        # Get score from our AI model
        print(">>> Contacting AI Ward for deep analysis...")
        ai_verdict, ai_score, ai_reason = ai_ward.analyze_with_ai(subject, email_body)
        print(f">>> AI Ward Verdict: {ai_verdict} (Score: {ai_score})")
        if ai_verdict == "PHISHING":
            all_reasons.append(f"AI Reason: {ai_reason} (AI Score: +{ai_score})")

        # Combine scores for a final verdict
        total_score = keyword_total_score + ai_score

        # STAGE 3: GENERATE REPORT
        # ------------------------
        if total_score >= SUSPICION_THRESHOLD:
            print(f"\n>>> [!] SUSPICIOUS EMAIL DETECTED [!] (Total Score: {total_score})")
            print(f"    Reason(s) Found:")
            for reason in all_reasons:
                print(f"      - {reason}")
            print("------------------------------------------")
        else:
            print(f">>> [✓] Email appears safe (Total Score: {total_score}).")

        # STAGE 4: PROCESS ATTACHMENTS & CLEANUP
        # ----------------------------------------
        if attachment_md5:
            print(">>> Analyzing attachment with VirusTotal...")
            process_attachment(attachment_md5, api_key)

        # Mark the email as read so it isn't processed again
        service.users().messages().modify(userId='me', id=msg_id, body={'removeLabelIds': ['UNREAD']}).execute()
        print(">>> Analysis complete. Email marked as read.")

    except HttpError as error:
        print(f'An API error occurred while processing an email: {error}')
    except Exception as e:
        print(f"An unexpected error occurred in process_email: {e}")

def main():
    api_key = vt_api_key
    service = get_gmail_service()
    
    # List unread messages
    results = service.users().messages().list(userId='me', labelIds=['INBOX', 'UNREAD']).execute()
    messages = results.get('messages', [])

    if not messages:
        print("No unread messages found.")
    else:
        print("Processing unread messages:")
        for message in messages:
            process_email(service, message['id'], api_key)

if __name__ == '__main__':
    main()