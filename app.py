# wiredgeist_mail_guard.py

import gradio as gr
import base64
import re
import email
import html
from email import policy
import ollama # Import ollama to list models
import sys
import traceback

# Import your existing modules
from main import get_gmail_service, subject_analysis, analyze_attachment
import content_analysis
import ai_ward
import file_hash_analysis
from cred import vt_api_key
from web_utils import create_gmail_button_html

# --- 1. THEME & CSS ---
# (This section is unchanged, so it is omitted for brevity)
font = gr.themes.GoogleFont("Inter")
bw_theme = gr.themes.Base(font=font, primary_hue=gr.themes.colors.sky, neutral_hue=gr.themes.colors.slate).set(body_background_fill="#111111",block_background_fill="#1e1e1e",block_border_width="1px",border_color_primary="#333333",body_text_color="#EAEAEA",button_primary_background_fill="*primary_200",button_primary_text_color="#000000",block_title_text_color="*primary_200",block_label_text_color="*neutral_400",input_background_fill="#2c2c2c",)
custom_css = """#app-title { text-align: center; font-size: 3em; font-weight: 600; color: #AEC6CF; padding-bottom: 20px; margin-bottom: 20px; border-bottom: 1px solid #333; } #scan-button:hover { box-shadow: 0 0 12px 2px #AEC6CF; transform: scale(1.01); transition: all 0.2s ease-in-out; }"""


# --- 2. BACKEND FUNCTIONS ---

GMAIL_SERVICE = None

# --- Define the Ollama host explicitly ---
OLLAMA_HOST = "http://localhost:11434"

def get_available_models():
    """Fetches the list of locally available Ollama models, handling the modern object-based API response."""
    try:
        client = ollama.Client(host=OLLAMA_HOST)
        response_data = client.list()
        
        models_list = response_data.get('models', [])

        if not models_list:
            return ["No local models found"]
        
        # --- THE FINAL FIX ---
        # The traceback confirms the key is not 'name'.
        # The raw output shows the attribute is 'model'.
        # We change model['name'] to model['model'].
        model_names = [model['model'] for model in models_list]

        if not model_names:
            return ["No local models found"]
            
        return model_names
        
    except Exception as e:
        print(f"CRITICAL ERROR: An exception occurred while fetching Ollama models from {OLLAMA_HOST}.", file=sys.stderr)
        traceback.print_exc() 
        return ["Error fetching models"]

def highlight_source_code(source_text, reasons):
    escaped_text = html.escape(source_text)
    keywords = []
    for reason in reasons:
        match = re.search(r"'(.*?)'", reason)
        if match: keywords.append(match.group(1))
    for keyword in set(keywords):
        try:
            escaped_text = re.sub(re.escape(keyword), lambda m: f'<mark style="background-color: #FF5733; color: white; padding: 2px; border-radius: 3px;">{m.group(0)}</mark>', escaped_text, flags=re.IGNORECASE)
        except re.error: pass
    return f"<pre style='white-space: pre-wrap; word-wrap: break-word;'>{escaped_text}</pre>"

def analyze_headers(headers_text):
    score, reasons = 0, []
    header_checks = {"dmarc=fail": (10, "DMARC Failure"),"dkim=fail": (7, "DKIM Failure"),"spf=fail": (5, "SPF Failure"),"X-Spam-Flag: YES": (8, "Spam Flag Detected")}
    for keyword, (points, reason_text) in header_checks.items():
        if re.search(re.escape(keyword), headers_text, re.IGNORECASE):
            score += points
            reasons.append(f"{reason_text} ('{keyword}') (Score: +{points})")
    return score, reasons

def initialize_gmail_service():
    global GMAIL_SERVICE
    if GMAIL_SERVICE is None:
        print("Connecting to Gmail API..."); GMAIL_SERVICE = get_gmail_service(); print("Connected.")
    return GMAIL_SERVICE

def get_body_by_mimetype(payload, mimetype):
    if payload:
        if payload.get('mimeType') == mimetype and 'body' in payload and 'data' in payload['body']:
            data = payload['body']['data']
            return base64.urlsafe_b64decode(data.encode('ASCII')).decode('utf-8', 'ignore')
        if 'parts' in payload:
            for part in payload.get('parts', []):
                found_body = get_body_by_mimetype(part, mimetype)
                if found_body: return found_body
    return ""

def perform_core_analysis(sender, subject, html_content, plain_text_body, header_text, raw_source_text, attachment_report, model_name):
    """Runs all analysis modules, now accepting a model_name for the AI."""
    text_for_analysis = plain_text_body if plain_text_body else re.sub('<[^<]+?>', ' ', html_content)

    header_score, header_reasons = analyze_headers(header_text)
    subject_score, subject_reasons = subject_analysis(subject)
    content_score, content_reasons = content_analysis.content_analysis(text_for_analysis)
    # Pass the selected model to the AI analysis function
    ai_verdict, ai_score, ai_reason = ai_ward.analyze_with_ai(sender, subject, text_for_analysis, model_name)
    
    ai_highlight_keywords = re.findall(r"'(.*?)'", ai_reason)
    ai_highlight_reasons = [f"AI identified: '{k}'" for k in ai_highlight_keywords]
    
    sender_email_match = re.search(r'<(.+?)>', sender)
    if sender_email_match and ai_verdict == "PHISHING":
        sender_email = sender_email_match.group(1)
        ai_highlight_reasons.append(f"Suspicious sender ('{sender_email}')")

    all_reasons_for_highlighting = header_reasons + subject_reasons + content_reasons + ai_highlight_reasons
    highlighted_source = highlight_source_code(raw_source_text, all_reasons_for_highlighting)

    total_score = header_score + subject_score + content_score + ai_score
    
    if total_score >= 8: final_verdict_md = f"<h3 style='color:#FF5733;'>[!] DANGEROUS (Score: {total_score})</h3>"
    elif 3 <= total_score < 8: final_verdict_md = f"<h3 style='color:#FFC300;'>[?] SUSPICIOUS (Score: {total_score})</h3>"
    else: final_verdict_md = f"<h3 style='color:#33FF57;'>[✓] LIKELY SAFE (Score: {total_score})</h3>"

    ai_report_text = f"Verdict: {ai_verdict} (Score: {ai_score})\n\n{ai_reason}"
    header_analysis_report = "\n".join(header_reasons) or "No suspicious headers found."
    keyword_analysis_report = "\n".join(subject_reasons + content_reasons) or "No suspicious keywords found."

    return text_for_analysis, highlighted_source, attachment_report, header_analysis_report, keyword_analysis_report, ai_report_text, final_verdict_md

def scan_and_update(model_name):
    """Main function for scanning, now takes model_name from the UI."""
    try:
        service = initialize_gmail_service()
        results = service.users().messages().list(userId='me', labelIds=['INBOX', 'UNREAD'], maxResults=1).execute()
        messages = results.get('messages', [])
        if not messages: return get_initial_ui_values("No unread messages found.")

        msg_id = messages[0]['id']
        message_raw_obj = service.users().messages().get(userId='me', id=msg_id, format='raw').execute()
        message_full = service.users().messages().get(userId='me', id=msg_id, format='full').execute()
        
        raw_email_data = base64.urlsafe_b64decode(message_raw_obj['raw'].encode('ASCII'))
        raw_source_text = email.message_from_bytes(raw_email_data, policy=policy.default).as_string()
        
        payload = message_full.get('payload', {})
        headers = payload.get('headers', [])
        header_text = "\n".join([f"{h['name']}: {h['value']}" for h in headers])
        subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), 'No Subject')
        sender = next((h['value'] for h in headers if h['name'].lower() == 'from'), 'Unknown Sender')
        
        plain_text_body = get_body_by_mimetype(payload, "text/plain")
        html_content = get_body_by_mimetype(payload, "text/html")

        attachment_report = "No attachments found."
        for part in payload.get('parts', []):
            if part.get('filename'):
                filename = part['filename']
                if 'data' in part['body']: attachment_data = part['body']['data']
                else: att_id = part['body']['attachmentId']; attachment = service.users().messages().attachments().get(userId='me', messageId=msg_id, id=att_id).execute(); attachment_data = attachment['data']
                md5_hash = analyze_attachment(attachment_data); vt_result = file_hash_analysis.analyze_file(vt_api_key, md5_hash)
                if isinstance(vt_result, dict) and 'tagged_count' in vt_result: attachment_report = f"FILE: {filename}\nSTATUS: Malicious ({vt_result['tagged_count']} vendors detected)"
                else: attachment_report = f"FILE: {filename}\nSTATUS: Appears safe."
                break
        
        service.users().messages().modify(userId='me', id=msg_id, body={'removeLabelIds': ['UNREAD']}).execute()
        analysis_results = perform_core_analysis(sender, subject, html_content, plain_text_body, header_text, raw_source_text, attachment_report, model_name)
        
        current_state = {"id": msg_id, "results": analysis_results}
        open_in_gmail_btn = create_gmail_button_html(msg_id)
        
        return list(analysis_results) + [f"Scan complete for: {subject}", current_state, open_in_gmail_btn]

    except Exception as e:
        import traceback; traceback.print_exc()
        return get_initial_ui_values(f"An error occurred: {e}")

def analyze_pasted_email(raw_source_text, model_name):
    """Analyzes pasted content, now takes model_name from the UI."""
    if not raw_source_text or len(raw_source_text) < 20: return get_initial_ui_values("Please paste a valid raw email source.")
    
    msg = email.message_from_string(raw_source_text, policy=policy.default)
    subject, sender = msg.get("Subject", "No Subject"), msg.get("From", "Unknown Sender")
    header_text = "\n".join([f"{k}: {v}" for k, v in msg.items()])

    html_content, plain_text_body = "", ""
    if msg.is_multipart():
        for part in msg.walk():
            ct, cs = part.get_content_type(), part.get_content_charset() or 'utf-8'
            if ct == "text/plain": plain_text_body = part.get_payload(decode=True).decode(cs, 'ignore')
            elif ct == "text/html": html_content = part.get_payload(decode=True).decode(cs, 'ignore')
    else:
        cs = msg.get_content_charset() or 'utf-8'
        plain_text_body = msg.get_payload(decode=True).decode(cs, 'ignore')
    
    attachment_report = "Attachment analysis is not available for pasted content."
    analysis_results = perform_core_analysis(sender, subject, html_content, plain_text_body, header_text, raw_source_text, attachment_report, model_name)
    
    return list(analysis_results) + ["Pasted content analyzed.", None, ""]

def restore_ui_from_state(state):
    if not state or "results" not in state:
        initial_defaults = get_initial_ui_values(); analysis_defaults = initial_defaults[:7]; status_default = initial_defaults[7]; button_default = initial_defaults[9]; return analysis_defaults + (status_default, button_default)
    msg_id, results = state.get("id"), state.get("results", [])
    open_in_gmail_btn = create_gmail_button_html(msg_id)
    return list(results) + ["Session restored.", open_in_gmail_btn]

def get_initial_ui_values(status_message="Ready..."):
    return "", "", "N/A", "N/A", "N/A", "", "", status_message, None, ""

def delete_email(state):
    if not state or "id" not in state: return "No email loaded to delete."
    try: service = initialize_gmail_service(); service.users().messages().trash(userId='me', id=state["id"]).execute(); return "Email moved to trash."
    except Exception as e: return f"Error deleting email: {e}"

def move_to_spam(state):
    if not state or "id" not in state: return "No email loaded to report as spam."
    try: service = initialize_gmail_service(); service.users().messages().modify(userId='me', id=state["id"], body={'addLabelIds': ['SPAM']}).execute(); return "Email reported as spam."
    except Exception as e: return f"Error reporting spam: {e}"

# --- 3. BUILD THE GRADIO INTERFACE ---

# Fetch the list of available models when the app starts
available_models = get_available_models()
default_model = available_models[0] if "Error" not in available_models[0] else "llama3"

with gr.Blocks(theme=bw_theme, css=custom_css, title="WiredGeist Mail Guard") as demo:
    app_state = gr.State(value=None)
    gr.Markdown("# WiredGeist Mail Guard", elem_id="app-title")
    
    with gr.Row():
        with gr.Column(scale=2):
            with gr.Tabs():
                with gr.TabItem("Action"):
                    gr.Markdown("### Scan your latest unread email from your inbox.")
                    scan_button = gr.Button("Scan Inbox", variant="primary", elem_id="scan-button")
                    status_textbox = gr.Textbox(label="Status", interactive=False, placeholder="Ready...")
                with gr.TabItem("Manual Paste"):
                    pasted_email_input = gr.Textbox(label="Paste Raw Email Source Here", lines=10, placeholder="...")
                    analyze_pasted_button = gr.Button("Analyze Pasted Content", variant="secondary")
            
            with gr.Tabs():
                with gr.TabItem("Email Content (Plain Text)"): email_content_box = gr.Textbox(label="Readable Email Content", interactive=False, lines=25)
                with gr.TabItem("Original Message Source"): raw_source_box = gr.HTML(label="Original Source with Suspicious Parts Highlighted")

        with gr.Column(scale=1):
            final_verdict_box = gr.Markdown(label="Final Verdict")
            open_in_gmail_button = gr.HTML()
            attachment_analysis_box = gr.Textbox(label="Attachment Analysis", lines=4, interactive=False)
            header_analysis_box = gr.Textbox(label="Header & Auth Analysis", lines=4, interactive=False)
            keyword_analysis_box = gr.Textbox(label="Content Keyword Analysis", lines=4, interactive=False)
            ai_ward_box = gr.Textbox(label="AI Ward Analysis", lines=4, interactive=False)
            
            # ** NEW: AI Model Selector Dropdown **
            model_selector_dropdown = gr.Dropdown(
                label="Select AI Model",
                choices=available_models,
                value=default_model,
                interactive=True
            )
            
            with gr.Row():
                delete_button = gr.Button("Delete Email", variant="stop")
                spam_button = gr.Button("Report as Spam")

    analysis_outputs = [email_content_box, raw_source_box, attachment_analysis_box, header_analysis_box, keyword_analysis_box, ai_ward_box, final_verdict_box]
    full_scan_outputs = analysis_outputs + [status_textbox, app_state, open_in_gmail_button]
    load_outputs = analysis_outputs + [status_textbox, open_in_gmail_button]

    # Event Wiring - now passing the dropdown value as an input
    scan_button.click(fn=scan_and_update, inputs=[model_selector_dropdown], outputs=full_scan_outputs)
    analyze_pasted_button.click(fn=analyze_pasted_email, inputs=[pasted_email_input, model_selector_dropdown], outputs=full_scan_outputs)
    demo.load(fn=restore_ui_from_state, inputs=[app_state], outputs=load_outputs)
    delete_button.click(fn=delete_email, inputs=[app_state], outputs=[status_textbox])
    spam_button.click(fn=move_to_spam, inputs=[app_state], outputs=[status_textbox])

if __name__ == "__main__":
    print("-----------------------------------------")
    print("  WiredGeist Mail Guard - Starting Up")
    print("-----------------------------------------")
    print("Make sure your Ollama application is running.")
    demo.launch()