# wiredgeist_mail_guard.py (FINAL VERSION with YOUR OLLAMA FIX)

import gradio as gr
import base64
import re
import email
import html
from email import policy
import ollama
import sys
import traceback

# Import your existing modules
from main import get_gmail_service, subject_analysis, analyze_attachment
import content_analysis
import ai_ward
import file_hash_analysis
from cred import vt_api_key
from web_utils import create_gmail_button_html
import origin_tracker
import url_analysis
import db_manager # Import the database manager

# --- 1. THEME & CSS ---
font = gr.themes.GoogleFont("Inter")
bw_theme = gr.themes.Base(font=font, primary_hue=gr.themes.colors.sky, neutral_hue=gr.themes.colors.slate).set(body_background_fill="#111111",block_background_fill="#1e1e1e",block_border_width="1px",border_color_primary="#333333",body_text_color="#EAEAEA",button_primary_background_fill="*primary_200",button_primary_text_color="#000000",block_title_text_color="*primary_200",block_label_text_color="*neutral_400",input_background_fill="#2c2c2c",)
custom_css = """#app-title { text-align: center; font-size: 3em; font-weight: 600; color: #AEC6CF; padding-bottom: 20px; margin-bottom: 20px; border-bottom: 1px solid #333; } #scan-button:hover { box-shadow: 0 0 12px 2px #AEC6CF; transform: scale(1.01); transition: all 0.2s ease-in-out; }"""

# --- 2. BACKEND FUNCTIONS ---
GMAIL_SERVICE = None
OLLAMA_HOST = "http://localhost:11434" # Define the Ollama host explicitly

def get_available_models():
    """
    Fetches the list of locally available Ollama models.
    (This is YOUR updated, robust version)
    """
    try:
        client = ollama.Client(host=OLLAMA_HOST)
        response_data = client.list()
        models_list = response_data.get('models', [])
        if not models_list:
            return ["No local models found"]
        # The key is 'model' in recent versions of the library.
        model_names = [model['model'] for model in models_list]
        return model_names or ["No local models found"]
    except Exception as e:
        print(f"CRITICAL ERROR: An exception occurred while fetching Ollama models from {OLLAMA_HOST}.", file=sys.stderr)
        traceback.print_exc() 
        return ["Error fetching models"]

def highlight_source_code(source_text, reasons):
    escaped_text = html.escape(source_text)
    keywords = [m.group(1) for r in reasons for m in [re.search(r"'(.*?)'", r)] if m]
    for keyword in set(keywords):
        try:
            escaped_text = re.sub(re.escape(keyword), lambda m: f'<mark style="background-color: #FF5733; color: white; padding: 2px; border-radius: 3px;">{m.group(0)}</mark>', escaped_text, flags=re.IGNORECASE)
        except re.error: pass
    return f"<pre style='white-space: pre-wrap; word-wrap: break-word;'>{escaped_text}</pre>"

def analyze_headers(headers_text):
    score, reasons = 0, []; header_checks = {"dmarc=fail": (10, "DMARC Failure"), "dkim=fail": (7, "DKIM Failure"), "spf=fail": (5, "SPF Failure"), "X-Spam-Flag: YES": (8, "Spam Flag Detected")}
    for keyword, (points, reason) in header_checks.items():
        if re.search(re.escape(keyword), headers_text, re.IGNORECASE): score += points; reasons.append(f"{reason} ('{keyword}') (Score: +{points})")
    return score, reasons, "\n".join(reasons) or "No suspicious headers found."

def initialize_gmail_service():
    global GMAIL_SERVICE
    if GMAIL_SERVICE is None: print("Connecting to Gmail API..."); GMAIL_SERVICE = get_gmail_service(); print("Connected.")
    return GMAIL_SERVICE

def get_body_by_mimetype(payload, mimetype):
    if payload:
        if payload.get('mimeType') == mimetype and 'body' in payload and 'data' in payload['body']: return base64.urlsafe_b64decode(payload['body']['data'].encode('ASCII')).decode('utf-8', 'ignore')
        if 'parts' in payload:
            for part in payload.get('parts', []):
                if (found_body := get_body_by_mimetype(part, mimetype)): return found_body
    return ""

def create_map_html(lat, lon):
    if isinstance(lat, (int, float)) and isinstance(lon, (int, float)):
        return f'<iframe src="https://www.google.com/maps?q={lat},{lon}&hl=en&z=10&output=embed" width="100%" height="300" style="border:0; border-radius: 8px;" allowfullscreen="" loading="lazy"></iframe>'
    return '<div style="width:100%; height:300px; display:flex; align-items:center; justify-content:center; background-color:#2c2c2c; border-radius: 8px; color: #888;">Map not available: No valid coordinates found.</div>'

def run_deeper_investigation(initial_ip, initial_domain):
    indicators_to_check = []; checked_indicators = set(); master_report = {}
    if initial_ip: indicators_to_check.append(("ip", initial_ip))
    if initial_domain: indicators_to_check.append(("domain", initial_domain))
    for _ in range(3): 
        if not indicators_to_check: break
        indicator_type, indicator_value = indicators_to_check.pop(0)
        if indicator_value in checked_indicators: continue
        checked_indicators.add(indicator_value)
        if indicator_type == "ip":
            report = origin_tracker.get_reverse_ip_report(indicator_value)
            master_report[f"Reverse IP ({indicator_value})"] = report
            found_domains = re.findall(r'- ([\w.-]+\.[a-zA-Z]{2,})', report)
            for domain in found_domains:
                if domain not in checked_indicators: indicators_to_check.append(("domain", domain))
        elif indicator_type == "domain":
            report = origin_tracker.get_domain_report(indicator_value)
            master_report[f"Domain ({indicator_value})"] = report
            found_domains = re.findall(r'- ([\w.-]+\.[a-zA-Z]{2,})', report)
            for domain in found_domains:
                if domain not in checked_indicators: indicators_to_check.append(("domain", domain))
    domain_report_final = master_report.get(f"Domain ({initial_domain})", "N/A"); reverse_ip_report_final = master_report.get(f"Reverse IP ({initial_ip})", "N/A")
    pivoted_results = [f"\n--- Pivoted Result for {key} ---\n{value}" for key, value in master_report.items() if key not in [f"Domain ({initial_domain})", f"Reverse IP ({initial_ip})"]]
    if pivoted_results: reverse_ip_report_final += "\n" + "\n".join(pivoted_results)
    return domain_report_final, reverse_ip_report_final

def perform_non_ai_analysis(sender, subject, html_content, plain_text_body, header_text, raw_source_text, attachment_report):
    text_for_analysis = plain_text_body if plain_text_body else re.sub('<[^<]+?>', ' ', html_content)
    initial_indicators = []
    sender_domain_match = re.search(r'@([\w.-]+)', sender)
    if sender_domain_match: initial_indicators.append(sender_domain_match.group(1))
    origin_ip, _ = origin_tracker.extract_origin_ip(raw_source_text)
    if origin_ip: initial_indicators.append(origin_ip)
    urls = url_analysis.extract_urls_from_html(html_content)
    initial_indicators.extend(urls)
    history_report = db_manager.check_indicator_history(list(set(initial_indicators)))
    url_report = url_analysis.generate_url_report(html_content)
    ip_analysis_result = ""; map_html = create_map_html(None, None)
    if origin_ip:
        geo_data = origin_tracker.get_geolocation(origin_ip)
        if geo_data.get('status') == 'success':
            lat, lon = geo_data.get('lat'), geo_data.get('lon')
            map_html = create_map_html(lat, lon)
            ip_analysis_result = (f"IP Address: {geo_data.get('ip', 'N/A')}\nLocation: {geo_data.get('city', 'N/A')}, {geo_data.get('region', 'N/A')}, {geo_data.get('country', 'N/A')}\n"
                              f"Coordinates: Lat: {lat}, Lon: {lon}\nISP: {geo_data.get('isp', 'N/A')}\n"
                              f"Organization: {geo_data.get('org', 'N/A')}\nAS: {geo_data.get('as', 'N/A')}")
        else: ip_analysis_result = f"IP Address: {origin_ip}\nGeolocation Failed: {geo_data.get('message')}"
    else: ip_analysis_result = "No public IP address found."
    domain_report, reverse_ip_report = run_deeper_investigation(origin_ip, sender_domain_match.group(1) if sender_domain_match else None)
    header_score, header_reasons, header_analysis_report = analyze_headers(header_text)
    subject_score, subject_reasons = subject_analysis(subject)
    content_score, content_reasons = content_analysis.content_analysis(text_for_analysis)
    keyword_analysis_report = "\n".join(subject_reasons + content_reasons) or "No suspicious keywords found."
    non_ai_score = header_score + subject_score + content_score
    analysis_data_for_ai = { "sender": sender, "subject": subject, "ip_origin_report": ip_analysis_result, "domain_report": domain_report, "reverse_ip_lookup": reverse_ip_report, "embedded_link_analysis": url_report, "header_authentication_failures": header_analysis_report, "suspicious_keyword_report": keyword_analysis_report, "email_body_text": text_for_analysis[:1000] }
    all_reasons = header_reasons + subject_reasons + content_reasons
    highlighted_source = highlight_source_code(raw_source_text, all_reasons)
    ui_results = (text_for_analysis, highlighted_source, attachment_report, url_report, ip_analysis_result, header_analysis_report, keyword_analysis_report, domain_report, reverse_ip_report)
    return ui_results, map_html, history_report, analysis_data_for_ai, non_ai_score

def run_ai_on_demand(state, model_name):
    if not state or "analysis_data" not in state: return "AI analysis cannot be run. Please perform a scan first.", ""
    analysis_data = state["analysis_data"]; non_ai_score = state.get("non_ai_score", 0)
    ai_verdict, ai_score, ai_strategic_report = ai_ward.analyze_with_ai(analysis_data, model_name)
    ai_report_text = ai_strategic_report
    total_score = non_ai_score + ai_score
    if total_score >= 8: final_verdict_md = f"<h3 style='color:#FF5733;'>[!] DANGEROUS (Score: {total_score})</h3>"
    elif 3 <= total_score < 8: final_verdict_md = f"<h3 style='color:#FFC300;'>[?] SUSPICIOUS (Score: {total_score})</h3>"
    else: final_verdict_md = f"<h3 style='color:#33FF57;'>[✓] LIKELY SAFE (Score: {total_score})</h3>"
    return ai_report_text, final_verdict_md

def scan_and_update(model_name, ai_enabled):
    try:
        service = initialize_gmail_service()
        messages = service.users().messages().list(userId='me', labelIds=['INBOX', 'UNREAD'], maxResults=1).execute().get('messages', [])
        if not messages: return get_initial_ui_values("No unread messages found.")
        msg_id = messages[0]['id']
        message_raw_obj = service.users().messages().get(userId='me', id=msg_id, format='raw').execute()
        message_full = service.users().messages().get(userId='me', id=msg_id, format='full').execute()
        raw_source_text = email.message_from_bytes(base64.urlsafe_b64decode(message_raw_obj['raw'].encode('ASCII')), policy=policy.default).as_string()
        payload = message_full.get('payload', {}); headers = payload.get('headers', [])
        header_text = "\n".join([f"{h['name']}: {h['value']}" for h in headers])
        subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), 'No Subject')
        sender = next((h['value'] for h in headers if h['name'].lower() == 'from'), 'Unknown Sender')
        plain_text_body = get_body_by_mimetype(payload, "text/plain"); html_content = get_body_by_mimetype(payload, "text/html")
        attachment_report = "No attachments found."
        ui_results, map_html, history_report, analysis_data_for_ai, non_ai_score = perform_non_ai_analysis(sender, subject, html_content, plain_text_body, header_text, raw_source_text, attachment_report)
        db_manager.log_investigation(sender, subject, analysis_data_for_ai)
        app_state_data = {"id": msg_id, "analysis_data": analysis_data_for_ai, "non_ai_score": non_ai_score}
        ai_report_text, final_verdict_md = "AI Analysis is disabled. Toggle on to run.", ""
        if ai_enabled: ai_report_text, final_verdict_md = run_ai_on_demand(app_state_data, model_name)
        service.users().messages().modify(userId='me', id=msg_id, body={'removeLabelIds': ['UNREAD']}).execute()
        open_in_gmail_btn = create_gmail_button_html(msg_id)
        return list(ui_results) + [map_html, history_report, ai_report_text, final_verdict_md, f"Scan complete for: {subject}", app_state_data, open_in_gmail_btn]
    except Exception as e:
        import traceback; traceback.print_exc()
        return get_initial_ui_values(f"An error occurred: {e}")

def get_initial_ui_values(status_message="Ready..."):
    return "", "", "N/A", "", "", "", "", "", "", "", "", "", "", status_message, None, ""

def delete_email(state):
    if not state or "id" not in state: return "No email loaded to delete."
    try: service = initialize_gmail_service(); service.users().messages().trash(userId='me', id=state["id"]).execute(); return "Email moved to trash."
    except Exception as e: return f"Error deleting email: {e}"

def move_to_spam(state):
    if not state or "id" not in state: return "No email loaded to report as spam."
    try: service = initialize_gmail_service(); service.users().messages().modify(userId='me', id=state["id"], body={'addLabelIds': ['SPAM']}).execute(); return "Email reported as spam."
    except Exception as e: return f"Error reporting spam: {e}"

# --- 3. BUILD THE GRADIO INTERFACE ---
available_models = get_available_models(); default_model = available_models[0] if "Error" not in available_models[0] else "llama3"
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
                with gr.TabItem("Email Content (Plain Text)"): email_content_box = gr.Textbox(label="Readable Email Content", interactive=False, lines=15)
                with gr.TabItem("Original Message Source"): raw_source_box = gr.HTML(label="Original Source with Suspicious Parts Highlighted")
            map_view = gr.HTML(label="Sender Location Map")
        with gr.Column(scale=1):
            history_alert_box = gr.Textbox(label="Threat History & Reputation", lines=5, interactive=False, elem_id="history-box")
            final_verdict_box = gr.Markdown(label="Final Verdict")
            open_in_gmail_button = gr.HTML()
            with gr.Accordion("AI Configuration", open=False):
                ai_toggle = gr.Checkbox(label="Enable Final AI Analysis", value=True, interactive=True)
                model_selector_dropdown = gr.Dropdown(label="Select AI Model", choices=available_models, value=default_model, interactive=True)
            attachment_analysis_box = gr.Textbox(label="Attachment Analysis", lines=3, interactive=False)
            url_analysis_box = gr.Textbox(label="Link Analysis (Top 3)", lines=5, interactive=False)
            ip_analysis_box = gr.Textbox(label="Email Origin Trace", lines=7, interactive=False)
            header_analysis_box = gr.Textbox(label="Header & Auth Analysis", lines=3, interactive=False)
            keyword_analysis_box = gr.Textbox(label="Content Keyword Analysis", lines=3, interactive=False)
            with gr.Accordion("Deeper Investigation", open=False):
                domain_report_box = gr.Textbox(label="Sender Domain Report", lines=10, interactive=False)
                reverse_ip_box = gr.Textbox(label="Reverse IP Report (Pivots)", lines=10, interactive=False)
            ai_ward_box = gr.Textbox(label="AI Strategic Assessment", lines=10, interactive=False)
            with gr.Row():
                delete_button = gr.Button("Delete Email", variant="stop"); spam_button = gr.Button("Report as Spam")
    analysis_outputs = [email_content_box, raw_source_box, attachment_analysis_box, url_analysis_box, ip_analysis_box, header_analysis_box, keyword_analysis_box, domain_report_box, reverse_ip_box]
    ai_outputs = [ai_ward_box, final_verdict_box]
    full_scan_outputs = analysis_outputs + [map_view, history_alert_box, ai_ward_box, final_verdict_box, status_textbox, app_state, open_in_gmail_button]
    scan_button.click(fn=scan_and_update, inputs=[model_selector_dropdown, ai_toggle], outputs=full_scan_outputs)
    ai_toggle.change(fn=lambda state, model, enabled: run_ai_on_demand(state, model) if enabled else ("AI Analysis is disabled.", ""), inputs=[app_state, model_selector_dropdown, ai_toggle], outputs=ai_outputs)
    delete_button.click(fn=delete_email, inputs=[app_state], outputs=[status_textbox]); spam_button.click(fn=move_to_spam, inputs=[app_state], outputs=[status_textbox])

if __name__ == "__main__":
    print("-----------------------------------------"); print("  WiredGeist Mail Guard - Starting Up"); print("-----------------------------------------")
    print("Initializing database..."); db_manager.initialize_database(); print("Database ready.")
    print("Make sure your Ollama application is running."); demo.launch()
