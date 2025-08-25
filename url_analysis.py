# url_analysis.py

import re
import requests
import time
from cred import vt_api_key

def extract_urls_from_html(html_content: str):
    """
    Finds all unique http and https links in a block of HTML.
    
    Args:
        html_content: The HTML body of the email.
        
    Returns:
        A list of unique URLs found.
    """
    if not html_content:
        return []
    
    # This regex finds URLs starting with http:// or https://
    # It's designed to capture the full URL until a quote, space, or angle bracket.
    urls = re.findall(r'https?://[^\s"<>]+', html_content)
    
    # Return a list of unique URLs to avoid scanning the same link multiple times
    return list(set(urls))

def analyze_single_url_with_virustotal(api_key: str, url_to_scan: str):
    """
    Submits a single URL to VirusTotal for scanning and retrieves the report.
    NOTE: The free VirusTotal API has a rate limit (e.g., 4 requests per minute).
    
    Args:
        api_key: Your VirusTotal API key.
        url_to_scan: The URL to analyze.
        
    Returns:
        A dictionary with the scan result.
    """
    try:
        # Step 1: Submit the URL to VirusTotal for analysis.
        # This tells VT to scan the URL if it hasn't been scanned recently.
        submit_url_endpoint = "https://www.virustotal.com/api/v3/urls"
        headers = {"x-apikey": api_key}
        payload = {"url": url_to_scan}
        
        response = requests.post(submit_url_endpoint, data=payload, headers=headers)
        response.raise_for_status()
        
        analysis_id = response.json()['data']['id']
        
        # Step 2: Retrieve the analysis report using the ID from Step 1.
        report_url_endpoint = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        
        # IMPORTANT: We need to wait for the analysis to complete.
        # This pause is crucial. 20 seconds is a safe bet for most URLs.
        time.sleep(20)
        
        report_response = requests.get(report_url_endpoint, headers=headers)
        report_response.raise_for_status()
        
        report_data = report_response.json()
        stats = report_data['data']['attributes']['stats']
        malicious_vendors = stats.get('malicious', 0)
        suspicious_vendors = stats.get('suspicious', 0)
        
        return {
            "status": "success",
            "malicious_count": malicious_vendors,
            "suspicious_count": suspicious_vendors,
            "url": url_to_scan
        }
        
    except requests.exceptions.RequestException as e:
        print(f"VirusTotal API Error for URL {url_to_scan}: {e}")
        return {"status": "fail", "message": f"API Error", "url": url_to_scan}

def generate_url_report(html_body: str):
    """
    The main function that orchestrates the URL analysis process.
    
    Args:
        html_body: The HTML content of the email.
        
    Returns:
        A formatted string report of the URL analysis.
    """
    urls = extract_urls_from_html(html_body)
    
    if not urls:
        return "No links found in the email body."
        
    # Limit to the first 3 URLs to respect API limits and keep scan times reasonable.
    urls_to_scan = urls[:3]
    
    report_lines = []
    for url in urls_to_scan:
        # To avoid making the URL too long in the display, we truncate it.
        display_url = (url[:70] + '...') if len(url) > 73 else url
        result = analyze_single_url_with_virustotal(vt_api_key, url)
        
        if result['status'] == 'success':
            malicious_count = result.get('malicious_count', 0)
            suspicious_count = result.get('suspicious_count', 0)
            
            if malicious_count > 0:
                report_lines.append(f"🔴 DANGEROUS ({malicious_count} vendors): {display_url}")
            elif suspicious_count > 0:
                report_lines.append(f"🟡 SUSPICIOUS ({suspicious_count} vendors): {display_url}")
            else:
                report_lines.append(f"🟢 LIKELY SAFE (0 vendors): {display_url}")
        else:
            report_lines.append(f"⚪️ SCAN ERROR: {display_url}")
            
    if len(urls) > 3:
        report_lines.append(f"\n...and {len(urls) - 3} more links (not scanned).")
        
    return "\n".join(report_lines)
