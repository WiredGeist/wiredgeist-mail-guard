# origin_tracker.py

import re
import email
from email import policy
import requests
from cred import vt_api_key # Important: Make sure this is imported

def extract_origin_ip(raw_email_source: str):
    """
    Parses the raw email source to find the most likely origin IP address.
    It works by reading the 'Received:' headers from the bottom up.
    """
    try:
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        msg = email.message_from_string(raw_email_source, policy=policy.default)
        received_headers = msg.get_all('Received', [])
        
        if not received_headers:
            return (None, "No 'Received' headers found in the email.")

        for header in reversed(received_headers):
            found_ips = ip_pattern.findall(header)
            for ip in found_ips:
                is_private = (ip.startswith(('10.', '172.', '192.168.')) or
                              ip.startswith('127.') or ip.startswith('169.254.') or
                              ip == '0.0.0.0')
                if not is_private:
                    return (ip, "Origin IP Found")
        return (None, "No public IP address could be identified in the headers.")
    except Exception as e:
        return (None, f"An error occurred during parsing: {e}")

def get_geolocation(ip_address: str):
    """
    Uses the free ip-api.com service to get the location of an IP address.
    """
    if not ip_address:
        return {"status": "fail", "message": "No IP address provided."}

    url = f"http://ip-api.com/json/{ip_address}?fields=status,message,country,regionName,city,lat,lon,isp,org,as,query"
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        data = response.json()
        
        if data.get('status') == 'success':
            return {
                "status": "success", "ip": data.get('query', 'N/A'),
                "country": data.get('country', 'N/A'), "region": data.get('regionName', 'N/A'),
                "city": data.get('city', 'N/A'), "lat": data.get('lat', 'N/A'),
                "lon": data.get('lon', 'N/A'), "isp": data.get('isp', 'N/A'),
                "org": data.get('org', 'N/A'), "as": data.get('as', 'N/A')
            }
        else:
            return {"status": "fail", "message": data.get('message', 'API returned a failure status.')}
    except requests.exceptions.RequestException as e:
        return {"status": "fail", "message": f"API request error: {e}"}

# --- NEW INVESTIGATION FUNCTIONS ---

def get_reverse_ip_report(ip_address: str):
    """
    Performs a reverse IP lookup using the VirusTotal API to find domains
    hosted on the same IP address (Passive DNS).
    """
    if not ip_address:
        return "No IP address to investigate."
    
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}/resolutions"
    headers = {"x-apikey": vt_api_key}
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json().get('data', [])
        
        if not data:
            return "No other domains found hosted on this IP."

        domains = [item['attributes']['host_name'] for item in data[:5]]
        
        report = "Other domains recently seen on this IP:\n" + "\n".join(f"- {d}" for d in domains)
        if len(data) > 5:
            report += f"\n...and {len(data) - 5} more."
        return report
    except requests.exceptions.RequestException:
        return "Reverse IP Lookup Failed: API Error or rate limit exceeded."

def get_domain_report(domain: str):
    """
    Retrieves a report for a domain from VirusTotal, focusing on creation date
    and SSL certificate relationships.
    """
    if not domain:
        return "No domain to investigate."
        
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": vt_api_key}
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 404:
            return "Domain not found in VirusTotal database (itself a potential red flag)."
            
        response.raise_for_status()
        attributes = response.json().get('data', {}).get('attributes', {})
        
        creation_date = attributes.get('creation_date')
        if creation_date:
            from datetime import datetime
            age = (datetime.now() - datetime.fromtimestamp(creation_date)).days
            age_report = f"Domain created {age} days ago."
        else:
            age_report = "Domain age is unknown."

        certs = attributes.get('last_https_certificate', {}).get('extensions', {}).get('subject_alternative_name', [])
        related_domains = [d for d in certs if d != domain and not d.startswith('*.')][:5]
        
        if related_domains:
            related_report = "Related domains found via SSL cert:\n" + "\n".join(f"- {d}" for d in related_domains)
        else:
            related_report = "No related domains found via SSL."
            
        return f"{age_report}\n\n{related_report}"
    except requests.exceptions.RequestException:
        return "Domain report failed: API Error or rate limit exceeded."
