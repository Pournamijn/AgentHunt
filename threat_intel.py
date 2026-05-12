import os
import re
import json
import socket
import hashlib
import requests
import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import Optional
from pathlib import Path

try:
    import whois as whois_lib
    WHOIS_ACTIVE = True
except ImportError:
    WHOIS_ACTIVE = False

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

BLACKLIST_FILE = Path(__file__).parent / "malicious_domains.txt"

# Built-in malicious domain database
KNOWN_MALICIOUS_DOMAINS = {
    "paypa1.com", "paypal-secure.net", "amaz0n-deals.com",
    "micros0ft.com", "apple-id-verify.com", "irs-refund.org",
    "netflix-billing.info", "lottery-win.net", "bank-alert.com",
    "secure-login-verify.com", "account-suspended-alert.com",
    "chasebankk.com", "wells-farg0.com", "citibank-alert.net",
}

URL_THREAT_PATTERNS = {
    "raw_ip_pattern": r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
    "encoded_chars_pattern": r'%[0-9a-fA-F]{2}',
    "suspicious_port_pattern": r':\d{4,5}',
    "brand_spoofing_pattern": r'[^.]*(?:google|amazon|apple|microsoft|paypal|facebook)[^.]*\.[^/]+',
    "credential_keywords_pattern": r'(login|signin|auth|password|verify|account|reset|confirm)',
    "hex_encoding_pattern": r'[0-9a-f]{8,}',
}

URL_REDIRECT_PATTERNS = {
    "excessive_redirects": r'redirect|redir|jump|go\.php',
    "obfuscated_domain": r'[0-9]{3}\.[0-9]{3}\.[0-9]{3}\.[0-9]{3}',
    "shortened_url_service": r'(bit\.ly|tinyurl|short\.link|goo\.gl)',
    "suspicious_extensions": r'\.(php|asp|jsp|cgi)',
    "data_exfil_keywords": r'(collect|gather|extract|send|transmit)',
}


def extract_domain(input_value: str) -> str:
    """
    Extract domain from email address or URL.
    
    Args:
        input_value: Email address or URL string
        
    Returns:
        Domain name in lowercase
    """
    cleaned = input_value.strip()
    
    # Try extracting from email format (user@domain.com)
    if "@" in cleaned:
        domain_part = cleaned.split("@")[-1]
        return domain_part.lower()
    
    # Try extracting from URL format (https://domain.com/path)
    if cleaned.startswith("http"):
        parsed_url = urlparse(cleaned)
        return parsed_url.netloc.lower().lstrip("www.")
    
    return cleaned.lower()


def resolve_host_to_ip(hostname: str) -> Optional[str]:
    """
    Resolve hostname to IP address.
    
    Args:
        hostname: Domain to resolve
        
    Returns:
        IP address if successful, None otherwise
    """
    try:
        resolved = socket.gethostbyname(hostname)
        return resolved
    except Exception:
        return None


def load_domain_blacklist() -> set:
    """
    Load blacklisted domains from local file and built-in list.
    
    Returns:
        Set of blacklisted domains
    """
    blacklist = set(KNOWN_MALICIOUS_DOMAINS)
    
    # Load from external file if it exists
    if BLACKLIST_FILE.exists():
        with open(BLACKLIST_FILE) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    blacklist.add(line.lower())
    
    return blacklist


def analyze_url_threats(url: str) -> dict:
    """
    Analyze URL for threat characteristics and suspicious patterns.
    
    Args:
        url: URL to analyze
        
    Returns:
        Dictionary with detected threat characteristics
    """
    threat_chars = {
        "has_raw_ip": False,
        "has_encoded_chars": False,
        "has_suspicious_port": False,
        "has_brand_spoofing": False,
        "has_credential_keywords": False,
        "has_hex_encoding": False,
        "suspicious_indicators": [],
        "threat_risk_level": "low"
    }
    
    # Check for raw IP address
    if re.search(URL_THREAT_PATTERNS["raw_ip_pattern"], url):
        threat_chars["has_raw_ip"] = True
        threat_chars["suspicious_indicators"].append("Uses IP address instead of domain")
    
    # Check for URL-encoded characters
    if re.search(URL_THREAT_PATTERNS["encoded_chars_pattern"], url):
        threat_chars["has_encoded_chars"] = True
        threat_chars["suspicious_indicators"].append("Contains URL-encoded characters")
    
    # Check for suspicious port numbers
    if re.search(URL_THREAT_PATTERNS["suspicious_port_pattern"], url):
        threat_chars["has_suspicious_port"] = True
        threat_chars["suspicious_indicators"].append("Uses non-standard port")
    
    # Check for brand name spoofing in subdomains
    if re.search(URL_THREAT_PATTERNS["brand_spoofing_pattern"], url):
        threat_chars["has_brand_spoofing"] = True
        threat_chars["suspicious_indicators"].append("Brand name in subdomain")
    
    # Check for credential-related keywords
    if re.search(URL_THREAT_PATTERNS["credential_keywords_pattern"], url, re.IGNORECASE):
        threat_chars["has_credential_keywords"] = True
        threat_chars["suspicious_indicators"].append("Credential-related keywords in URL")
    
    # Check for hex encoding
    if re.search(URL_THREAT_PATTERNS["hex_encoding_pattern"], url):
        threat_chars["has_hex_encoding"] = True
        threat_chars["suspicious_indicators"].append("Hex-encoded domain segments")
    
    # Check for other URL threat patterns
    for pattern_name, pattern in URL_REDIRECT_PATTERNS.items():
        if re.search(pattern, url, re.IGNORECASE):
            threat_chars["suspicious_indicators"].append(f"Detected: {pattern_name}")
    
    # Calculate risk level
    indicator_count = len(threat_chars["suspicious_indicators"])
    if indicator_count >= 4:
        threat_chars["threat_risk_level"] = "critical"
    elif indicator_count >= 2:
        threat_chars["threat_risk_level"] = "high"
    elif indicator_count >= 1:
        threat_chars["threat_risk_level"] = "medium"
    
    return threat_chars


def query_phishtank(url: str) -> dict:
    """
    Check URL against PhishTank community database.
    
    Args:
        url: URL to check
        
    Returns:
        PhishTank check result
    """
    result = {
        "source": "PhishTank",
        "is_phishing": False,
        "details": ""
    }
    
    if not url.startswith("http"):
        return result
    
    try:
        response = requests.post(
            "https://checkurl.phishtank.com/checkurl/",
            data={
                "url": url,
                "format": "json",
            },
            headers={"User-Agent": "ThreatScanner/1.0"},
            timeout=10,
        )
        
        data = response.json()
        in_db = data.get("results", {}).get("in_database", False)
        verified = data.get("results", {}).get("valid", False)
        
        result["is_phishing"] = in_db and verified
        result["details"] = f"in_database={in_db}, verified={verified}"
        
    except Exception as e:
        result["details"] = f"PhishTank unavailable: {e}"
    
    return result


def query_virustotal(domain: str) -> dict:
    """
    Query VirusTotal for domain reputation.
    
    Args:
        domain: Domain to check
        
    Returns:
        VirusTotal check result
    """
    result = {
        "source": "VirusTotal",
        "detections": 0,
        "total": 0,
        "malicious": False,
        "details": "",
    }
    
    if not VT_API_KEY:
        result["details"] = "No VIRUSTOTAL_API_KEY set"
        return result
    
    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": VT_API_KEY},
            timeout=10,
        )
        
        if response.status_code == 200:
            stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values())
            
            result["detections"] = malicious + suspicious
            result["total"] = total
            result["malicious"] = (malicious + suspicious) > 2
            result["details"] = f"{malicious} malicious, {suspicious} suspicious out of {total} engines"
        else:
            result["details"] = f"VT API status {response.status_code}"
            
    except Exception as e:
        result["details"] = f"VirusTotal error: {e}"
    
    return result


def query_abuseipdb(ip_address: str) -> dict:
    """
    Check IP address against AbuseIPDB.
    
    Args:
        ip_address: IP address to check
        
    Returns:
        AbuseIPDB check result
    """
    result = {
        "source": "AbuseIPDB",
        "abuse_score": 0,
        "total_reports": 0,
        "is_abusive": False,
        "details": "",
    }
    
    if not ABUSEIPDB_API_KEY:
        result["details"] = "No ABUSEIPDB_API_KEY set"
        return result
    
    try:
        ipaddress.ip_address(ip_address)
        
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={
                "ipAddress": ip_address,
                "maxAgeInDays": 90
            },
            headers={
                "Key": ABUSEIPDB_API_KEY,
                "Accept": "application/json"
            },
            timeout=10,
        )
        
        if response.status_code == 200:
            data = response.json().get("data", {})
            
            score = data.get("abuseConfidenceScore", 0)
            reports = data.get("totalReports", 0)
            
            result["abuse_score"] = score
            result["total_reports"] = reports
            result["is_abusive"] = score > 25
            result["details"] = f"Abuse confidence: {score}%, reports: {reports}"
        else:
            result["details"] = f"AbuseIPDB status {response.status_code}"
            
    except ValueError:
        result["details"] = "Not a valid IP address"
    except Exception as e:
        result["details"] = f"AbuseIPDB error: {e}"
    
    return result


def check_domain_registration_age(domain: str) -> dict:
    """
    Check domain registration age using WHOIS.
    
    Args:
        domain: Domain to check
        
    Returns:
        Domain age information
    """
    result = {
        "source": "WHOIS",
        "age_days": None,
        "is_newly_registered": False,
        "created_date": None,
        "details": "",
    }
    
    if not WHOIS_ACTIVE:
        result["details"] = "python-whois not installed (pip install python-whois)"
        return result
    
    try:
        whois_data = whois_lib.whois(domain)
        creation_date = whois_data.creation_date
        
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        if creation_date:
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=timezone.utc)
            
            days_old = (datetime.now(timezone.utc) - creation_date).days
            
            result["age_days"] = days_old
            result["created_date"] = creation_date.strftime("%Y-%m-%d")
            result["is_newly_registered"] = days_old < 30
            result["details"] = f"Domain registered {days_old} days ago"
            
    except Exception as e:
        result["details"] = f"WHOIS lookup failed: {e}"
    
    return result


def check_local_blacklist(domain: str) -> dict:
    """
    Check domain against local blacklist.
    
    Args:
        domain: Domain to check
        
    Returns:
        Local blacklist result
    """
    blacklist = load_domain_blacklist()
    
    if domain in blacklist:
        return {
            "source": "LocalBlacklist",
            "blacklisted": True,
            "matched_entry": domain
        }
    
    for entry in blacklist:
        if entry in domain:
            return {
                "source": "LocalBlacklist",
                "blacklisted": True,
                "matched_entry": entry
            }
    
    return {
        "source": "LocalBlacklist",
        "blacklisted": False,
        "matched_entry": None
    }


def assess_sender_reputation(sender: str, urls_in_body: list = None) -> dict:
    """
    Comprehensive threat intelligence check for sender and URLs.
    
    Args:
        sender: Sender email address
        urls_in_body: List of URLs found in email body
        
    Returns:
        Consolidated threat intelligence report
    """
    sender_domain = extract_domain(sender)
    resolved_ip = resolve_host_to_ip(sender_domain)
    urls_in_body = urls_in_body or []
    threat_flags = []
    intel_results = {}

    # ── 1. Local Domain Blacklist Check ──
    blacklist_result = check_local_blacklist(sender_domain)
    intel_results["local_blacklist"] = blacklist_result
    
    if blacklist_result["blacklisted"]:
        threat_flags.append(f"Domain on local blacklist (matched: {blacklist_result['matched_entry']})")

    # ── 2. Domain Age / WHOIS Check ──
    whois_result = check_domain_registration_age(sender_domain)
    intel_results["whois"] = whois_result
    
    if whois_result.get("is_newly_registered"):
        threat_flags.append(f"Domain registered only {whois_result['age_days']} days ago")

    # ── 3. VirusTotal Reputation ──
    vt_result = query_virustotal(sender_domain)
    intel_results["virustotal"] = vt_result
    
    if vt_result.get("malicious"):
        threat_flags.append(f"VirusTotal: {vt_result['detections']} engines flagged as malicious")

    # ── 4. AbuseIPDB Check (if IP resolved) ──
    if resolved_ip:
        abuse_result = query_abuseipdb(resolved_ip)
        intel_results["abuseipdb"] = abuse_result
        
        if abuse_result.get("is_abusive"):
            threat_flags.append(f"AbuseIPDB: IP {resolved_ip} has abuse score {abuse_result['abuse_score']}%")
    else:
        intel_results["abuseipdb"] = {"details": "Could not resolve IP"}

    # ── 5. PhishTank Check (first URL) ──
    if urls_in_body:
        phishtank_result = query_phishtank(urls_in_body[0])
        intel_results["phishtank"] = phishtank_result
        
        if phishtank_result.get("is_phishing"):
            threat_flags.append(f"PhishTank confirmed malicious URL: {urls_in_body[0]}")
    else:
        intel_results["phishtank"] = {"details": "No URLs to check"}

    # ── 6. URL Threat Characteristics ──
    url_threat_analysis = []
    for url in urls_in_body[:3]:
        url_chars = analyze_url_threats(url)
        url_threat_analysis.append({
            "url": url,
            "analysis": url_chars
        })
        
        if url_chars["suspicious_indicators"]:
            threat_flags.append(f"URL threat pattern: {url_chars['suspicious_indicators'][0]}")

    intel_results["url_threat_analysis"] = url_threat_analysis

    # ── Aggregate Results ──
    is_blacklisted = (
        blacklist_result["blacklisted"] or
        vt_result.get("malicious", False) or
        (resolved_ip and intel_results.get("abuseipdb", {}).get("is_abusive", False))
    )
    
    vt_detection_count = vt_result.get("detections", 0)
    abuse_report_count = intel_results.get("abuseipdb", {}).get("total_reports", 0)
    domain_age = whois_result.get("age_days")

    return {
        "sender_domain": sender_domain,
        "resolved_ip": resolved_ip,
        "is_domain_blacklisted": is_blacklisted,
        "vt_detection_count": vt_detection_count,
        "abuseipdb_report_count": abuse_report_count,
        "domain_age_days": domain_age,
        "detected_threat_flags": threat_flags,
        "detailed_results": intel_results,
    }


if __name__ == "__main__":
    import sys
    
    target = sys.argv[1] if len(sys.argv) > 1 else "security@paypa1-alerts.com"
    print(f"\n Checking threat intelligence for: {target}\n")
    
    report = assess_sender_reputation(target)
    print(json.dumps(report, indent=2, default=str))