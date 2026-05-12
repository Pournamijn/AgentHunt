import re
import json
import requests
import os
from datetime import datetime
from email.parser import Parser
from email import policy

GROK_API_URL = "https://api.groq.com/openai/v1/chat/completions"
GROK_MODEL = "llama-3.3-70b-versatile"

# ── ML + NLP engine (graceful fallback if deps missing) ───────────────────
try:
    from ml_engine import analyze_with_ml_nlp
    ML_ENGINE_ACTIVE = True
except ImportError:
    ML_ENGINE_ACTIVE = False
    def analyze_with_ml_nlp(*args, **kwargs):
        return {"ml": {"ml_score": -1, "ml_available": False},
                "nlp": {"nlp_score": 0}, "combined_score": 0, "top_signals": []}


def fetch_api_credential():
    """
    Retrieve Groq API credential from environment.
    Returns: Cleaned API key string
    """
    api_credential = "" #groq api key 
    return api_credential.strip().strip('"').strip("'")


TRUSTED_DOMAINS_SET = {
    "google.com", "microsoft.com", "amazon.com",
    "github.com", "linkedin.com", "apple.com",
    "paypal.com", "chase.com", "wellsfargo.com",
    "accounts.google.com", "mail.google.com",
    "youtube.com", "support.google.com"
}

THREAT_INDICATORS = [
    "urgent", "verify", "suspended", "click here",
    "act now", "limited time", "your account", "confirm your",
    "password expired", "unusual activity", "win a prize",
    "congratulations you", "free gift"
]

RISK_TLD_SET = [".xyz", ".top", ".tk", ".ml", ".cf", ".gq", ".pw"]

URL_THREAT_SIGNATURES = {
    "ip_addr": r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
    "encoded_url": r'%[0-9a-fA-F]{2}',
    "port_obfuscation": r':\d{4,5}',
    "subdomain_spoofing": r'[^.]*(?:google|amazon|apple|microsoft|paypal)[^.]*\.[^/]+',
    "credential_path": r'(login|signin|auth|password|verify|account)',
}


def get_domain_from_string(email_or_url: str) -> str:
    
    email_match = re.search(r'@([\w.-]+)', email_or_url)
    if email_match:
        return email_match.group(1).lower()
    
    url_match = re.search(r'https?://([^/]+)', email_or_url)
    return url_match.group(1).lower() if url_match else ""


def decode_headers(raw_headers: str) -> dict:
    
    try:
        parsed_msg = Parser(policy=policy.default).parsestr(raw_headers)
    except Exception:
        return {}
    
    auth_results = str(parsed_msg.get("Authentication-Results", "")).lower()
    
    def check_auth(auth_type):
        if f"{auth_type}=pass" in auth_results:
            return "pass"
        if f"{auth_type}=fail" in auth_results:
            return "fail"
        return "unknown"
    
    return {
        "from": str(parsed_msg.get("From", "")),
        "reply_to": str(parsed_msg.get("Reply-To", "")),
        "return_path": str(parsed_msg.get("Return-Path", "")),
        "subject": str(parsed_msg.get("Subject", "")),
        "spf": check_auth("spf"),
        "dkim": check_auth("dkim"),
        "dmarc": check_auth("dmarc"),
    }


def extract_message_content(email_body_text: str) -> dict:
    
    found_urls = list(set(re.findall(r'https?://[^\s<>"\']+', email_body_text)))
    
    return {
        "text": email_body_text,
        "urls": found_urls[:10],
        "attachments": []
    }


def scan_url_threats(url: str) -> dict:
   
    threat_indicators = {
        "raw_ip_detected": False,
        "encoded_chars": False,
        "port_obfuscation": False,
        "subdomain_spoofing": False,
        "credential_keywords": False,
        "suspicious_tld": False,
        "detected_patterns": []
    }
    
    if re.search(URL_THREAT_SIGNATURES["ip_addr"], url):
        threat_indicators["raw_ip_detected"] = True
        threat_indicators["detected_patterns"].append("Raw IP address in URL")
    
    if re.search(URL_THREAT_SIGNATURES["encoded_url"], url):
        threat_indicators["encoded_chars"] = True
        threat_indicators["detected_patterns"].append("URL-encoded characters")
    
    if re.search(URL_THREAT_SIGNATURES["port_obfuscation"], url):
        threat_indicators["port_obfuscation"] = True
        threat_indicators["detected_patterns"].append("Non-standard port usage")
    
    if re.search(URL_THREAT_SIGNATURES["subdomain_spoofing"], url):
        threat_indicators["subdomain_spoofing"] = True
        threat_indicators["detected_patterns"].append("Potential brand spoofing in subdomain")
    
    if re.search(URL_THREAT_SIGNATURES["credential_path"], url, re.IGNORECASE):
        threat_indicators["credential_keywords"] = True
        threat_indicators["detected_patterns"].append("Credential keywords in URL path")
    
    if any(risky_tld in url for risky_tld in RISK_TLD_SET):
        threat_indicators["suspicious_tld"] = True
        threat_indicators["detected_patterns"].append("Risky TLD detected")
    
    return threat_indicators


def calculate_heuristic_risk(headers: dict, body: dict, sender: str) -> dict:
    
    risk_score = 0
    detected_flags = []
    sender_domain = get_domain_from_string(sender)

    if any(sender_domain.endswith(tld) for tld in RISK_TLD_SET):
        risk_score += 25
        detected_flags.append(f"Risky TLD in sender domain")

    if sender_domain not in TRUSTED_DOMAINS_SET:
        for trusted_domain in TRUSTED_DOMAINS_SET:
            base_name = trusted_domain.split(".")[0]
            is_typo = base_name in sender_domain and sender_domain != trusted_domain and not sender_domain.endswith("." + trusted_domain)
            if is_typo:
                risk_score += 30
                detected_flags.append(f"Possible typosquat of {trusted_domain}")
                break

    if headers.get("spf") == "fail":
        risk_score += 20
        detected_flags.append("SPF authentication failed")
    
    if headers.get("dkim") == "fail":
        risk_score += 20
        detected_flags.append("DKIM authentication failed")

    reply_to_domain = get_domain_from_string(headers.get("reply_to", ""))
    from_domain = get_domain_from_string(headers.get("from", ""))
    if reply_to_domain and from_domain and reply_to_domain != from_domain:
        risk_score += 15
        detected_flags.append("Reply-To domain differs from From domain")

    email_text_lower = body.get("text", "").lower()
    matched_keywords = [kw for kw in THREAT_INDICATORS if kw in email_text_lower]
    if matched_keywords:
        risk_score += min(25, len(matched_keywords) * 5)
        detected_flags.append(f"Threat keywords: {', '.join(matched_keywords[:4])}")

    for url in body.get("urls", []):
        if any(tld in url for tld in RISK_TLD_SET):
            risk_score += 20
            detected_flags.append("Risky URL TLD in body")
            break
        
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
            risk_score += 20
            detected_flags.append("Raw IP address in URL")
            break
        
        url_threat_check = scan_url_threats(url)
        if url_threat_check["detected_patterns"]:
            risk_score += min(15, len(url_threat_check["detected_patterns"]) * 3)
            detected_flags.append(f"URL threat pattern: {url_threat_check['detected_patterns'][0]}")

    return {
        "score": min(risk_score, 100),
        "flags": detected_flags
    }


def grok_analyze(sender: str, subject: str, body_text: str, heuristic: dict) -> dict:
    
    api_credential = fetch_api_credential()

    if not api_credential:
        return fallback_assessment(heuristic, "Missing GROQ_API_KEY — get one free at console.groq.com")

    print(f"[AI] Groq key: {api_credential[:12]}... (len={len(api_credential)})")

    prompt = f"""You are a cybersecurity expert analyzing a potentially malicious email.
Return ONLY a valid JSON object, no markdown, no explanation outside JSON.

From: {sender}
Subject: {subject}
Body (first 1500 chars): {body_text[:1500]}

Heuristic score: {heuristic['score']}/100
Heuristic flags: {heuristic['flags']}

Return exactly this JSON:
{{
  "risk_score": <integer 0-100>,
  "verdict": "<Phishing|Suspicious|Legitimate>",
  "confidence": "<High|Medium|Low>",
  "reasoning": "<2-3 sentence explanation>",
  "attack_type": "<Credential Harvesting|BEC|Malware|Advance Fee|Brand Impersonation|Spam|None|Unknown>",
  "suggested_action": "<Block & Report|Quarantine|Manual Review|Safe to Ignore>",
  "red_flags": ["<flag1>", "<flag2>", "<flag3>"]
}}"""

    try:
        api_response = requests.post(
            GROK_API_URL,
            headers={
                "Authorization": f"Bearer {api_credential}",
                "Content-Type": "application/json"
            },
            json={
                "model": GROK_MODEL,
                "max_tokens": 600,
                "temperature": 0.1,
                "messages": [
                    {"role": "system", "content": "You are a cybersecurity expert. Always respond with valid JSON only."},
                    {"role": "user", "content": prompt}
                ]
            },
            timeout=20
        )

        print(f"[AI] HTTP status: {api_response.status_code}")

        if api_response.status_code != 200:
            print(f"[AI] Error: {api_response.text[:300]}")
            return fallback_assessment(heuristic, f"Groq API HTTP {api_response.status_code}: {api_response.text[:100]}")

        response_data = api_response.json()
        ai_response_text = response_data["choices"][0]["message"]["content"].strip()
        print(f"[AI] Raw: {ai_response_text[:200]}")

       
        cleaned_response = re.sub(r"```json|```", "", ai_response_text).strip()
        parsed_response = json.loads(cleaned_response)

       
        if "red_flags" not in parsed_response or not isinstance(parsed_response["red_flags"], list):
            parsed_response["red_flags"] = heuristic.get("flags", [])

        return parsed_response

    except json.JSONDecodeError as json_error:
        print(f"[AI] JSON error: {json_error}")
        return fallback_assessment(heuristic, f"JSON parse error: {json_error}")
    except Exception as general_error:
        print(f"[AI] Exception: {general_error}")
        return fallback_assessment(heuristic, str(general_error))


def scan_single_url(url: str) -> dict:
    
    api_credential = fetch_api_credential()
    detected_flags = []
    base_risk = 0

    # ── ML-based URL analysis (primary) ──────────────────────────────────
    from ml_engine import ml_evaluate_url as _ml_evaluate_url
    ml_url_result = _ml_evaluate_url(url)
    ml_url_score  = ml_url_result.get("ml_score", -1)
    if ml_url_score >= 0:
        base_risk = ml_url_score
        ml_indicators = ml_url_result.get("features", {})
        # Translate high-signal features to human-readable flags
        if ml_indicators.get("suspicious_tld", 0) > 0.5:
            detected_flags.append("Risky TLD detected")
        if ml_indicators.get("raw_ip_address", 0) > 0.5:
            detected_flags.append("Raw IP address in URL")
        if ml_indicators.get("brand_spoofing", 0) > 0.5:
            detected_flags.append("Brand name spoofing")
        if ml_indicators.get("credential_keywords", 0) > 0.5:
            detected_flags.append("Credential keywords in path")
        if ml_indicators.get("known_phishing_domain", 0) > 0.5:
            detected_flags.append("Matches known malicious domain")
        if ml_indicators.get("url_shortener", 0) > 0.5:
            detected_flags.append("URL shortener service")
    else:
        # Fallback heuristics
        for risky_tld in RISK_TLD_SET:
            if risky_tld in url:
                base_risk += 40
                detected_flags.append(f"Risky TLD: {risky_tld}")
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
            base_risk += 35
            detected_flags.append("Raw IP in URL")
        url_threat_patterns = scan_url_threats(url)
        if url_threat_patterns["detected_patterns"]:
            base_risk += 20
            detected_flags.extend(url_threat_patterns["detected_patterns"][:2])

    if not api_credential:
        verdict = "Malicious" if base_risk >= 70 else "Suspicious" if base_risk >= 40 else "Likely Safe"
        return {
            "url": url,
            "risk_score": min(base_risk, 100),
            "verdict": verdict,
            "confidence": ml_url_result.get("ml_confidence", "Low"),
            "reasoning": f"ML URL classifier score: {base_risk}/100",
            "flags": detected_flags,
            "ml_url": ml_url_result,
        }

    prompt = f"""Analyze this URL for malicious indicators. Return ONLY valid JSON.

URL: {url}

{{
  "risk_score": <0-100>,
  "verdict": "<Malicious|Suspicious|Likely Safe>",
  "confidence": "<High|Medium|Low>",
  "reasoning": "<1-2 sentences>",
  "flags": ["<flag1>", "<flag2>"]
}}"""

    try:
        api_response = requests.post(
            GROK_API_URL,
            headers={
                "Authorization": f"Bearer {api_credential}",
                "Content-Type": "application/json"
            },
            json={
                "model": GROK_MODEL,
                "max_tokens": 300,
                "temperature": 0.1,
                "messages": [
                    {"role": "system", "content": "You are a cybersecurity expert. Respond with valid JSON only."},
                    {"role": "user", "content": prompt}
                ]
            },
            timeout=15
        )
        
        response_data = api_response.json()
        ai_response_text = response_data["choices"][0]["message"]["content"].strip()
        cleaned_response = re.sub(r"```json|```", "", ai_response_text).strip()
        parsed_result = json.loads(cleaned_response)
        parsed_result["url"] = url
        return parsed_result
        
    except Exception as error:
        return {
            "url": url,
            "risk_score": 50,
            "verdict": "Unknown",
            "confidence": "Low",
            "reasoning": f"Analysis failed: {error}",
            "flags": detected_flags
        }


def fallback_assessment(heuristic: dict, error_message: str = "AI failed") -> dict:
    
    risk_score = heuristic["score"]
    if risk_score > 60:
        verdict = "Phishing"
    elif risk_score > 30:
        verdict = "Suspicious"
    else:
        verdict = "Legitimate"
    
    return {
        "risk_score": risk_score,
        "verdict": verdict,
        "confidence": "Low",
        "reasoning": f"AI unavailable ({error_message}). Heuristic analysis only.",
        "attack_type": "Unknown",
        "suggested_action": "Manual Review",
        "red_flags": heuristic.get("flags", [])
    }


def analyze_email_message(sender="", subject="", body_text="", headers_raw=""):

    parsed_headers = decode_headers(headers_raw)
    parsed_body    = extract_message_content(body_text)

    # Layer 1: Rule-based heuristics
    heuristic_analysis = calculate_heuristic_risk(parsed_headers, parsed_body, sender)

    # Layer 2: ML + NLP analysis
    ml_nlp_result = analyze_with_ml_nlp(
        subject=subject,
        body=body_text,
        sender=sender,
        urls=parsed_body["urls"],
    )

    # Layer 3: Grok AI analysis
    ai_analysis = grok_analyze(sender, subject, body_text, heuristic_analysis)

    # Blend scores: heuristic 30% + ML/NLP 35% + Grok AI 35%
    heuristic_val = heuristic_analysis["score"]
    ml_nlp_val    = ml_nlp_result["combined_score"]
    ai_val        = ai_analysis.get("risk_score", heuristic_val)

    if ML_ENGINE_ACTIVE and ml_nlp_result["ml"]["ml_available"]:
        blended = round(heuristic_val * 0.30 + ml_nlp_val * 0.35 + ai_val * 0.35)
    else:
        blended = round(heuristic_val * 0.40 + ai_val * 0.60)

    blended = min(100, blended)

    return {
        "timestamp":     datetime.now().isoformat(),
        "sender":        sender,
        "subject":       subject,
        "urls":          parsed_body["urls"],
        "heuristic":     heuristic_analysis,
        "ml_nlp":        ml_nlp_result,
        "ai_analysis":   ai_analysis,
        "final_score":   blended,
        "final_verdict": ai_analysis.get("verdict", "Unknown"),
    }


if __name__ == "__main__":
    api_credential = fetch_api_credential()
    print("Groq key:", api_credential[:12] + "..." if api_credential else "NOT SET — get one at console.groq.com")
    
    demo_result = analyze_email_message(
        sender="security@paypa1-alerts.xyz",
        subject="URGENT: Verify your account now",
        body_text="Click here immediately: http://fake-login.xyz/paypal"
    )
    
    print(json.dumps(demo_result, indent=2))