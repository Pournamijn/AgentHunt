from flask import Flask, request, jsonify
from analyzer import analyze_email_message, scan_single_url
from threat_intel import assess_sender_reputation
from flask_cors import CORS

app = Flask(__name__)
CORS(app)


@app.route("/health", methods=["GET"])
def health_check():
    """
    Health check endpoint for server status.
    
    Returns:
        JSON with status and version information
    """
    return jsonify({
        "status": "operational",
        "version": "1.1.0",
        "service": "Threat Detection Service"
    })


@app.route("/analyze", methods=["POST"])
def analyze_email_endpoint():
    """
    Main endpoint: Analyze email for threats.
    
    Combines:
    - Email header/body parsing
    - Heuristic risk scoring
    - AI-powered analysis (Groq)
    - Threat intelligence checks
    
    Expected JSON:
    {
        "sender": "attacker@evil.com",
        "subject": "Verify your account",
        "body": "Click here to verify...",
        "headers": "From: ...\nTo: ..."
    }
    
    Returns:
        JSON with comprehensive threat analysis
    """
    try:
        request_data = request.json
        if not request_data:
            return jsonify({"error": "No data received"}), 400

        sender = request_data.get("sender", "")
        subject = request_data.get("subject", "")
        body = request_data.get("body", "")
        headers = request_data.get("headers", "")

        # ── Step 1: Analyze email content ──
        analysis = analyze_email_message(
            sender=sender,
            subject=subject,
            body_text=body,
            headers_raw=headers
        )

        # ── Step 2: Run threat intelligence checks ──
        try:
            intel_report = assess_sender_reputation(
                sender,
                urls_in_body=analysis.get("urls", [])
            )
            
            analysis["threat_intel"] = {
                "is_domain_blacklisted": intel_report.get("is_domain_blacklisted"),
                "vt_detections": intel_report.get("vt_detection_count", 0),
                "abuseipdb_reports": intel_report.get("abuseipdb_report_count", 0),
                "domain_age_days": intel_report.get("domain_age_days"),
                "flags": intel_report.get("detected_threat_flags", [])
            }

            # ── Step 3: Boost score based on threat intelligence ──
            score_boost = 0
            
            if intel_report.get("is_domain_blacklisted"):
                score_boost += 30
            
            if intel_report.get("vt_detection_count", 0) > 2:
                score_boost += 20
            
            domain_age = intel_report.get("domain_age_days")
            if domain_age is not None and domain_age < 30:
                score_boost += 15

            analysis["final_score"] = min(100, analysis["final_score"] + score_boost)
            
        except Exception as intel_error:
            analysis["threat_intel"] = {
                "error": str(intel_error),
                "flags": []
            }

        # Attach ML/NLP summary to top-level result
        ml_nlp = analysis.get("ml_nlp", {})
        url_analysis = ml_nlp.get("url_analysis", {})
        analysis["ml_summary"] = {
            "ml_score":           ml_nlp.get("ml", {}).get("ml_score", -1),
            "ml_confidence":      ml_nlp.get("ml", {}).get("ml_confidence", "unavailable"),
            "ml_available":       ml_nlp.get("ml", {}).get("ml_available", False),
            "nlp_score":          ml_nlp.get("nlp", {}).get("nlp_score", 0),
            "combined_score":     ml_nlp.get("combined_score", 0),
            "top_signals":        ml_nlp.get("top_signals", []),
            "urgency_score":      ml_nlp.get("nlp", {}).get("urgency", {}).get("score", 0),
            "deception_score":    ml_nlp.get("nlp", {}).get("deception", {}).get("score", 0),
            "impersonation_score":ml_nlp.get("nlp", {}).get("impersonation", {}).get("score", 0),
            "brands_detected":    ml_nlp.get("nlp", {}).get("impersonation", {}).get("brands_detected", []),
            "readability":        ml_nlp.get("nlp", {}).get("readability", {}),
            "sentiment":          ml_nlp.get("nlp", {}).get("sentiment", {}),
            "url_analysis": {
                "url_count":       url_analysis.get("url_count", 0),
                "malicious_count": url_analysis.get("malicious_count", 0),
                "suspicious_count":url_analysis.get("suspicious_count", 0),
                "aggregate_score": url_analysis.get("aggregate_score", 0),
                "results":         url_analysis.get("results", []),
            },
        }

        return jsonify({"result": analysis})

    except Exception as err:
        return jsonify({
            "error": "Backend analysis failed",
            "details": str(err)
        }), 500


@app.route("/scan-url", methods=["POST"])
def scan_url_endpoint():
    """
    Endpoint: Scan a single URL for malicious characteristics.
    
    Expected JSON:
    {
        "url": "http://malicious-site.xyz/login"
    }
    
    Returns:
        JSON with URL threat assessment
    """
    try:
        request_data = request.json
        if not request_data or not request_data.get("url"):
            return jsonify({"error": "No URL provided"}), 400

        target_url = request_data["url"]

        # ── Step 1: Analyze URL with AI ──
        url_analysis = scan_single_url(target_url)

        # ── Step 2: Run threat intelligence on domain ──
        try:
            intel_report = assess_sender_reputation(
                target_url,
                urls_in_body=[target_url]
            )
            
            score_boost = 0
            
            if intel_report.get("is_domain_blacklisted"):
                score_boost += 30
            
            if intel_report.get("vt_detection_count", 0) > 2:
                score_boost += 20
            
            url_analysis["risk_score"] = min(100, url_analysis.get("risk_score", 0) + score_boost)
            
            url_analysis["threat_intel"] = {
                "is_domain_blacklisted": intel_report.get("is_domain_blacklisted"),
                "vt_detections": intel_report.get("vt_detection_count", 0),
                "abuseipdb_reports": intel_report.get("abuseipdb_report_count", 0),
                "domain_age_days": intel_report.get("domain_age_days"),
                "flags": intel_report.get("detected_threat_flags", [])
            }
            
        except Exception as intel_error:
            url_analysis["threat_intel"] = {}

        return jsonify({"result": url_analysis})

    except Exception as err:
        return jsonify({
            "error": "Backend URL scanning failed",
            "details": str(err)
        }), 500


if __name__ == "__main__":
    print("""
    
        Threat Detection Server (v1.1.0)                           
      
      Server: http://127.0.0.1:5000                                
      Health Check: GET /health                                    
      Email Analysis: POST /analyze                                
      URL Scanning: POST /scan-url                                 
    
    """)
    
    app.run(debug=True, port=5000)