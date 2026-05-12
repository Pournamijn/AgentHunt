# AgentHunt

A Chrome extension that scans emails and links for phishing — powered by a local Python backend that runs heuristics, ML models, and an LLM together to give you a risk score.

It hooks into Gmail and Outlook, badges every link on every page, and lets you right-click any link to scan it. Everything runs on your machine except the optional Groq API call.

---

## The detection pipeline

Three things run on every email, in order:

1. **Heuristics** — SPF/DKIM/DMARC checks, typosquat detection, risky TLDs, keyword matching, Reply-To mismatches. Fast and rule-based. Weighted at 30% of the final score.

2. **ML + NLP** — Two scikit-learn models trained on boot from built-in samples. Emails go through TF-IDF (word + char n-grams) into Logistic Regression, plus 10 NLP features into a Random Forest. URLs go through 35 structural features into Gradient Boosting + char-level TF-IDF. The UI also shows separate urgency, deception, and impersonation sub-scores. Weighted at 35%.

3. **Groq LLaMA 3.3-70B** — Gets the sender, subject, body, and whatever the heuristics flagged, and returns a JSON verdict with reasoning, attack type, and suggested action. Weighted at 35%. If you don't set an API key it just skips this layer.

After that, threat intel (domain age, VirusTotal, AbuseIPDB) runs and can add up to 65 points on top if the domain is a known bad actor.

---

## Setup

You need Python 3.9+ and Chrome. Groq key is optional.

```bash
pip install -r requirements.txt
```

Add your Groq key in `analyzer.py`:

```python
def fetch_api_credential():
    api_credential = "gsk_YOUR_KEY_HERE"
    return api_credential.strip()
```

Start the server:

```bash
python server.py
```

Then go to `chrome://extensions/`, turn on Developer mode, hit Load unpacked, and point it at the project folder. Open Gmail or Outlook and it just works.

---

## Files

```
manifest.json        Chrome MV3 config
background.js        Service worker — routes messages, handles context menu
content.js           Pulls email data out of Gmail / Outlook DOM
link_scanner.js      Badges all links on any page, handles click-to-scan
popup.html / .js     The extension popup — results, history, stats

server.py            Flask server, entry point
analyzer.py          Orchestrates the 3-layer pipeline
ml_engine.py         Trains and runs all ML/NLP models
threat_intel.py      Domain reputation lookups

email_threat_model.pkl   Auto-generated on first run
url_threat_model.pkl     Auto-generated on first run
```

---

## Endpoints

`GET /health` — health check, used by the popup status indicator.

`POST /analyze` — full email analysis. Send `sender`, `subject`, `body`, `headers`. Get back `final_score`, `final_verdict`, `ai_analysis`, `threat_intel`, and `ml_summary`.

`POST /scan-url` — single URL scan. Send `{ "url": "..." }`. Get back score, verdict, reasoning, and flags.

All endpoints are on `http://127.0.0.1:5000`.

---

## Scores

| Range | Verdict |
|---|---|
| 70–100 | Phishing |
| 40–69 | Suspicious |
| 0–39 | Legitimate |

---

## Privacy

Nothing leaves your machine except the Groq API call (if you have a key set) and the optional threat intel lookups. If you want fully offline, remove the Groq key and gut `threat_intel.py`.

---

## License
