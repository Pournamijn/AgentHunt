"""
threat_detection.py — ML + NLP Core for Security Scanner
===========================================================
Two detection modules:
  EMAIL: TF-IDF (word + char) features fed into Logistic Regression
         + 10 custom NLP features fed into Random Forest
         Both scores combined for final ML result.
  URL  : 35 custom URL features fed into Gradient Boosting
         + char TF-IDF fed into Logistic Regression, combined.

Architecture kept straightforward to avoid sklearn pipeline
compatibility issues (no FeatureUnion mixing sparse+dense).
"""

import re
import math
import pickle
import hashlib
import urllib.parse
from pathlib import Path
from typing import List
from collections import Counter

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
    import numpy as np
    SKLEARN_READY = True
except ImportError:
    SKLEARN_READY = False

try:
    from textblob import TextBlob
    TEXTBLOB_READY = True
except ImportError:
    TEXTBLOB_READY = False

EMAIL_MODEL_FILE = Path(__file__).parent / "email_threat_model.pkl"
URL_MODEL_FILE   = Path(__file__).parent / "url_threat_model.pkl"

# ─────────────────────────────────────────────────────────────────────────────
# THREAT PATTERNS
# ─────────────────────────────────────────────────────────────────────────────

URGENT_TRIGGERS = [
    "urgent","immediately","act now","right now","within 24 hours","within 12 hours",
    "within 48 hours","expires tonight","final notice","last chance","limited time",
    "don't delay","hurry","asap","as soon as possible","account will be","will be deleted",
    "will be suspended","will be closed","will be terminated","will be deactivated",
    "click here now","verify now","confirm now","update now","respond immediately",
    "failure to","action required","immediate action","time sensitive","deadline",
    "today only","hours left","minutes left","access will be","must verify","must confirm",
]

SPOOFING_PATTERNS = [
    r'paypa[l1]', r'amaz[o0]n', r'micr[o0]s[o0]ft', r'g[o0]{2}gle',
    r'f[a@]cebook', r'[a@]pple', r'n[e3]tflix', r'[i1]nstagram',
    r'click\s+here', r'verify\s+your', r'confirm\s+your',
    r'update\s+your\s+(payment|billing|credit|card|account)',
    r'bank\s*account', r'credit\s*card', r'social\s*security',
    r'wire\s*transfer', r'bitcoin|crypto|wallet',
    r'you\s*have\s*(won|been\s*selected)',
]

WELL_KNOWN_BRANDS = [
    "paypal","amazon","microsoft","google","apple","netflix","facebook","instagram",
    "twitter","linkedin","dropbox","chase","wells fargo","citibank","bank of america",
    "barclays","hsbc","irs","social security","dhl","fedex","ups","usps","ebay",
    "coinbase","binance","whatsapp","telegram","yahoo","outlook","office365",
]

SUSPICIOUS_TERMS = [
    "verify","suspended","click here","act now","limited time","your account",
    "confirm your","password expired","unusual activity","win a prize",
    "congratulations","free gift","winner","selected","inheritance","beneficiary",
    "wire transfer","bitcoin","unclaimed","refund","stimulus","grant","lottery",
    "your payment","billing","credit card","debit card","ssn","social security",
    "pin number","otp","one time password",
]

RISKY_TLDS = {
    ".xyz",".top",".tk",".ml",".cf",".gq",".pw",".info",".biz",
    ".click",".link",".online",".site",".web",".win",".loan",
    ".download",".stream",".racing",".review",".accountant",
}

KNOWN_MALICIOUS_DOMAINS = {
    "paypa1.com","paypal-secure.net","amaz0n-deals.com","micros0ft.com",
    "apple-id-verify.com","irs-refund.org","netflix-billing.info",
    "secure-login-verify.com","account-suspended-alert.com",
    "chasebankk.com","wells-farg0.com","citibank-alert.net",
    "update-billing.com","verify-account.net","signin-secure.com",
}

SAFE_DOMAINS = {
    "google.com","microsoft.com","amazon.com","apple.com","github.com",
    "linkedin.com","facebook.com","twitter.com","netflix.com","paypal.com",
    "chase.com","wellsfargo.com","bankofamerica.com","youtube.com",
    "dropbox.com","slack.com","zoom.us","salesforce.com",
}

# ─────────────────────────────────────────────────────────────────────────────
# TRAINING SAMPLES
# ─────────────────────────────────────────────────────────────────────────────

THREAT_EMAILS = [
    "URGENT: Your PayPal account has been suspended. Click here immediately to verify your identity and restore access or it will be permanently deleted.",
    "Your bank account will be closed in 24 hours if you do not confirm your personal details at the link below. Act now.",
    "ALERT: Suspicious login detected on your account. Verify now or your account will be permanently deleted within 12 hours.",
    "Dear customer, your password has expired. Update it immediately to avoid losing access to your account forever.",
    "Microsoft Security Team: Your account shows unusual activity. Sign in now to protect your information before access is revoked.",
    "Apple ID suspended! Verify your billing information immediately or you will lose all your data and purchases.",
    "Your Netflix subscription payment failed. Update your payment method now to avoid losing access tonight.",
    "Urgent action required: Your credit card was flagged for fraudulent activity. Click here to secure it immediately.",
    "PAYPAL SECURITY ALERT: We noticed unusual transactions. Confirm your account within 12 hours to avoid suspension.",
    "Chase Bank: A new payee was added to your account. If this wasn't you, click here to cancel immediately.",
    "Google Account Alert: Sign-in attempt blocked. Verify your account now to prevent permanent lockout.",
    "Wells Fargo: Your debit card has been blocked for security reasons. Unblock it here immediately or lose access.",
    "Your Amazon account has been compromised. Log in immediately to reset your password.",
    "IRS Notice: You are owed a tax refund. Submit your SSN and banking info to claim $892.00 now.",
    "Your social security number has been suspended due to suspicious activity. Call immediately to resolve.",
    "FINAL NOTICE: Your email account will be deactivated tonight. Click here to keep your account active.",
    "Your credit card was used for a suspicious purchase. Verify now to block unauthorized charges.",
    "Office 365: Your subscription will expire in 24 hours. Update your payment details now.",
    "DHL: Your parcel could not be delivered. Pay $2.99 redelivery fee now at secure-dhl.xyz.",
    "FedEx shipment on hold: Customs duty payment required. Pay $4.99 and release your package today.",
    "Congratulations! You've won a $1000 Amazon gift card. Act now — limited time offer! Claim your prize here.",
    "You have a pending wire transfer. Confirm your banking credentials to receive $5000 immediately.",
    "WINNER! You've been selected for a special prize. Provide your details to claim your $500 reward today.",
    "Claim your inheritance now! You have been identified as the beneficiary of a $4.5M estate. Reply ASAP.",
    "You have unclaimed funds in your name. Complete this form to receive your $3,200 stimulus payment today.",
    "Your crypto wallet has been compromised. Act fast and transfer your funds to this secure wallet immediately.",
    "Nigerian prince needs your help to transfer $15 million. You will receive 30% commission. Reply urgently.",
    "Congratulations! You are the lucky winner of our lottery. Send your bank details to claim $500,000.",
    "Special investment opportunity: guaranteed 500% returns in 30 days. Send $500 in Bitcoin to start.",
    "You have won a free iPhone 15. Just pay $4.99 shipping to claim your prize today.",
    "Your invoice #INV-2024-8821 is attached. Please review and confirm payment by clicking the link below.",
    "HR Department: Your salary details have been updated. View your new payslip at the link attached.",
    "Important document requires your digital signature. Click here to review and sign before deadline tonight.",
    "COVID-19 relief fund: You qualify for $1,400 payment. Click the secure link to claim your funds now.",
    "Your computer is infected with a virus! Call our toll-free number immediately for free removal assistance.",
    "Hi, this is the CEO. I need you to process an urgent wire transfer of $45,000 to our new vendor today.",
    "IT Department: We are upgrading our systems. Please confirm your username and password for migration.",
    "HR Update: Please update your direct deposit banking information at the link below before Friday.",
    "Your account will be charged $499 for McAfee antivirus renewal. Call to cancel: 1-800-SCAM-NOW",
    "IRS: Final warning before legal action. You owe $4,821 in back taxes. Call immediately to avoid arrest.",
    "Verify your identity to receive your government benefit payment of $1,400. Submit SSN and bank account.",
    "Suspicious transaction on your PayPal: $849 sent to unknown recipient. Click here to dispute now.",
    "Tax season alert: You have an unclaimed refund of $2,840. File your claim now before the deadline.",
    "Your email was flagged for sending spam. Verify your account now to avoid permanent suspension.",
    "Apple Support: Your iCloud storage is full. Upgrade now for free for the next 24 hours only.",
    "Bank security: We have frozen your account due to unusual activity. Click here to unfreeze it now.",
    "Congratulations! You've been pre-approved for a $50,000 personal loan. Apply now — no credit check!",
    "Your Spotify Premium has been cancelled. Reactivate now at 50% off for the next 24 hours only.",
    "Zoom: Your account has been suspended for violating terms of service. Appeal here within 24 hours.",
    "Your Coinbase wallet was accessed from a new device. Verify immediately or account will be locked.",
    "URGENT: Your domain is about to expire. Renew now at this special price before it is taken.",
    "Your WhatsApp account will expire tomorrow. Click here to renew your subscription for free.",
    "Important: Your Google Drive storage will be deleted in 24 hours. Click here to secure your files.",
    "Amazon order #112-8821: Your order was placed. If you didn't make this purchase call 1-888-555-FAKE",
    "Microsoft refund department: You are owed $299 for overcharge. Share your bank details to receive it.",
    "Tech support: We detected malware on your PC. Call us immediately at 1-800-555-0100 to remove it.",
    "Your health insurance is expiring. Enroll now to avoid a gap in coverage. Limited spots available.",
    "URGENT: Ransomware detected on your network. Pay 0.5 BTC within 48 hours or all files will be deleted.",
    "Your password must be changed immediately. Click the link below and enter your current password first.",
    "Security alert: Someone tried to access your account. Verify your identity now to block them.",
    "Your Dropbox account has been compromised. Reset your password immediately using this link.",
    "LinkedIn: You have a job offer waiting. Click here and enter your credentials to view the offer.",
    "Delivery failed: Your package is waiting at the post office. Pay $1.99 customs fee to release it.",
    "Your online banking session has expired. Re-enter your credentials to secure your account now.",
    "We noticed you searched for loans. You qualify for $10,000 instantly. No credit check needed.",
]

SAFE_EMAILS = [
    "Hi Sarah, just following up on the project proposal we discussed in Tuesday's meeting. Let me know your thoughts.",
    "Thanks for your order! Your package has been shipped and will arrive in 3-5 business days.",
    "Reminder: Team standup at 10am tomorrow. Agenda: sprint review, backlog grooming, Q3 planning.",
    "We've updated our privacy policy. You can review the changes on our website. No action required.",
    "Your subscription renewal is coming up on Nov 30. No action needed — your card on file will be charged.",
    "Meeting notes from today's call are attached. Let me know if I missed anything.",
    "The quarterly financial report is ready for review. Please find the PDF attached to this email.",
    "Your flight booking confirmation: AA1234, New York to London, departing Dec 15 at 9:00 AM.",
    "Your reservation at The Grand Hotel is confirmed for Dec 20-23. Check-in is at 3 PM.",
    "Invoice #4521 from Acme Corp is attached. Payment is due by November 15. Thank you for your business.",
    "Your library book is due back on November 28. Renew it online at the library portal if needed.",
    "Team, the office will be closed on Thursday for the public holiday. Enjoy the long weekend!",
    "Your annual performance review is scheduled for Friday at 2 PM with your manager.",
    "New blog post: 10 tips for better remote work productivity. Read it on our website.",
    "We're excited to share our latest product updates. Here's what's new this month.",
    "Your GitHub pull request #142 has been reviewed. Two minor comments, otherwise looks good to merge.",
    "Lunch tomorrow at noon? I found a great new Italian place around the corner from the office.",
    "The document you shared has been edited by John. Click to view the latest version in Google Docs.",
    "Your weekly digest: 3 new comments on your post, 12 new followers, top story of the week.",
    "Thanks for attending our webinar! Here's the recording link and the slides from today's session.",
    "Your Amazon order #112-8821332 has been delivered. Your package was left at the front door.",
    "Your Spotify playlist was liked by 5 people this week. Check out what's trending on Spotify.",
    "Receipt from App Store: You purchased Headspace annual subscription for $69.99 on Nov 1.",
    "Your Uber ride receipt: Trip from Home to Airport on Nov 14. Total charged: $34.50 to Visa ending 1234.",
    "Order shipped: Your Nike shoes (Size 10, Blue) are on their way. Expected delivery: Nov 18-20.",
    "Your Airbnb booking is confirmed: Paris Studio, Dec 20-27. Host: Marie. Check-in: 3 PM.",
    "Dropbox: Sarah Jones shared a folder 'Project Assets Q4' with you. 12 files, 245MB total.",
    "Your Stripe payment of $299 was processed successfully. Receipt ID: ch_3NpQr2Abc123.",
    "Netflix: New episodes of your favorite show are now available. Enjoy watching!",
    "Your Duolingo streak is at 30 days! Keep it up — you're making great progress with Spanish.",
    "Your password was successfully changed. If you did not make this change, please contact support.",
    "Two-factor authentication has been enabled on your account. Your account is now more secure.",
    "Your monthly bank statement for October is now available online. Log in to view it.",
    "Reminder: Your dentist appointment is scheduled for November 20 at 10:00 AM with Dr. Johnson.",
    "Your prescription is ready for pickup at CVS Pharmacy on Main Street. Store hours: 9 AM - 9 PM.",
    "Security alert: A new device signed into your Google Account. If this was you, no action needed.",
    "Your LinkedIn connection request to Jane Doe was accepted. You now have 342 connections.",
    "GitHub Actions: Your workflow 'CI Pipeline' completed successfully in 2m 34s on branch main.",
    "Slack: You have 3 unread messages in #general and 1 direct message from Alex.",
    "Zoom: Your meeting 'Weekly Sync' starts in 15 minutes. Join link: zoom.us/j/abc123",
    "Happy birthday! Wishing you a wonderful day filled with joy and celebration.",
    "Just wanted to share this interesting article I read about machine learning.",
    "Are you free this weekend? A few of us are planning a hike on Saturday morning.",
    "Great working with you on this project. Looking forward to our next collaboration.",
    "Thanks for recommending that book — I finished it last night and absolutely loved it.",
    "Just a heads up that I'll be out of office next week. Sarah will be covering for me.",
    "Can you review my resume before I submit it? I've made some updates.",
    "Congratulations on your promotion! You've worked so hard and really deserve this.",
    "GitHub Newsletter: Top repositories this week include a new React framework with 12k stars.",
    "Stack Overflow: Your answer received 15 upvotes this week. You are in the top 10% this month.",
    "Your Google Analytics report for November is ready. Total visits: 12,450. Bounce rate: 42%.",
    "AWS billing alert: Your estimated bill for this month is $47.23. View breakdown in billing console.",
    "Cloudflare: Your domain example.com SSL certificate will expire in 30 days. Renewal is automatic.",
    "Please join us for our annual company picnic on June 15 at Riverside Park. RSVP by June 10.",
    "Your IT ticket #8821 has been resolved. Please let us know if you experience any further issues.",
    "Reminder: Expense reports for Q3 are due by October 31. Submit them through the portal.",
    "Your background check has been completed successfully. We look forward to you joining the team.",
    "The project kickoff meeting is confirmed for Monday at 9 AM in the main conference room.",
    "Your code review for feature/auth-refactor has been approved by 2 reviewers. Ready to merge.",
    "Company all-hands meeting this Thursday at 2 PM. CEO will share Q3 results and Q4 roadmap.",
    "Your 401k contribution for this month has been processed. Current balance: $48,392.",
    "The new design mockups are ready for review. I've shared them in Figma — link in the project folder.",
    "Good news — your passport application has been approved. Please collect it from the office.",
    "Your course completion certificate for Python Bootcamp is ready to download from Udemy.",
    "The team has reviewed your proposal and we're excited to move forward. Let's schedule a kickoff.",
    "Your insurance renewal is due next month. No action needed — it will auto-renew as usual.",
]

EMAIL_CONTENTS  = THREAT_EMAILS + SAFE_EMAILS
EMAIL_TARGETS = [1] * len(THREAT_EMAILS) + [0] * len(SAFE_EMAILS)

THREAT_URLS = [
    "http://paypal-secure-login.xyz/verify/account",
    "http://192.168.1.1/paypal/login.php",
    "http://secure-paypal.tk/update/billing",
    "http://paypal.com.malicious-site.xyz/signin",
    "http://accounts-google.com.verify.xyz/login",
    "http://login-amazon.ml/account/signin",
    "http://apple-id-verify.cf/update",
    "http://netflix-billing-update.gq/payment",
    "http://microsoftsupport.xyz/account/verify",
    "http://chase-bank-alert.pw/login",
    "http://bit.ly/3xFakePayPal",
    "http://10.0.0.1/admin/login.php",
    "http://172.16.0.1:8080/paypal/verify",
    "http://secure-login-verify.com/account/reset/password",
    "http://free-gift-claim.xyz/winner/prize",
    "http://irs-tax-refund-2024.ml/claim",
    "http://update-billing-info.tk/creditcard",
    "http://amazon.signin.verify-account.gq/login",
    "http://google.com.phishing-test.xyz/accounts/login",
    "http://wellsfargo-alert.top/signin/verify",
    "http://dhl-parcel.xyz/track/pay/customs",
    "http://microsoft.com.update-required.tk/office365",
    "http://apple.com.id-verify.ml/icloud/signin",
    "https://secure%20login%20verify.com/account",
    "http://login.paypa1.com/signin",
    "http://amaz0n.account-verify.com/signin",
    "http://193.42.111.88/paypal/login",
    "http://185.220.101.45:8443/account/verify",
    "http://accounts.google.com.auth.phish.xyz/login",
    "http://signin.microsoft.com.attacker.top/oauth",
    "http://coinbase-wallet-verify.tk/signin",
    "http://binance-security-alert.ml/verify",
    "http://instagram-verify.gq/account/login",
    "http://facebook-security.top/checkpoint/verify",
    "http://amazon-gift-card-winner.cf/claim",
    "http://irs-unclaimed-refund.xyz/apply",
    "http://social-security-suspended.ml/verify",
    "http://stimulus-payment-2024.gq/claim",
    "http://bank-account-frozen.tk/unfreeze",
    "http://creditcard-fraud-alert.xyz/dispute",
    "http://lottery-winner-2024.gq/claim/prize",
    "http://free-iphone15-winner.xyz/claim",
    "http://mcafee-renewal-cancel.top/refund",
    "http://norton-subscription-refund.xyz/cancel",
    "http://tech-support-virus-removal.xyz/help",
    "http://paypal.com-login.verify-secure.xyz/signin",
    "http://secure.amazon.com.fake-domain.ml/login",
    "http://login.microsoft.com.phishing.gq/signin",
    "http://update.apple.com.verify-now.xyz/id",
    "http://my.bank.com.login-verify.xyz/account",
]

SAFE_URLS = [
    "https://www.google.com/search?q=phishing+detection",
    "https://github.com/anthropics/anthropic-sdk-python",
    "https://stackoverflow.com/questions/tagged/python",
    "https://www.linkedin.com/in/johndoe",
    "https://mail.google.com/mail/u/0/#inbox",
    "https://docs.microsoft.com/en-us/azure/active-directory",
    "https://www.amazon.com/dp/B09G9HD6PD",
    "https://support.apple.com/en-us/HT201441",
    "https://www.paypal.com/myaccount/summary",
    "https://accounts.google.com/signin",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://www.reddit.com/r/netsec/comments/example",
    "https://news.ycombinator.com/item?id=38000000",
    "https://medium.com/@author/article-about-security",
    "https://app.slack.com/client/T12345/C12345",
    "https://zoom.us/j/92345678901",
    "https://www.dropbox.com/sh/abc123/AAAexample",
    "https://drive.google.com/file/d/1abc123/view",
    "https://outlook.office.com/mail/inbox",
    "https://www.netflix.com/browse",
    "https://open.spotify.com/album/abc123",
    "https://trello.com/b/abc123/project-board",
    "https://notion.so/workspace/page-title",
    "https://console.aws.amazon.com/s3/buckets",
    "https://portal.azure.com/#blade/Microsoft",
    "https://stripe.com/dashboard/payments",
    "https://www.coursera.org/learn/machine-learning",
    "https://arxiv.org/abs/2310.12345",
    "https://techcrunch.com/2024/01/15/ai-news",
    "https://cloud.google.com/compute/docs/instances",
    "https://scikit-learn.org/stable/modules/ensemble",
    "https://pandas.pydata.org/docs/user_guide",
    "https://huggingface.co/models",
    "https://vercel.com/dashboard/projects",
    "https://netlify.com/sites/your-site",
    "https://www.cloudflare.com/dashboard",
    "https://app.datadog.com/monitors/manage",
    "https://sentry.io/organizations/your-org",
    "https://colab.research.google.com/drive/abc123",
    "https://www.kaggle.com/competitions",
    "https://pytorch.org/docs/stable/index.html",
    "https://flask.palletsprojects.com/en/3.0.x",
    "https://numpy.org/doc/stable/reference",
    "https://www.bbc.com/news/technology-12345678",
    "https://www.nytimes.com/2024/01/15/technology",
    "https://render.com/dashboard/srv-abc123",
    "https://fly.io/apps/your-app",
    "https://grafana.your-company.com/dashboards",
    "https://kubernetes.io/docs/concepts/overview",
]

URL_CONTENTS  = THREAT_URLS + SAFE_URLS
URL_TARGETS = [1] * len(THREAT_URLS) + [0] * len(SAFE_URLS)


# ─────────────────────────────────────────────────────────────────────────────
# URL FEATURE ENGINEERING (35 features, pure Python)
# ─────────────────────────────────────────────────────────────────────────────

def _calc_entropy(text):
    if not text: return 0.0
    freq = Counter(text)
    n = len(text)
    return -sum((c/n)*math.log2(c/n) for c in freq.values())

def extract_url_indicators(url: str) -> list:
    """Extract 35 numerical indicators from a URL. Returns list of floats."""
    try:
        parsed   = urllib.parse.urlparse(url)
        host_part = parsed.netloc.lower()
        path_part = parsed.path.lower()
        query_part = parsed.query.lower()
        scheme_type = parsed.scheme.lower()
    except Exception:
        return [0.0] * 35

    clean_host = re.sub(r':\d+$', '', host_part)
    host_parts = clean_host.split('.')
    tld_part = ('.' + host_parts[-1]) if len(host_parts) >= 2 else ''
    subdomain_qty = max(0, len(host_parts) - 2)

    brand_keywords = ['paypal','amazon','google','apple','microsoft',
                      'facebook','netflix','chase','wellsfargo','ebay',
                      'instagram','linkedin','dropbox','twitter']
    url_lowercase = url.lower()
    brand_present   = any(b in url_lowercase for b in brand_keywords)
    is_trusted       = any(clean_host == d or clean_host.endswith('.'+d)
                         for d in SAFE_DOMAINS)

    features = [
        min(len(url) / 200.0, 1.0),                                              # 0 url length
        min(len(clean_host) / 80.0, 1.0),                                        # 1 host length
        min(len(path_part) / 100.0, 1.0),                                        # 2 path length
        min(subdomain_qty / 5.0, 1.0),                                           # 3 subdomain count
        1.0 if tld_part in RISKY_TLDS else 0.0,                                  # 4 risky TLD
        1.0 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', host_part) else 0.0,  # 5 IP address
        1.0 if re.search(r':\d{4,5}', parsed.netloc) else 0.0,                  # 6 unusual port
        1.0 if scheme_type == 'http' else 0.0,                                   # 7 http only
        1.0 if (brand_present and not is_trusted) else 0.0,                     # 8 brand impersonation
        1.0 if any(p in clean_host for p in KNOWN_MALICIOUS_DOMAINS) else 0.0,  # 9 known malicious
        1.0 if '%' in url else 0.0,                                              # 10 encoding present
        min(_calc_entropy(clean_host) / 4.5, 1.0),                              # 11 host entropy
        min(_calc_entropy(path_part) / 4.5, 1.0),                               # 12 path entropy
        sum(c.isdigit() for c in clean_host) / max(len(clean_host),1),          # 13 digit proportion
        min(clean_host.count('-') / 5.0, 1.0),                                  # 14 hyphen frequency
        min(url.count('.') / 10.0, 1.0),                                        # 15 dot frequency
        1.0 if re.search(r'(login|signin|sign-in|auth|verify|confirm|account|password|credential|secure|update)', path_part+query_part) else 0.0,  # 16 auth keywords
        1.0 if re.search(r'\.(php|asp|aspx|jsp|cgi|exe|zip)$', path_part) else 0.0, # 17 risky extension
        1.0 if any(s in clean_host for s in ['bit.ly','tinyurl','t.co','goo.gl','ow.ly','is.gd']) else 0.0,  # 18 link shortener
        1.0 if re.search(r'(redirect|redir|jump|goto|click|go\.php)', url_lowercase) else 0.0,  # 19 redirect
        1.0 if (subdomain_qty >= 2 and brand_present and not is_trusted) else 0.0,  # 20 multi-subdomain spoof
        1.0 if re.search(r'[a-z]\d|\d[a-z]', host_parts[0] if host_parts else '') else 0.0,  # 21 alphanumeric mix
        1.0 if len(clean_host) > 30 else 0.0,                                   # 22 long host
        min(len(query_part) / 100.0, 1.0),                                      # 23 query length
        min(len(urllib.parse.parse_qs(query_part)) / 5.0, 1.0),                # 24 query param count
        min(path_part.count('/') / 6.0, 1.0),                                  # 25 path depth
        1.0 if any(w in clean_host for w in ['secure','login','verify','account','update','alert','confirm','bank','payment']) else 0.0,  # 26 suspicious host words
        1.0 if is_trusted else 0.0,                                             # 27 trusted domain
        1.0 if re.search(r'[0-9a-f]{8,}', clean_host) else 0.0,                # 28 hex pattern
        1.0 if '@' in url else 0.0,                                             # 29 @ symbol
        1.0 if re.search(r'(ssn|creditcard|passport|cvv|dateofbirth)', url_lowercase) else 0.0,  # 30 sensitive data
        1.0 if re.search(r'(claim|winner|prize|gift|free|reward|lucky|bonus)', path_part) else 0.0,  # 31 prize keywords
        1.0 if re.search(r'(.)\1{3,}', clean_host) else 0.0,                   # 32 char repetition
        1.0 if re.search(r'\.[a-z]{2,4}\.[a-z]{2,4}$', path_part) else 0.0,    # 33 double extension
        min((len(host_parts) - 2) / 3.0, 1.0) if len(host_parts) > 2 else 0.0, # 34 excess subdomains
    ]
    return features

def extract_url_indicators_labeled(url: str) -> dict:
    indicator_names = [
        'url_length','hostname_length','path_length','subdomain_count',
        'suspicious_tld','raw_ip_address','non_standard_port','http_only',
        'brand_spoofing','known_phishing_domain','url_encoding',
        'hostname_entropy','path_entropy','digit_ratio','hyphen_count',
        'dot_count','credential_keywords','suspicious_extension',
        'url_shortener','redirect_keywords','multi_subdomain_spoof',
        'digit_letter_mix','long_hostname','query_length','query_param_count',
        'path_depth','suspicious_domain_words','legitimate_domain',
        'hex_in_hostname','at_symbol','data_exfil_keywords',
        'phishing_action_keywords','char_repetition','double_extension',
        'excess_subdomains',
    ]
    vals = extract_url_indicators(url)
    return {indicator_names[i]: round(vals[i], 3) for i in range(len(vals))}


# ─────────────────────────────────────────────────────────────────────────────
# NLP FEATURE EXTRACTION (10 numeric features from email text)
# ─────────────────────────────────────────────────────────────────────────────

def _extract_email_nlp_indicators(text: str) -> list:
    text_lower = text.lower()
    words = text.split()
    sentences = [s for s in re.split(r'[.!?]+', text) if s.strip()]
    return [
        sum(1 for p in URGENT_TRIGGERS if p in text_lower),                  # 0 urgency count
        sum(1 for p in SPOOFING_PATTERNS if re.search(p, text, re.I)),       # 1 spoofing patterns
        sum(1 for b in WELL_KNOWN_BRANDS if b in text_lower),                # 2 brand count
        sum(1 for k in SUSPICIOUS_TERMS if k in text_lower),                 # 3 suspicious terms
        len(re.findall(r'(!!+|\$\$+|[A-Z]{5,}|\*{3,})', text)),              # 4 unusual punctuation
        sum(1 for w in words if w.isupper() and len(w) > 2) / max(len(words), 1),  # 5 uppercase ratio
        len(re.findall(r'https?://[^\s]+', text)),                            # 6 url count
        len([u for u in re.findall(r'https?://[^\s]+', text)
             if any(t in u for t in RISKY_TLDS)]),                            # 7 risky url count
        len(words) / max(len(sentences), 1),                                 # 8 avg sentence length
        min(len(text) / 2000.0, 1.0),                                        # 9 text length ratio
    ]


# ─────────────────────────────────────────────────────────────────────────────
# MODEL TRAINING (two separate pipelines, NO FeatureUnion)
# ─────────────────────────────────────────────────────────────────────────────

def _generate_fingerprint(texts, labels):
    return hashlib.md5(("".join(texts) + str(labels)).encode()).hexdigest()[:16]


def _train_email_detectors():
    """
    Train two separate email detection models and return both.
    Model 1: TF-IDF (word + char combined text) -> LogisticRegression
    Model 2: NLP numeric features -> RandomForest
    """
    # Model 1 — text-based
    tfidf_word = TfidfVectorizer(ngram_range=(1, 3), max_features=6000,
                                  sublinear_tf=True, analyzer='word',
                                  stop_words='english')
    tfidf_char = TfidfVectorizer(ngram_range=(2, 4), max_features=3000,
                                  sublinear_tf=True, analyzer='char_wb')

    X_word = tfidf_word.fit_transform(EMAIL_CONTENTS)
    X_char = tfidf_char.fit_transform(EMAIL_CONTENTS)
    from scipy.sparse import hstack
    X_text = hstack([X_word, X_char])
    lr_model = LogisticRegression(C=2.0, max_iter=1000,
                                   class_weight='balanced', solver='lbfgs')
    lr_model.fit(X_text, EMAIL_TARGETS)

    # Model 2 — NLP features
    X_nlp = np.array([_extract_email_nlp_indicators(t) for t in EMAIL_CONTENTS])
    rf_model = RandomForestClassifier(n_estimators=200, max_depth=10,
                                       class_weight='balanced', random_state=42)
    rf_model.fit(X_nlp, EMAIL_TARGETS)

    bundle = {
        'tfidf_word': tfidf_word,
        'tfidf_char': tfidf_char,
        'lr_model':   lr_model,
        'rf_model':   rf_model,
        'fingerprint': _generate_fingerprint(EMAIL_CONTENTS, EMAIL_TARGETS),
        'type': 'email_v2',
    }
    with open(EMAIL_MODEL_FILE, 'wb') as f:
        pickle.dump(bundle, f)
    print(f"[ML] Email detectors trained on {len(EMAIL_CONTENTS)} samples.")
    return bundle


def _train_url_detectors():
    """
    Train two separate URL detection models and return both.
    Model 1: char TF-IDF -> LogisticRegression
    Model 2: 35 engineered features -> GradientBoosting
    """
    from scipy.sparse import hstack

    # Model 1 — char TF-IDF on URL string
    tfidf_url = TfidfVectorizer(ngram_range=(2, 4), max_features=3000,
                                 sublinear_tf=True, analyzer='char_wb')
    X_char = tfidf_url.fit_transform(URL_CONTENTS)
    lr_model = LogisticRegression(C=3.0, max_iter=1000,
                                   class_weight='balanced', solver='lbfgs')
    lr_model.fit(X_char, URL_TARGETS)

    # Model 2 — engineered features
    X_feat = np.array([extract_url_indicators(u) for u in URL_CONTENTS])
    gb_model = GradientBoostingClassifier(n_estimators=200, max_depth=4,
                                           learning_rate=0.08, random_state=42)
    gb_model.fit(X_feat, URL_TARGETS)

    bundle = {
        'tfidf_url': tfidf_url,
        'lr_model':  lr_model,
        'gb_model':  gb_model,
        'fingerprint': _generate_fingerprint(URL_CONTENTS, URL_TARGETS),
        'type': 'url_v2',
    }
    with open(URL_MODEL_FILE, 'wb') as f:
        pickle.dump(bundle, f)
    print(f"[ML] URL detectors trained on {len(URL_CONTENTS)} samples.")
    return bundle


def _load_detector_bundle(path, train_fn, texts, labels):
    if not SKLEARN_READY:
        return None
    fp = _generate_fingerprint(texts, labels)
    if path.exists():
        try:
            with open(path, 'rb') as f:
                bundle = pickle.load(f)
            if bundle.get('fingerprint') == fp:
                return bundle
            print(f"[ML] {path.name}: data changed, retraining.")
        except Exception as e:
            print(f"[ML] {path.name} load error ({e}), retraining.")
    return train_fn()


_EMAIL_DETECTOR = None
_URL_DETECTOR   = None

def _get_email_detector():
    global _EMAIL_DETECTOR
    if _EMAIL_DETECTOR is None:
        _EMAIL_DETECTOR = _load_detector_bundle(EMAIL_MODEL_FILE, _train_email_detectors,
                                                EMAIL_CONTENTS, EMAIL_TARGETS)
    return _EMAIL_DETECTOR

def _get_url_detector():
    global _URL_DETECTOR
    if _URL_DETECTOR is None:
        _URL_DETECTOR = _load_detector_bundle(URL_MODEL_FILE, _train_url_detectors,
                                              URL_CONTENTS, URL_TARGETS)
    return _URL_DETECTOR


# ─────────────────────────────────────────────────────────────────────────────
# PUBLIC API — EMAIL
# ─────────────────────────────────────────────────────────────────────────────

def ml_evaluate_email(subject: str = "", body: str = "", sender: str = "") -> dict:
    """Evaluate email text. Returns threat probability 0-100."""
    if not SKLEARN_READY:
        return {'ml_score': -1, 'ml_confidence': 'unavailable', 'ml_available': False}
    bundle = _get_email_detector()
    if bundle is None:
        return {'ml_score': -1, 'ml_confidence': 'unavailable', 'ml_available': False}

    text = f"{subject} {body}".strip()
    if not text:
        return {'ml_score': 0, 'ml_confidence': 'low', 'ml_available': True}

    try:
        from scipy.sparse import hstack
        # Model 1 score
        X_word = bundle['tfidf_word'].transform([text])
        X_char = bundle['tfidf_char'].transform([text])
        X_text = hstack([X_word, X_char])
        prob_lr = float(bundle['lr_model'].predict_proba(X_text)[0][1])

        # Model 2 score
        X_nlp = np.array([_extract_email_nlp_indicators(text)])
        prob_rf = float(bundle['rf_model'].predict_proba(X_nlp)[0][1])

        # Weighted average (text model slightly more weight)
        prob = 0.6 * prob_lr + 0.4 * prob_rf
        score = round(prob * 100)
        conf  = 'high' if prob >= 0.80 else 'medium' if prob >= 0.55 else 'low'
        return {
            'ml_score': score,
            'ml_confidence': conf,
            'ml_available': True,
            'phishing_probability': round(prob, 4),
        }
    except Exception as e:
        return {'ml_score': -1, 'ml_confidence': 'error', 'ml_available': False, 'reason': str(e)}


# ─────────────────────────────────────────────────────────────────────────────
# PUBLIC API — URL
# ─────────────────────────────────────────────────────────────────────────────

def ml_evaluate_url(url: str) -> dict:
    """Evaluate a single URL. Returns threat probability 0-100."""
    features_labeled = extract_url_indicators_labeled(url)
    feats = extract_url_indicators(url)

    if not SKLEARN_READY:
        # Fallback heuristics
        score = min(100, int(
            feats[4]*40 + feats[5]*45 + feats[8]*30 + feats[9]*50 +
            feats[16]*20 + feats[18]*25 + feats[26]*15
        ))
        verdict = 'Malicious' if score >= 70 else 'Suspicious' if score >= 40 else 'Likely Safe'
        return {'ml_score': score, 'ml_confidence': 'heuristic_only',
                'ml_available': False, 'verdict': verdict,
                'phishing_probability': round(score/100, 4),
                'features': features_labeled}

    bundle = _get_url_detector()
    if bundle is None:
        score = min(100, int(feats[4]*40 + feats[5]*45 + feats[8]*30))
        return {'ml_score': score, 'ml_confidence': 'heuristic_only',
                'ml_available': False, 'features': features_labeled}

    try:
        # Model 1 — char TF-IDF
        X_char = bundle['tfidf_url'].transform([url])
        prob_lr = float(bundle['lr_model'].predict_proba(X_char)[0][1])

        # Model 2 — engineered features
        X_feat = np.array([feats])
        prob_gb = float(bundle['gb_model'].predict_proba(X_feat)[0][1])

        # Weighted average (GB gets more weight — features are strong signals)
        prob  = 0.45 * prob_lr + 0.55 * prob_gb
        score = round(prob * 100)
        conf  = 'high' if prob >= 0.80 else 'medium' if prob >= 0.55 else 'low'
        verdict = 'Malicious' if score >= 70 else 'Suspicious' if score >= 40 else 'Likely Safe'

        return {
            'ml_score': score,
            'ml_confidence': conf,
            'ml_available': True,
            'phishing_probability': round(prob, 4),
            'verdict': verdict,
            'features': features_labeled,
        }
    except Exception as e:
        return {'ml_score': -1, 'ml_confidence': 'error',
                'ml_available': False, 'reason': str(e),
                'features': features_labeled}


# ─────────────────────────────────────────────────────────────────────────────
# PUBLIC API — URL BATCH ANALYSIS (for emails)
# ─────────────────────────────────────────────────────────────────────────────

def _get_top_threat_flags(features: dict) -> list:
    flags = []
    checks = [
        ('suspicious_tld',        'Suspicious TLD'),
        ('raw_ip_address',        'Raw IP address used'),
        ('brand_spoofing',        'Brand name spoofing'),
        ('known_phishing_domain', 'Known malicious domain'),
        ('credential_keywords',   'Credential keywords in URL'),
        ('http_only',             'Unencrypted HTTP'),
        ('url_shortener',         'URL shortener used'),
        ('suspicious_domain_words','Suspicious words in domain'),
        ('non_standard_port',     'Non-standard port'),
        ('phishing_action_keywords','Threat action keywords'),
    ]
    for key, label in checks:
        if features.get(key, 0) > 0.5:
            flags.append(label)
        if len(flags) == 5:
            break
    return flags


def analyze_urls_in_message(urls: list) -> dict:
    """Deep ML analysis of all URLs found in an email body."""
    if not urls:
        return {'url_count': 0, 'malicious_count': 0,
                'suspicious_count': 0, 'aggregate_score': 0, 'results': []}

    results = []
    for url in urls[:10]:
        r = ml_evaluate_url(url)
        score   = max(0, r.get('ml_score', 0))
        verdict = 'Malicious' if score >= 70 else 'Suspicious' if score >= 40 else 'Safe'
        results.append({
            'url':        url,
            'score':      score,
            'verdict':    verdict,
            'confidence': r.get('ml_confidence', 'low'),
            'top_flags':  _get_top_threat_flags(r.get('features', {})),
        })

    malicious  = sum(1 for r in results if r['verdict'] == 'Malicious')
    suspicious = sum(1 for r in results if r['verdict'] == 'Suspicious')
    max_score  = max((r['score'] for r in results), default=0)
    avg_score  = round(sum(r['score'] for r in results) / len(results)) if results else 0
    aggregate  = min(100, max(max_score, avg_score + malicious*15 + suspicious*5))

    return {
        'url_count':       len(urls),
        'malicious_count': malicious,
        'suspicious_count':suspicious,
        'aggregate_score': aggregate,
        'results':         results,
    }


# ─────────────────────────────────────────────────────────────────────────────
# NLP FEATURE EXTRACTION (for API response / popup display)
# ─────────────────────────────────────────────────────────────────────────────

def _check_urgency(text):
    text_l = text.lower()
    matched = [p for p in URGENT_TRIGGERS if p in text_l]
    return {'score': min(100, len(matched)*8), 'matched_phrases': matched[:5]}

def _check_spoofing(text):
    n = sum(1 for p in SPOOFING_PATTERNS if re.search(p, text, re.I))
    return {'score': min(100, n*14)}

def _check_brand_impersonation(text):
    text_l = text.lower()
    found = [b for b in WELL_KNOWN_BRANDS if b in text_l]
    return {'score': min(100, len(found)*18), 'brands_detected': found}

def _analyze_sentiment(text):
    if not TEXTBLOB_READY or not text.strip():
        return {'polarity': 0.0, 'subjectivity': 0.0, 'available': False}
    try:
        blob = TextBlob(text)
        return {'polarity': round(blob.sentiment.polarity, 3),
                'subjectivity': round(blob.sentiment.subjectivity, 3),
                'available': True}
    except Exception:
        return {'polarity': 0.0, 'subjectivity': 0.0, 'available': False}

def _assess_readability(text):
    words = text.split()
    sents = [s for s in re.split(r'[.!?]+', text) if s.strip()]
    if not words or not sents:
        return {'score': 50, 'grade': 'Unknown'}
    asl = len(words) / len(sents)
    def syl(w):
        w = w.lower().strip('.,!?;:')
        if len(w) <= 3: return 1
        return max(1, len(re.findall(r'[aeiouy]+', w)) - (1 if w.endswith('e') else 0))
    asw = sum(syl(w) for w in words) / len(words)
    score = max(0, min(100, 206.835 - 1.015*asl - 84.6*asw))
    grade = ('Very Simple' if score >= 80 else 'Standard' if score >= 60
             else 'Difficult' if score >= 40 else 'Very Difficult')
    return {'score': round(score, 1), 'grade': grade}

def _check_punctuation(text):
    matches = re.findall(r'(!!+|\$\$+|[A-Z]{5,}|\*{3,})', text)
    return {'score': min(100, len(matches)*18), 'count': len(matches)}

def _analyze_urls_in_text(urls):
    if not urls:
        return {'count': 0, 'suspicious_count': 0, 'score': 0}
    susp = sum(1 for u in urls if
               any(t in u for t in RISKY_TLDS) or
               re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', u))
    return {'count': len(urls), 'suspicious_count': susp, 'score': min(100, susp*35)}


def extract_nlp_indicators(subject="", body="", sender="", urls=None) -> dict:
    urls = urls or []
    full = f"{subject} {body}".strip()
    urg  = _check_urgency(full)
    spoof = _check_spoofing(full)
    imp  = _check_brand_impersonation(full)
    sent = _analyze_sentiment(full)
    read = _assess_readability(body or full)
    punct = _check_punctuation(full)
    url_risk = _analyze_urls_in_text(urls)

    nlp_score = round(min(100,
        urg['score']*0.28 + spoof['score']*0.24 +
        imp['score']*0.20 + punct['score']*0.12 + url_risk['score']*0.16))

    return {
        'nlp_score': nlp_score,
        'urgency': urg, 'deception': spoof, 'impersonation': imp,
        'sentiment': sent, 'readability': read,
        'readability_flag': read['score'] > 78 or read['score'] < 20,
        'suspicious_punctuation': punct, 'url_features': url_risk,
    }


# ─────────────────────────────────────────────────────────────────────────────
# MAIN ENTRY POINT (called by analyzer.py)
# ─────────────────────────────────────────────────────────────────────────────

def analyze_with_ml_nlp(subject="", body="", sender="", urls=None) -> dict:
    urls = urls or []

    ml_result    = ml_evaluate_email(subject, body, sender)
    nlp_result   = extract_nlp_indicators(subject, body, sender, urls)
    url_analysis = analyze_urls_in_message(urls)

    if ml_result['ml_available'] and ml_result['ml_score'] >= 0:
        email_combined = round(0.55 * ml_result['ml_score'] + 0.45 * nlp_result['nlp_score'])
    else:
        email_combined = nlp_result['nlp_score']

    url_boost = 20 if url_analysis['malicious_count'] >= 1 else (10 if url_analysis['suspicious_count'] >= 1 else 0)
    combined  = min(100, email_combined + url_boost)

    signals = []
    if ml_result['ml_score'] >= 70:
        signals.append(f"ML detector: {ml_result['ml_score']}% threat probability ({ml_result['ml_confidence']} confidence)")
    if url_analysis['malicious_count'] > 0:
        signals.append(f"⚠ {url_analysis['malicious_count']} malicious URL(s) detected in email")
    if url_analysis['suspicious_count'] > 0:
        signals.append(f"{url_analysis['suspicious_count']} suspicious URL(s) in email")
    urg_phrases = nlp_result['urgency'].get('matched_phrases', [])
    if urg_phrases:
        signals.append(f"Urgency language: '{urg_phrases[0]}'")
    brands = nlp_result['impersonation'].get('brands_detected', [])
    if brands:
        signals.append(f"Brand impersonation: {', '.join(brands[:2])}")
    if nlp_result['deception']['score'] >= 30:
        signals.append("Obfuscation/spoofing patterns detected")
    if nlp_result['suspicious_punctuation']['count'] >= 2:
        signals.append(f"Suspicious punctuation ({nlp_result['suspicious_punctuation']['count']} instances)")

    return {
        'ml':             ml_result,
        'nlp':            nlp_result,
        'url_analysis':   url_analysis,
        'combined_score': combined,
        'top_signals':    signals[:6],
    }


# ─────────────────────────────────────────────────────────────────────────────
# CLI SELF-TEST
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if not SKLEARN_READY:
        print("Install scikit-learn first:  pip install scikit-learn scipy")
        exit(1)

    print("\n" + "="*60)
    print("  Threat Detection Engine — Self Test")
    print("="*60)

    print("\n[1] Training models...")
    eb = _train_email_detectors()
    ub = _train_url_detectors()

    try:
        from sklearn.model_selection import cross_val_score
        from scipy.sparse import hstack

        print("\n[2] Cross-validation (5-fold):")

        # Email LR model
        Xw = eb['tfidf_word'].transform(EMAIL_CONTENTS)
        Xc = eb['tfidf_char'].transform(EMAIL_CONTENTS)
        Xt = hstack([Xw, Xc])
        lr_scores = cross_val_score(eb['lr_model'], Xt, EMAIL_TARGETS, cv=5, scoring='accuracy')
        print(f"    Email (TF-IDF + LR)   : {lr_scores.mean()*100:.1f}% ± {lr_scores.std()*100:.1f}%")

        Xn = np.array([_extract_email_nlp_indicators(t) for t in EMAIL_CONTENTS])
        rf_scores = cross_val_score(eb['rf_model'], Xn, EMAIL_TARGETS, cv=5, scoring='accuracy')
        print(f"    Email (NLP + RF)       : {rf_scores.mean()*100:.1f}% ± {rf_scores.std()*100:.1f}%")

        Xu = ub['tfidf_url'].transform(URL_CONTENTS)
        ul_scores = cross_val_score(ub['lr_model'], Xu, URL_TARGETS, cv=5, scoring='accuracy')
        print(f"    URL   (char TF-IDF+LR) : {ul_scores.mean()*100:.1f}% ± {ul_scores.std()*100:.1f}%")

        Xf = np.array([extract_url_indicators(u) for u in URL_CONTENTS])
        gb_scores = cross_val_score(ub['gb_model'], Xf, URL_TARGETS, cv=5, scoring='accuracy')
        print(f"    URL   (features + GB)  : {gb_scores.mean()*100:.1f}% ± {gb_scores.std()*100:.1f}%")

    except Exception as e:
        print(f"    Cross-validation error: {e}")

    print("\n[3] Live predictions:")
    cases = [
        ("THREAT", "URGENT: Your PayPal account suspended. Verify now.", "URGENT: Verify PayPal",
         "evil@paypa1-secure.xyz", ["http://paypal-secure.xyz/verify", "http://192.168.1.1/login"]),
        ("SAFE",    "Meeting notes attached. Let me know if I missed anything.", "Meeting notes",
         "colleague@company.com", ["https://docs.google.com/document/d/abc"]),
    ]
    for label, body, subj, sender, urls in cases:
        r = analyze_with_ml_nlp(subject=subj, body=body, sender=sender, urls=urls)
        print(f"\n  [{label}]")
        print(f"    Email ML  : {r['ml']['ml_score']}  ({r['ml']['ml_confidence']})")
        print(f"    NLP score : {r['nlp']['nlp_score']}")
        print(f"    URLs      : {r['url_analysis']['malicious_count']} malicious / {r['url_analysis']['suspicious_count']} suspicious")
        print(f"    Combined  : {r['combined_score']}")
        for s in r['top_signals']:
            print(f"      → {s}")

    print("\n" + "="*60)