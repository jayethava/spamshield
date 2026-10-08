"""
SpamShield: Core Detector & Explainable AI Engine
=================================================
Performs:
1. Model inference (TF-IDF + Naive Bayes / Logistic Regression)
2. Explainable AI: Token attribution, log-odds calculation & HTML highlighter
3. Link Scanner: Heuristic analysis of URLs, IP detection, suspicious TLDs & shorteners
4. Scam Categorization: Rule-based classification for Indian & global fraud themes
5. Actionable safety tips generation
"""

import os
import re
import json
import joblib
from urllib.parse import urlparse
import numpy as np

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, 'model', 'spam_detector.joblib')
METRICS_PATH = os.path.join(BASE_DIR, 'model', 'metrics.json')

# Known suspicious / free / high-abuse top-level domains
SUSPICIOUS_TLDS = {
    'xyz', 'top', 'buzz', 'club', 'tk', 'ml', 'ga', 'cf', 'gq',
    'work', 'icu', 'vip', 'click', 'download', 'rest', 'fit', 'guru',
    'surf', 'live', 'cam', 'sbs', 'cfd', 'quest', 'date'
}

# Known URL shortener domains
SHORTENER_DOMAINS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'buff.ly',
    'cutt.ly', 'is.gd', 'shorturl.at', 'rb.gy', 'rebrand.ly', 'tiny.cc'
}

# Suspicious keywords in URL host or path
SUSPICIOUS_URL_KEYWORDS = [
    'login', 'verify', 'kyc', 'pan', 'aadhaar', 'update', 'banking',
    'secure', 'wallet', 'refund', 'support', 'free', 'bonus', 'claim',
    'account', 'security', 'authenticate', 'unblock', 'signin'
]

# Scam Category Rules (Regex and Keywords)
CATEGORY_RULES = {
    'Fake KYC / Banking': [
        r'\b(?:kyc|pan|aadhaar|yono|debit\s*card|credit\s*card|netbanking|bank\s*account|savings\s*account)\b',
        r'\b(?:suspended|frozen|blocked|deactivated|put\s*on\s*hold|unfreeze|re-kyc)\b',
        r'\b(?:sbi|hdfc|icici|axis|kotak|pnb|bob|paytm\s*payments\s*bank)\b'
    ],
    'Lottery / Reward Scam': [
        r'\b(?:lottery|lucky\s*draw|kbc|crorepati|bumper|cash\s*prize|jackpot)\b',
        r'\b(?:congratulations|won\s*(?:rs|inr|lakh|crore|\$)|selected\s*for|claim\s*prize|reward\s*points)\b',
        r'\b(?:gift\s*voucher|iphone\s*(?:14|15|16)|megadraw|processing\s*fee)\b'
    ],
    'OTP Fraud': [
        r'\b(?:otp|one\s*time\s*password|verification\s*code|security\s*otp)\b',
        r'\b(?:share\s*otp|send\s*otp|unauthorized\s*(?:transaction|debit)|reverse\s*transaction)\b',
        r'\b(?:fraud\s*helpline|cancel\s*(?:charge|transaction|transfer))\b'
    ],
    'Electricity Bill Disconnection': [
        r'\b(?:electricity|power|power\s*cut|meter|tariff)\b',
        r'\b(?:disconnected?\s*tonight|bill\s*not\s*updated|previous\s*month\s*bill)\b',
        r'\b(?:officer|sub-division|mahavitaran|bescom|tneb|torrent\s*power|dhbvn|uppcl)\b'
    ],
    'Fake Job Offer': [
        r'\b(?:part\s*time\s*job|work\s*from\s*home|wfh|data\s*entry|typing\s*job)\b',
        r'\b(?:daily\s*(?:1-2|2-3)\s*hours|earn\s*(?:rs|daily)|weekly\s*payment)\b',
        r'\b(?:liking\s*youtube|google\s*reviews|telegram\s*@|registration\s*fee|uniform\s*(?:fee|deposit))\b'
    ],
    'Promotional / Marketing': [
        r'\b(?:flat\s*\d+%\s*off|discount|sale|limited\s*time\s*offer|use\s*code|shop\s*now)\b',
        r'\b(?:buy\s*1\s*get\s*1|exclusive\s*deal|clearance|promo)\b'
    ],
    'Phishing / Account Theft': [
        r'\b(?:verify\s*your\s*identity|password\s*reset|unusual\s*activity|account\s*lock)\b',
        r'\b(?:click\s*here\s*to\s*confirm|security\s*alert|sign-in\s*attempt)\b'
    ]
}


class SpamDetectorEngine:
    def __init__(self):
        self.model = None
        self.vectorizer = None
        self.model_name = "Not Loaded"
        self.word_weights = {}
        self.metrics = {}
        self.load_artifacts()

    def load_artifacts(self):
        """Loads trained model, vectorizer, and metrics."""
        if os.path.exists(MODEL_PATH):
            try:
                payload = joblib.load(MODEL_PATH)
                self.model = payload.get('model')
                self.vectorizer = payload.get('vectorizer')
                self.model_name = payload.get('model_name', 'Trained Classifier')
                self.word_weights = payload.get('word_weights', {})
                print(f"[+] Loaded SpamShield model: {self.model_name} with {len(self.word_weights)} features.")
            except Exception as e:
                print(f"[-] Error loading model artifact: {e}")

        if os.path.exists(METRICS_PATH):
            try:
                with open(METRICS_PATH, 'r', encoding='utf-8') as f:
                    self.metrics = json.load(f)
            except Exception as e:
                print(f"[-] Error loading metrics.json: {e}")

    def clean_text_inference(self, text: str) -> str:
        """Text cleaning for inference matching training pipeline."""
        if not isinstance(text, str):
            return ""
        text = re.sub(r'https?://\S+|www\.\S+', ' http_url ', text)
        text = re.sub(r'\S+@\S+', ' email_addr ', text)
        text = re.sub(r'\+?\d[\d -]{8,}\d', ' phone_num ', text)
        text = re.sub(r'(?:rs\.?|inr|₹|\$|£|€)\s*\d+', ' money_amount ', text, flags=re.IGNORECASE)
        text = text.lower()
        text = re.sub(r'[^a-z0-9_\s]', ' ', text)
        return re.sub(r'\s+', ' ', text).strip()

    def scan_links(self, text: str) -> list:
        """
        Extracts and analyzes links for cybersecurity red flags:
        - IP addresses used directly
        - URL shorteners hiding destination
        - Suspicious/abused TLDs (.xyz, .top, .buzz, etc.)
        - Excessive subdomains
        - Suspicious path/query keywords (kyc, verify, login)
        - Insecure HTTP protocol
        """
        # Match complete URLs or domain names
        raw_urls = re.findall(r'(?:https?://[^\s]+|www\.[^\s]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?)', text)
        scanned_links = []
        seen = set()

        for raw_url in raw_urls:
            # Clean trailing punctuation
            clean_url = raw_url.rstrip('.,;!?:)"\'>')
            if clean_url in seen or len(clean_url) < 4:
                continue
            seen.add(clean_url)

            # Ensure schema for parsing
            parse_target = clean_url if clean_url.startswith(('http://', 'https://')) else 'http://' + clean_url
            try:
                parsed = urlparse(parse_target)
                hostname = parsed.hostname or ''
                path = parsed.path or ''
            except Exception:
                continue

            flags = []
            risk_level = "Clean"  # Clean, Suspicious, Malicious

            # Check 1: Direct IP address in URL
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname):
                flags.append("Uses raw IP address instead of legitimate domain name")
                risk_level = "Malicious"

            # Check 2: Known URL shortener
            if any(hostname == s or hostname.endswith('.' + s) for s in SHORTENER_DOMAINS):
                flags.append("URL shortener used to conceal actual destination")
                if risk_level != "Malicious":
                    risk_level = "Suspicious"

            # Check 3: Suspicious TLD
            tld = hostname.split('.')[-1].lower() if '.' in hostname else ''
            if tld in SUSPICIOUS_TLDS:
                flags.append(f"High-risk top-level domain (.{tld}) commonly associated with scam sites")
                risk_level = "Malicious"

            # Check 4: Excessive subdomains
            subdomain_parts = hostname.split('.')
            if len(subdomain_parts) > 3 and not hostname.startswith('www.'):
                flags.append("Excessive subdomains masking the real domain owner")
                if risk_level != "Malicious":
                    risk_level = "Suspicious"

            # Check 5: Suspicious keywords in host or path
            combined_url_str = (hostname + path).lower()
            matched_keywords = [kw for kw in SUSPICIOUS_URL_KEYWORDS if kw in combined_url_str]
            if matched_keywords:
                flags.append(f"Sensitive phishing keywords found in URL: '{', '.join(matched_keywords[:3])}'")
                risk_level = "Malicious"

            # Check 6: Insecure HTTP
            if clean_url.startswith('http://') and not clean_url.startswith('https://'):
                flags.append("Unencrypted connection (HTTP instead of secure HTTPS)")

            if not flags:
                flags.append("Standard domain structure; no overt structural anomalies detected.")

            scanned_links.append({
                'url': clean_url,
                'hostname': hostname,
                'risk_level': risk_level,
                'flags': flags
            })

        return scanned_links

    def detect_category(self, text: str, is_spam: bool) -> str:
        """Determines the specific scam category or returns Legitimate."""
        if not is_spam:
            return "Safe / Legitimate"

        text_lower = text.lower()
        matched_scores = {}

        for category, patterns in CATEGORY_RULES.items():
            score = 0
            for pattern in patterns:
                matches = len(re.findall(pattern, text_lower))
                score += matches
            if score > 0:
                matched_scores[category] = score

        if matched_scores:
            # Pick category with highest matched rules
            return max(matched_scores.items(), key=lambda x: x[1])[0]

        return "General Spam / Phishing"

    def get_safety_tips(self, category: str, has_suspicious_links: bool) -> list:
        """Returns 2-3 tailored actionable safety tips based on scam category."""
        tips_map = {
            'Fake KYC / Banking': [
                "Banks and RBI never ask for PAN, Aadhaar, or NetBanking updates through SMS links.",
                "Never click links claiming your account will be suspended; check your status directly in your official banking app.",
                "If in doubt, call the official toll-free customer care number printed on the back of your debit card."
            ],
            'Lottery / Reward Scam': [
                "You cannot win a lottery or contest you never purchased a ticket for or entered.",
                "Never pay 'processing charges', 'GST', or 'clearance fees' to claim a prize - real prizes never ask for advance payments.",
                "Do not call unknown phone numbers or WhatsApp contacts mentioned in reward messages."
            ],
            'OTP Fraud': [
                "NEVER share your OTP with anyone over the phone or SMS. Bank employees will never ask for it.",
                "An OTP is used to approve a debit or transfer. Sharing it authorizes money to leave your account.",
                "If you receive an unexpected OTP, do not share it and immediately lock your card/account via your banking app."
            ],
            'Electricity Bill Disconnection': [
                "Power distribution companies issue official notices on physical bills, not sudden same-day disconnection SMS with personal numbers.",
                "Never pay bills to personal UPI IDs or call personal numbers provided in such alerts.",
                "Check and pay your electricity dues only on your state power board's official portal or verified bill apps."
            ],
            'Fake Job Offer': [
                "Legitimate companies like Amazon, Google, or TCS never charge registration or interview fees.",
                "Earning thousands per day for simply 'liking YouTube videos' or 'rating Google reviews' is a classic task fraud trap.",
                "Do not join unofficial Telegram channels or deposit security money for job offers."
            ],
            'Promotional / Marketing': [
                "Look for an official 'Opt-Out' or 'STOP' instruction if receiving unsolicited marketing messages.",
                "Be wary of deals that seem unrealistically discounted (e.g. 90% off flagship electronics).",
                "Shop only on verified, official brand applications or stores."
            ],
            'Phishing / Account Theft': [
                "Inspect sender email addresses and links closely; look for subtle misspellings in domain names.",
                "Never enter passwords or confidential credentials on websites reached via an SMS or email link.",
                "Enable Two-Factor Authentication (2FA) with an authenticator app across all your online accounts."
            ],
            'Safe / Legitimate': [
                "This message does not exhibit known scam patterns, but always verify before sending money.",
                "Never share sensitive passwords or PINs over unencrypted communication channels.",
                "Keep your phone and messaging apps updated to protect against modern security exploits."
            ]
        }

        tips = tips_map.get(category, tips_map['Phishing / Account Theft'])[:]
        if has_suspicious_links and category != 'Safe / Legitimate':
            tips[0] = "DO NOT click the embedded link: it leads to a suspicious or phishing-flagged destination."
        return tips[:3]

    def explain_prediction(self, original_text: str):
        """
        Explainable AI Engine:
        - Identifies words that contributed toward the spam verdict using model log-odds
        - Generates highlighted HTML text where background opacity corresponds to word impact
        - Extracts top-5 most influential spam trigger keywords with explanation
        """
        # Tokenize preserving original casing and punctuation for HTML reconstruction
        tokens_with_delims = re.findall(r'(\w+|[^\w\s]+|\s+)', original_text)

        word_scores = []
        html_parts = []

        max_weight = 1.0
        # Find positive weights present in text
        positive_weights = []
        for token in tokens_with_delims:
            clean_tok = token.strip().lower()
            if clean_tok in self.word_weights and self.word_weights[clean_tok] > 0:
                positive_weights.append(self.word_weights[clean_tok])

        if positive_weights:
            max_weight = max(positive_weights)

        for token in tokens_with_delims:
            clean_tok = token.strip().lower()
            if clean_tok in self.word_weights and self.word_weights[clean_tok] > 0:
                w = self.word_weights[clean_tok]
                # Normalized weight between 0.2 and 0.85 for CSS opacity
                norm_intensity = min(0.9, max(0.2, (w / max_weight) * 0.9))
                # Tooltip and span
                escaped_tok = token.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                span = (
                    f'<span class="xai-highlight" '
                    f'style="background-color: rgba(239, 68, 68, {norm_intensity:.2f});" '
                    f'title="Spam impact weight: +{w:.2f}" '
                    f'data-weight="{w:.2f}">{escaped_tok}</span>'
                )
                html_parts.append(span)
                word_scores.append((clean_tok, w))
            else:
                escaped_tok = token.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                html_parts.append(escaped_tok)

        highlighted_html = "".join(html_parts)

        # Aggregate unique top words
        unique_words = {}
        for w, score in word_scores:
            if w not in unique_words or score > unique_words[w]:
                unique_words[w] = score

        sorted_words = sorted(unique_words.items(), key=lambda x: x[1], reverse=True)[:5]

        top_reasons = []
        for word, score in sorted_words:
            # Impact description
            if score >= 4.0:
                impact = "Critical"
                desc = "Very strong statistical spam marker in training dataset"
            elif score >= 2.5:
                impact = "High"
                desc = "Frequent indicator in fraud & spam communications"
            elif score >= 1.0:
                impact = "Medium"
                desc = "Moderately elevated spam probability"
            else:
                impact = "Low"
                desc = "Slight spam correlation"

            top_reasons.append({
                'word': word,
                'weight': round(score, 2),
                'impact': impact,
                'explanation': desc
            })

        return highlighted_html, top_reasons

    def analyze(self, text: str, subject: str = "") -> dict:
        """
        Complete analysis pipeline for a message:
        Returns verdict, risk score, confidence, category, explainability, links, and tips.
        """
        if not text or not text.strip():
            return {
                'success': False,
                'error': 'Message content cannot be empty.'
            }

        full_content = f"{subject}\n{text}".strip() if subject.strip() else text.strip()
        cleaned = self.clean_text_inference(full_content)

        # 1. Scan links
        links = self.scan_links(full_content)
        malicious_links = sum(1 for l in links if l['risk_level'] == 'Malicious')
        suspicious_links = sum(1 for l in links if l['risk_level'] == 'Suspicious')
        has_flagged_links = (malicious_links + suspicious_links) > 0

        # 2. Model Prediction
        if self.model and self.vectorizer and cleaned:
            X_vec = self.vectorizer.transform([cleaned])
            probs = self.model.predict_proba(X_vec)[0]
            # Class 0 = Ham, Class 1 = Spam
            ham_prob = float(probs[0])
            spam_prob = float(probs[1])
        else:
            # Fallback heuristic if model not loaded
            spam_prob = 0.5 if has_flagged_links else 0.1
            ham_prob = 1.0 - spam_prob

        # 3. Calculate Risk Score (0 - 100)
        # Base probability from ML model
        base_score = spam_prob * 100

        # Heuristic adjustments for high-risk links or urgent scam keywords
        if malicious_links > 0:
            base_score = max(base_score, 85.0)  # High risk if explicit malicious link present
        elif suspicious_links > 0:
            base_score = max(base_score, 55.0)  # At least suspicious

        risk_score = int(round(min(100.0, max(0.0, base_score))))

        # 4. Determine Verdict
        if risk_score >= 65:
            verdict = "SPAM"
            confidence = round(spam_prob * 100, 1) if spam_prob >= 0.5 else round((risk_score / 100) * 100, 1)
        elif risk_score >= 35:
            verdict = "SUSPICIOUS"
            confidence = round(max(spam_prob, ham_prob) * 100, 1)
        else:
            verdict = "SAFE"
            confidence = round(ham_prob * 100, 1)

        is_spam_verdict = verdict in ["SPAM", "SUSPICIOUS"]

        # 5. Scam Category Detection
        category = self.detect_category(full_content, is_spam_verdict)

        # 6. Explainable AI Highlights & Top Flagged Words
        highlighted_html, top_words = self.explain_prediction(full_content)

        # 7. Safety Recommendations
        safety_tips = self.get_safety_tips(category, has_flagged_links)

        return {
            'success': True,
            'verdict': verdict,
            'risk_score': risk_score,
            'confidence': confidence,
            'category': category,
            'model_name': self.model_name,
            'highlighted_html': highlighted_html,
            'top_words': top_words,
            'links': links,
            'links_count': len(links),
            'suspicious_links_count': malicious_links + suspicious_links,
            'safety_tips': safety_tips,
            'text_length': len(full_content),
            'subject': subject.strip()
        }


# Singleton engine instance
detector = SpamDetectorEngine()
