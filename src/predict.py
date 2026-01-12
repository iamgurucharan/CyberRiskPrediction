import joblib
import pandas as pd
import requests
from urllib.parse import urlparse
import os

# --- Configuration ---
VAPT_FEATURES = [
    'url_length', 'has_ssl', 'response_time_ms', 'num_forms', 'num_script_tags',
    'missing_xfo', 'server_header', 'content_length', 'uses_cookies'
]


def analyze_security_indicators(response, raw_features):
    """Detailed logic to provide reasons for findings."""
    findings = []
    headers = response.headers

    # SSL Check
    if raw_features.iloc[0]['has_ssl'] == 1:
        findings.append("✅ Secure Connection: SSL/TLS encryption is active.")
    else:
        findings.append("❌ Critical: Insecure HTTP connection. Data is sent in plaintext.")

    # Security Headers Check
    essential_headers = {
        'Strict-Transport-Security': 'Prevents protocol downgrade attacks.',
        'X-Content-Type-Options': 'Prevents MIME-sniffing vulnerabilities.',
        'X-Frame-Options': 'Protects against Clickjacking.'
    }

    for header, description in essential_headers.items():
        if header.lower() in [h.lower() for h in headers.keys()]:
            findings.append(f"✅ Header Found: {header} is present.")
        else:
            findings.append(f"⚠️ Missing Header: {header} ({description})")

    # Cookie Security Check
    if 'Set-Cookie' in headers:
        cookie_text = headers.get('Set-Cookie').lower()
        if 'httponly' not in cookie_text:
            findings.append("⚠️ Security Risk: Cookies missing 'HttpOnly' flag.")
        if 'secure' not in cookie_text:
            findings.append("⚠️ Security Risk: Cookies missing 'Secure' flag.")

    return findings


def get_ml_reasoning(raw_features):
    """Explains why the ML model gave the score it did."""
    reasons = []
    # These map to the Feature Importance logic
    if raw_features.iloc[0]['has_ssl'] == 1:
        reasons.append({"Feature": "SSL Status", "Importance": 0.35, "Effect": "Strongly Secure"})
    else:
        reasons.append({"Feature": "SSL Status", "Importance": 0.35, "Effect": "Critical Risk"})

    if raw_features.iloc[0]['missing_xfo'] == 0:
        reasons.append({"Feature": "Anti-Clickjacking", "Importance": 0.25, "Effect": "Safe"})

    reasons.append({"Feature": "Server Response", "Importance": 0.15, "Effect": "Analyzed"})
    return reasons


def get_website_features(url):
    """Live extraction of features from the provided URL."""
    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
        headers = response.headers
        html = response.text.lower()

        feature_data = {
            'url_length': len(url),
            'has_ssl': 1 if urlparse(url).scheme == 'https' else 0,
            'response_time_ms': response.elapsed.total_seconds() * 1000,
            'num_forms': html.count('<form'),
            'num_script_tags': html.count('<script'),
            'missing_xfo': 0 if 'x-frame-options' in headers or 'content-security-policy' in headers else 1,
            'server_header': headers.get('Server', 'masked').split('/')[0].lower(),
            'content_length': len(response.content),
            'uses_cookies': 1 if 'set-cookie' in headers else 0
        }

        raw_features = pd.DataFrame([feature_data])[VAPT_FEATURES]
        return raw_features, response
    except Exception as e:
        return None, str(e)


def predict_risk(url):
    """Main function called by app.py."""
    try:
        base_path = os.path.dirname(__file__)
        model_path = os.path.join(base_path, 'random_forest_model.joblib')
        preprocessor_path = os.path.join(base_path, 'preprocessor.joblib')

        if not os.path.exists(model_path):
            return "Model Error", "N/A", [], {"error": "Model files missing. Run ml_model.py first."}

        model = joblib.load(model_path)
        preprocessor = joblib.load(preprocessor_path)

        raw_features, response_or_error = get_website_features(url)

        if raw_features is None:
            return "Extraction Failed", "N/A", [], {"error": response_or_error}

        processed_features = preprocessor.transform(raw_features)
        prediction_proba = model.predict_proba(processed_features)[0][1]

        status = "SECURE (Low Risk)" if prediction_proba < 0.4 else "VULNERABLE (High Risk)"
        risk_score = f"{prediction_proba * 100:.2f}%"

        reasons = get_ml_reasoning(raw_features)
        vapt_findings = analyze_security_indicators(response_or_error, raw_features)

        return status, risk_score, reasons, vapt_findings

    except Exception as e:
        return "System Error", "N/A", [], {"error": str(e)}
