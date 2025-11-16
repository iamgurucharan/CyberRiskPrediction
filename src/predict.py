import joblib
import pandas as pd
import numpy as np
import requests
from urllib.parse import urlparse
import os

# --- Configuration for Alignment ---
# This list must match the feature names and order used for training the preprocessor.
VAPT_FEATURES = [
    'url_length', 'has_ssl', 'response_time_ms', 'num_forms', 'num_script_tags',
    'missing_xfo', 'server_header', 'content_length', 'uses_cookies'
]

# --- Setup ---
# Load the trained model and preprocessor (these files must exist from previous steps)
try:
    MODEL = joblib.load('src/random_forest_model.joblib')
    PREPROCESSOR = joblib.load('src/preprocessor.joblib')
except FileNotFoundError:
    print("Error: Model or Preprocessor not found. Run training scripts first.")
    MODEL = None
    PREPROCESSOR = None

# List of common security headers that a tool like Burp Suite would check for
SECURITY_HEADERS = [
    'X-Content-Type-Options', 'Content-Security-Policy',
    'Strict-Transport-Security', 'X-Frame-Options',
    'Referrer-Policy'
]


def get_website_features(url):
    """
    Simulates VAPT-like feature extraction from a live website via HTTP requests.
    (Features requiring BeautifulSoup are set to 0 to avoid dependency).
    """
    try:
        # Enforce a short timeout (5 seconds) to prevent application hangs
        response = requests.get(url, timeout=5, allow_redirects=True)
        response.raise_for_status()  # Raises an HTTPError if the status code is 4XX or 5XX

        headers = response.headers

        # 1. Feature Extraction (Data for ML Model Input)
        feature_data = {
            'url_length': len(url),
            'has_ssl': 1 if urlparse(url).scheme == 'https' else 0,
            'response_time_ms': response.elapsed.total_seconds() * 1000,
            # Features that required BeautifulSoup are set to 0 to avoid dependency
            'num_forms': 0,
            'num_script_tags': 0,
            'missing_xfo': 0 if 'X-Frame-Options' in headers else 1,
            'server_header': headers.get('Server', 'unknown').lower(),  # Categorical feature
            'content_length': len(response.content),
            'uses_cookies': 1 if 'Set-Cookie' in headers else 0
        }

        raw_features = pd.DataFrame([feature_data])

        # 2. VAPT Findings (Data for Report Display)
        vapt_findings = analyze_security_indicators(response, raw_features)

        # Ensure the feature DataFrame only contains the VAPT_FEATURES in the correct order
        raw_features = raw_features[VAPT_FEATURES]

        return raw_features, vapt_findings

    except requests.exceptions.Timeout:
        return None, {"error": "Request timed out (5s). The server is too slow or unresponsive."}
    except requests.exceptions.RequestException as e:
        return None, {"error": f"Failed to connect or invalid URL: {type(e).__name__}"}


def analyze_security_indicators(response, raw_features):
    """
    Simulates Burp Suite Scanner findings based on extracted HTTP features.
    This provides the 'reasoning' part of the VAPT report.
    """
    findings = []
    headers = response.headers

    # 1. SSL/TLS Checks
    if not raw_features.iloc[0]['has_ssl']:
        findings.append("Critical: HTTP (non-SSL) connection detected. Data is transmitted insecurely.")

    # 2. Missing Security Headers
    missing = [h for h in SECURITY_HEADERS if h not in headers]
    if missing:
        findings.append(f"High: Missing crucial HTTP headers: {', '.join(missing)}. Risk of Clickjacking/XSS.")

    # 3. Server Info Leakage
    server_header = headers.get('Server', 'unknown')
    if server_header != 'unknown' and len(server_header) > 10:
        findings.append(
            f"Informational: Server version revealed in header: {server_header[:10]}... Consider masking this.")

    # 4. Input Vectors
    if raw_features.iloc[0]['num_forms'] > 0:
        findings.append(
            f"Informational: {raw_features.iloc[0]['num_forms']} forms found. Potential input vectors for SQLi/XSS require manual testing.")

    return findings


def predict_risk(url):
    """Feeds extracted website features into the ML model for risk prediction."""
    if MODEL is None or PREPROCESSOR is None:
        # FIX: Return an empty list [] instead of None for top_reasons on failure
        return "Model Error", "Unknown", [], {"error": "Model or Preprocessor not loaded."}

    # 1. Extract Features & VAPT Findings
    raw_features, vapt_findings = get_website_features(url)

    if raw_features is None:
        # FIX: Return an empty list [] instead of None for top_reasons on failure
        return "Extraction Failed", "N/A", [], vapt_findings

    # 2. Preprocess
    try:
        # Extrapolar Testing: Apply preprocessor fit on training data to the new data
        processed_features = PREPROCESSOR.transform(raw_features)
    except ValueError as e:
        # FIX: Return a list containing an error message on failure
        return "Preprocessing Failed", "N/A", [
            {"error": f"Feature mismatch or unseen categorical value. Error: {e}"}], {
            "error": f"Preprocessing failed. Error: {e}"}

    # 3. Predict
    prediction_proba = MODEL.predict_proba(processed_features)[0]
    prediction = MODEL.predict(processed_features)[0]

    # Interpret results
    result_map = {0: 'SECURE (Low Risk)', 1: 'VULNERABLE (High Risk)'}
    status = result_map.get(prediction, 'UNKNOWN')
    risk_score = prediction_proba[1] * 100  # Probability of being VULNERABLE

    # 4. Feature Importance (For reasoning)
    feature_names = PREPROCESSOR.get_feature_names_out()
    importances = MODEL.feature_importances_

    feature_report = pd.DataFrame({
        'Feature': feature_names,
        'Importance': importances
    }).sort_values(by='Importance', ascending=False)

    # Select the top 5 most important features for the ML prediction report
    top_reasons = feature_report[feature_report['Importance'] > 0.001].head(5).to_dict('records')

    return status, f"{risk_score:.2f}% Risk", top_reasons, vapt_findings


if __name__ == '__main__':
    sample_url = 'https://www.google.com'

    print(f"Testing prediction for URL: {sample_url}")
    status, risk_score, top_reasons, vapt_findings = predict_risk(sample_url)

    print(f"Prediction Status: {status}")
    print(f"Risk Score: {risk_score}")

    print("\n--- Top ML Reasons for Prediction ---")

    # FIX: Check if the list contains an error message or is empty
    if top_reasons and 'error' in top_reasons[0]:
        print(f"ML Reasoning Error: {top_reasons[0]['error']}")
    elif not top_reasons:
        print("No significant features found for prediction.")
    else:
        for reason in top_reasons:
            # Clean up feature names for display
            clean_feature_name = reason['Feature'].replace('num__', '').replace('cat__server_header_', 'server_header_')
            print(f"- {clean_feature_name}: {reason['Importance']:.4f}")

    print("\n--- VAPT Findings ---")
    if isinstance(vapt_findings, dict) and 'error' in vapt_findings:
        print(f"VAPT Finding Error: {vapt_findings['error']}")
    else:
        for finding in vapt_findings:
            print(f"- {finding}")