Cyber Risk Prediction Model (VAPT Simulator) 🛡️

🎯 Overview

This project implements a functional Machine Learning pipeline designed to perform a simulated Vulnerability Assessment and Penetration Testing (VAPT) scan on a live website. It analyzes basic HTTP characteristics of a given URL and uses a trained Random Forest Classifier to predict its potential risk level.

The system provides a two-pronged risk report:

ML Risk Prediction: A quantitative prediction based on core website features.

Security Analysis: Actionable findings based on crucial HTTP security header checks (e.g., missing CSP, HSTS).

🧠 Technical Context & Feature Alignment

A key challenge was the feature set mismatch between the available training data (historical package vulnerabilities) and the required prediction input (live website features like url_length, server_header).

To create a fully runnable end-to-end pipeline, the training scripts (feature_engineering.py and ml_model.py) were fixed to inject dummy VAPT features for structural alignment.

Note: While the pipeline is technically functional and executes without errors, the ML model's risk score is based on arbitrary data due to this alignment requirement. The VAPT Findings (security header checks), however, are based on real-time data from the target URL.

📁 Project Structure

CyberRiskPrediction/
├── data/
│   └── Security_Vulnerabilities.csv  # Original training data source
├── src/
│   ├── feature_engineering.py        # Pipeline: data alignment, preprocessor creation.
│   ├── ml_model.py                   # Pipeline: model training and evaluation.
│   ├── predict.py                    # Pipeline: Live feature extraction and risk reporting.
│   ├── preprocessor.joblib           # (Artifact) Saved Scikit-learn ColumnTransformer.
│   └── random_forest_model.joblib    # (Artifact) Trained Random Forest model.
└── README.md                         # This file.


⚙️ Setup and Installation

1. Prerequisites

Ensure you have Python 3.x installed.

2. Virtual Environment Setup (Recommended)

# Create and activate the virtual environment
python -m venv venv
# On Windows
.\venv\Scripts\activate
# On macOS/Linux
source venv/bin/activate


3. Install Dependencies

The project relies on standard data science libraries and the requests library for web access.

pip install pandas scikit-learn joblib numpy requests


4. Data Placement

Place the Security_Vulnerabilities.csv file in the project's root directory.

▶️ Execution Guide

The entire pipeline must be run in the following sequence to generate the necessary, aligned model artifacts.

Step 1: Feature Engineering and Preprocessing (Alignment)

This script loads the data, injects the necessary VAPT features for alignment, fits the preprocessing tools, and saves the preprocessor.joblib.

python src/feature_engineering.py


Step 2: Model Training

This script loads the preprocessor, trains the Random Forest Classifier on the processed (aligned) data, evaluates performance, and saves the random_forest_model.joblib.

python src/ml_model.py


Step 3: Live Prediction and Reporting

This script runs the VAPT simulation on a sample URL (changeable inside the file), uses the saved artifacts to predict risk, and prints the full report.

python src/predict.py


Example Report Output

Testing prediction for URL: [https://www.google.com](https://www.google.com)
Prediction Status: VULNERABLE (High Risk)
Risk Score: 59.33% Risk

--- Top ML Reasons for Prediction ---
- url_length: 0.1257
- content_length: 0.1197
- response_time_ms: 0.1195
- uses_cookies: 0.1189
- missing_xfo: 0.1179

--- VAPT Findings ---
- High: Missing crucial HTTP headers: Content-Security-Policy, X-Frame-Options, Referrer-Policy. Risk of Clickjacking/XSS.
- Informational: Server version revealed in header: gws... Consider masking this.
