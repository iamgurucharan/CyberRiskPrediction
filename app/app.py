from flask import Flask, render_template, request
# Import prediction function from the src directory
import sys
import os

# Adjust the path to ensure Python can find the predict module in src/
# This is necessary because the Flask app is run from the 'app/' directory
# while the prediction script is in 'src/'.
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from src.predict import predict_risk

app = Flask(__name__)


@app.route('/', methods=['GET', 'POST'])
def index():
    report = None
    if request.method == 'POST':
        url = request.form.get('website_url')
        if url:
            # Call the ML prediction logic
            status, risk_score, reasons, vapt_findings = predict_risk(url)

            # Check for failure states reported by src/predict.py
            if 'Failed' in status:
                # If extraction or preprocessing failed, VAPT findings will contain the error dictionary
                report = {'error': vapt_findings.get('error', 'An unknown error occurred.'), 'url': url}
            else:
                # Successful analysis report
                report = {
                    'url': url,
                    'status': status,
                    'risk': risk_score,
                    'reasons': reasons,
                    'vapt_findings': vapt_findings
                }
        else:
            report = {'error': "Please enter a valid URL."}

    # Render the index.html template, passing the generated report data
    return render_template('index.html', report=report)


if __name__ == '__main__':
    # To run: FLASK_APP=app/app.py flask run
    # Set FLASK_APP=app/app.py (on Windows)
    app.run(debug=True)
