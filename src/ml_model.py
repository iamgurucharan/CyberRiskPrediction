import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
from sklearn.model_selection import train_test_split
import pandas as pd
import os
import numpy as np

# --- Configuration (Copied from feature_engineering.py for robustness) ---
TARGET_COLUMN = 'Severity'
TARGET_ML_COLUMN = 'is_vulnerable'
SEVERITY_MAPPING = {
    'Informational': 0, 'Low': 0, 'Moderate': 1, 'Medium': 1, 'High': 1, 'Critical': 1
}
VAPT_FEATURES = [
    'url_length', 'has_ssl', 'response_time_ms', 'num_forms', 'num_script_tags',
    'missing_xfo', 'server_header', 'content_length', 'uses_cookies'
]
TARGET_COLUMN_ORIGINAL = TARGET_COLUMN


def load_data_and_inject_features(file_path):
    """Loads data, creates target, and injects dummy VAPT features for alignment."""
    df = pd.read_csv(file_path)

    if TARGET_COLUMN in df.columns:
        df[TARGET_ML_COLUMN] = df[TARGET_COLUMN].map(SEVERITY_MAPPING).fillna(0).astype(int)

    # Inject Dummy VAPT Features for Alignment
    numerical_vapt_features = list(set(VAPT_FEATURES) - set(['server_header']))
    for col in numerical_vapt_features:
        df[col] = np.random.rand(len(df)) * 100

    df['server_header'] = 'nginx'

    return df


def train_and_save_model(data_path):
    """
    Loads data, trains the Random Forest model, tests it (Interpolar),
    and saves the model artifact.
    """
    if not os.path.exists('src'):
        os.makedirs('src')

    # FIX: Use the VAPT-aligned data loading function
    df = load_data_and_inject_features(data_path)

    if TARGET_ML_COLUMN not in df.columns:
        print(f"FATAL ERROR: Target column '{TARGET_ML_COLUMN}' not found.")
        return

    # Prepare features: Select ONLY the VAPT features
    X = df[VAPT_FEATURES]
    y = df[TARGET_ML_COLUMN]

    # Split data for training and testing
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    # Load preprocessor
    try:
        preprocessor = joblib.load('src/preprocessor.joblib')
    except FileNotFoundError:
        print("Preprocessor (src/preprocessor.joblib) not found. Run feature_engineering.py first.")
        return

    X_train_processed = preprocessor.transform(X_train)
    X_test_processed = preprocessor.transform(X_test)

    # 1. Model Selection: Random Forest Classifier
    rf_model = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced')

    print("Training Random Forest Classifier...")
    rf_model.fit(X_train_processed, y_train)

    # 2. Model Testing (Interpolar)
    y_pred = rf_model.predict(X_test_processed)
    accuracy = accuracy_score(y_test, y_pred)

    print("--- Model Testing Results (Interpolar) ---")
    print(f"Accuracy: {accuracy:.4f}")
    # zero_division=0 prevents warnings when a class has no predictions
    print(classification_report(y_test, y_pred, target_names=['Secure (0)', 'Vulnerable (1)'], zero_division=0))

    # Save the model artifact for deployment
    joblib.dump(rf_model, 'src/random_forest_model.joblib')
    print("Model saved as src/random_forest_model.joblib")


if __name__ == '__main__':
    # Assuming 'Security_Vulnerabilities.csv' is in the root directory
    train_and_save_model('data/Security_Vulnerabilities.csv')