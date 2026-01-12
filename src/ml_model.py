import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
# Import the loading logic from our feature engineering script
from feature_engineering import load_and_preprocess_data, TARGET_ML_COLUMN, VAPT_FEATURES


def train_model():
    df = load_and_preprocess_data('data/Security_Vulnerabilities.csv')
    X = df[VAPT_FEATURES]
    y = df[TARGET_ML_COLUMN]

    # Load preprocessor
    preprocessor = joblib.load('src/preprocessor.joblib')
    X_processed = preprocessor.transform(X)

    # Train model with more conservative parameters
    model = RandomForestClassifier(n_estimators=100, max_depth=5, random_state=42, class_weight='balanced')
    model.fit(X_processed, y)

    joblib.dump(model, 'src/random_forest_model.joblib')
    print("Model trained and saved.")


if __name__ == '__main__':
    train_model()
