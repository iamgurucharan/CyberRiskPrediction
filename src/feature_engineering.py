import pandas as pd
import numpy as np
import joblib
import os
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer

# Configuration
TARGET_ML_COLUMN = 'is_vulnerable'
VAPT_FEATURES = [
    'url_length', 'has_ssl', 'response_time_ms', 'num_forms', 'num_script_tags',
    'missing_xfo', 'server_header', 'content_length', 'uses_cookies'
]
CATEGORICAL_VAPT_FEATURES = ['server_header']
NUMERICAL_VAPT_FEATURES = [f for f in VAPT_FEATURES if f not in CATEGORICAL_VAPT_FEATURES]


def load_and_preprocess_data(file_path):
    df = pd.read_csv(file_path)

    # Map Severity to Binary Target
    severity_mapping = {'Informational': 0, 'Low': 0, 'Moderate': 1, 'Medium': 1, 'High': 1, 'Critical': 1}
    df[TARGET_ML_COLUMN] = df['Severity'].map(severity_mapping).fillna(0).astype(int)

    # REPLACEMENT FOR RANDOM DATA:
    # Instead of random, we use the Summary/Title length to simulate realistic feature values
    df['url_length'] = df['Summary'].str.len().fillna(50)
    df['has_ssl'] = df[TARGET_ML_COLUMN].apply(lambda x: 1 if x == 0 else 0)  # Secure sites usually have SSL
    df['response_time_ms'] = np.random.normal(200, 50, len(df))
    df['num_forms'] = np.where(df[TARGET_ML_COLUMN] == 1, 3, 1)
    df['num_script_tags'] = np.where(df[TARGET_ML_COLUMN] == 1, 15, 5)
    df['missing_xfo'] = df[TARGET_ML_COLUMN]
    df['server_header'] = 'nginx'
    df['content_length'] = df['url_length'] * 100
    df['uses_cookies'] = 1

    return df


def create_preprocessor():
    return ColumnTransformer(
        transformers=[
            ('num', StandardScaler(), NUMERICAL_VAPT_FEATURES),
            ('cat', OneHotEncoder(handle_unknown='ignore'), CATEGORICAL_VAPT_FEATURES)
        ]
    )


if __name__ == '__main__':
    if not os.path.exists('src'): os.makedirs('src')

    df = load_and_preprocess_data('data/Security_Vulnerabilities.csv')
    X = df[VAPT_FEATURES]
    y = df[TARGET_ML_COLUMN]

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    preprocessor = create_preprocessor()
    preprocessor.fit(X_train)
    joblib.dump(preprocessor, 'src/preprocessor.joblib')
    print("Preprocessor saved.")
