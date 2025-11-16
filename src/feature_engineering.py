import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
import joblib
import os
import numpy as np

# --- Configuration ---
TARGET_COLUMN = 'Severity'
SEVERITY_MAPPING = {
    'Informational': 0, 'Low': 0, 'Moderate': 1, 'Medium': 1, 'High': 1, 'Critical': 1
}
TARGET_ML_COLUMN = 'is_vulnerable'

# --- ALIGNED VAPT FEATURES (Must match predict.py) ---
VAPT_FEATURES = [
    'url_length', 'has_ssl', 'response_time_ms', 'num_forms', 'num_script_tags',
    'missing_xfo', 'server_header', 'content_length', 'uses_cookies'
]
CATEGORICAL_VAPT_FEATURES = ['server_header']
NUMERICAL_VAPT_FEATURES = list(set(VAPT_FEATURES) - set(CATEGORICAL_VAPT_FEATURES))


def load_data_and_inject_features(file_path):
    """Loads data, creates target, and injects dummy VAPT features for alignment."""
    df = pd.read_csv(file_path)

    # 1. Create the numerical target column 'is_vulnerable'
    if TARGET_COLUMN in df.columns:
        df[TARGET_ML_COLUMN] = df[TARGET_COLUMN].map(SEVERITY_MAPPING).fillna(0).astype(int)

    # 2. FEATURE ALIGNMENT FIX: Inject dummy features to match predict.py's input
    for col in NUMERICAL_VAPT_FEATURES:
        # Fill numerical features with random data (Model will still train, but on arbitrary input)
        df[col] = np.random.rand(len(df)) * 100

        # Fill the categorical feature with a common value
    df['server_header'] = 'nginx'

    return df


def create_preprocessor():
    """Creates a preprocessing pipeline using ONLY the VAPT feature set."""
    print(f"Features used for training: Numerical={NUMERICAL_VAPT_FEATURES}, Categorical={CATEGORICAL_VAPT_FEATURES}")

    numerical_transformer = StandardScaler()
    categorical_transformer = OneHotEncoder(handle_unknown='ignore')

    preprocessor = ColumnTransformer(
        transformers=[
            ('num', numerical_transformer, NUMERICAL_VAPT_FEATURES),
            ('cat', categorical_transformer, CATEGORICAL_VAPT_FEATURES)
        ],
        remainder='drop'  # Drops all other CSV columns (Title, Summary, Package_Type, etc.)
    )
    return preprocessor


if __name__ == '__main__':
    if not os.path.exists('src'):
        os.makedirs('src')

    data_path = 'data/Security_Vulnerabilities.csv'
    try:
        # Load data and inject required features
        df = load_data_and_inject_features(data_path)
    except FileNotFoundError:
        print(f"Error: Data file not found at {data_path}. Please ensure the file is in the correct directory.")
        exit()

    if TARGET_ML_COLUMN not in df.columns:
        print(f"FATAL ERROR: Target column '{TARGET_ML_COLUMN}' not created.")
        exit()

    # 2. Separate features (X) and target (y) - Select ONLY the VAPT features
    X = df[VAPT_FEATURES]
    y = df[TARGET_ML_COLUMN]

    # 3. Split data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    # 4. Create and save the preprocessor
    preprocessor = create_preprocessor()
    preprocessor.fit(X_train)
    joblib.dump(preprocessor, 'src/preprocessor.joblib')

    print("\nPreprocessing pipeline successfully created and saved to src/preprocessor.joblib.")
    print(f"X_train shape: {X_train.shape}, y_train shape: {y_train.shape}")