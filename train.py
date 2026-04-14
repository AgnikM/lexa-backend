import os
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from backend.utils.logger import log

def generate_mock_datasets():
    os.makedirs("./backend/data/datasets", exist_ok=True)
    csv_path = "./backend/data/datasets/mock_threats.csv"
    
    if not os.path.exists(csv_path):
        data = {
            "text": [
                "urgent verify your bank account details",
                "select * from users where id=1 drop table users;",
                "massive incoming traffic targeting our web server",
                "your files have been encrypted send bitcoin",
                "click here to claim your prize",
                "malicious exe payload running in memory",
                "could not identify this traffic"
            ],
            "label": [
                "phishing",
                "sql_injection",
                "ddos",
                "ransomware",
                "phishing",
                "malware",
                "unknown"
            ]
        }
        df = pd.DataFrame(data)
        df.to_csv(csv_path, index=False)
        log.info(f"Created mock dataset at {csv_path}")

def train_fallback_rf():
    """Trains a simple Random Forest model on the mock dataset."""
    os.makedirs("./backend/ml", exist_ok=True)
    csv_path = "./backend/data/datasets/mock_threats.csv"
    
    if not os.path.exists(csv_path):
        log.error("Dataset not found. Run dataset generator first.")
        return

    df = pd.read_csv(csv_path)
    
    vectorizer = TfidfVectorizer(stop_words='english', max_features=5000)
    X = vectorizer.fit_transform(df['text'])
    y = df['label']

    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X, y)

    # Save
    joblib.dump(clf, "./backend/ml/rf_fallback.pkl")
    joblib.dump(vectorizer, "./backend/ml/tfidf_vectorizer.pkl")
    log.info("Successfully trained and saved fallback RF model.")

if __name__ == "__main__":
    generate_mock_datasets()
    train_fallback_rf()
