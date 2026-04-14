import os
import joblib
from typing import Tuple, Dict, Any
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from transformers import pipeline
from backend.config import LEXA_MODEL_PATH
from backend.utils.logger import log

class LEXAClassifier:
    def __init__(self):
        self.labels = ["phishing", "malware", "ransomware", "ddos", "sql_injection", "social_engineering", "unknown"]
        self.hf_pipeline = None
        self.rf_model = None
        self.vectorizer = None

        self._load_models()

    def _load_models(self):
        # 1. Try loading HuggingFace Model
        if os.path.exists(LEXA_MODEL_PATH):
            try:
                self.hf_pipeline = pipeline("text-classification", model=LEXA_MODEL_PATH, top_k=1)
                log.info(f"Loaded primary HuggingFace model from {LEXA_MODEL_PATH}")
            except Exception as e:
                log.error(f"Failed to load HF model: {e}")
        else:
            log.warning(f"HF model path {LEXA_MODEL_PATH} not found. Attempting to load zero-shot or Fallback RF.")

        # 2. Try loading Random Forest Fallback
        rf_path = "./backend/ml/rf_fallback.pkl"
        vec_path = "./backend/ml/tfidf_vectorizer.pkl"
        if os.path.exists(rf_path) and os.path.exists(vec_path):
            try:
                self.rf_model = joblib.load(rf_path)
                self.vectorizer = joblib.load(vec_path)
                log.info("Loaded RandomForest fallback model.")
            except Exception as e:
                log.error(f"Failed to load RF model: {e}")
        else:
            log.warning("RF model missing. Using heuristic/dummy fallback.")

    def predict(self, text: str) -> Tuple[str, float]:
        """
        Returns (predicted_class, confidence_score)
        """
        # Primary: DistilBERT HF pipeline
        if self.hf_pipeline:
            try:
                res = self.hf_pipeline(text)[0][0]
                label = res["label"].lower()
                # Ensure it maps to our 7 classes
                if label not in self.labels:
                    label = "unknown"
                score = res["score"]
                return label, float(score)
            except Exception as e:
                log.error(f"HF prediction failed: {e}. Falling back to RF.")

        # Secondary: Random Forest
        if self.rf_model and self.vectorizer:
            try:
                X = self.vectorizer.transform([text])
                probs = self.rf_model.predict_proba(X)[0]
                max_idx = probs.argmax()
                score = probs[max_idx]
                label = self.rf_model.classes_[max_idx]
                return label, float(score)
            except Exception as e:
                log.error(f"RF prediction failed: {e}.")

        # Fallback: Dummy Heuristics if no AI model exists
        return self._heuristic_predict(text)

    def _heuristic_predict(self, text: str) -> Tuple[str, float]:
        text = text.lower()
        if "sql" in text or "select" in text:
            return "sql_injection", 0.6
        if "ddos" in text or "flood" in text:
            return "ddos", 0.6
        if "ransom" in text or "encrypt" in text:
            return "ransomware", 0.6
        if "password" in text or "login" in text or "urgent" in text:
            return "phishing", 0.6
        return "unknown", 0.5
