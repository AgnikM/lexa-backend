import os

# --- Model Loading Configuration ---
# If you place your pre-trained distilbert classification model at `./distilbert-threat-v1`,
# the app will load it smoothly.
# Otherwise, it falls back to a generic zero-shot HuggingFace model or a scikit-learn mock.

LEXA_MODEL_PATH = os.getenv("LEXA_MODEL_PATH", "./distilbert-threat-v1")

# VirusTotal Configuration
VT_API_KEY = os.getenv("VT_API_KEY", "")

# Rate Limiting
RATE_LIMIT = "100/day" # SlowAPI limit

# Database Configuration
DATABASE_URL = "sqlite+aiosqlite:///./lexa_data.db"
# Fallback for sync
SYNC_DATABASE_URL = "sqlite:///./lexa_data.db"
