import subprocess
import sys
import nltk

def install_dependencies():
    print("Installing dependencies from requirements.txt...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])

def download_spacy_models():
    print("Downloading spaCy en_core_web_sm model...")
    subprocess.check_call([sys.executable, "-m", "spacy", "download", "en_core_web_sm"])

def download_nltk_data():
    print("Downloading NLTK data...")
    nltk.download('punkt')
    nltk.download('punkt_tab')
    nltk.download('stopwords')
    nltk.download('wordnet')
    nltk.download('omw-1.4')
    nltk.download('averaged_perceptron_tagger')

if __name__ == "__main__":
    print("Starting LEXA Environment Setup...")
    try:
        install_dependencies()
        download_spacy_models()
        download_nltk_data()
        print("\nSetup Content Completed Successfully.")
        print("Remember to copy .env.example to .env and set your VT_API_KEY if needed.")
    except Exception as e:
        print(f"Setup Failed: {e}")
        sys.exit(1)
