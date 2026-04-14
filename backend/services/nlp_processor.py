import re
import spacy
import nltk
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer
from nltk.tokenize import word_tokenize
from backend.utils.logger import log

class ThreatNLPProcessor:
    def __init__(self):
        try:
            self.nlp = spacy.load("en_core_web_sm")
        except OSError:
            log.warning("Spacy en_core_web_sm not found. Falling back to simple parsing or rerun setup.py.")
            self.nlp = None

        try:
            self.stop_words = set(stopwords.words("english"))
            self.lemmatizer = WordNetLemmatizer()
        except Exception:
            log.warning("NLTK data not fully loaded. Rerun setup.py.")
            self.stop_words = set()
            self.lemmatizer = WordNetLemmatizer() # Might still fail if wordnet missing

        # Common indicators
        self.ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        self.url_pattern = re.compile(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+')
        self.hash_pattern = re.compile(r'\b([a-fA-F\d]{32}|[a-fA-F\d]{40}|[a-fA-F\d]{64})\b')
        self.cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}')

        # 42 terms mapped to keywords (simplified sample)
        self.threat_keywords = [
            "password", "login", "urgent", "account", "verify", "update", "bank",
            "ransom", "encrypt", "bitcoin", "payment", "malware", "payload",
            "ddos", "botnet", "flood", "sql", "injection", "select", "drop"
        ]

    def extract_iocs(self, text: str) -> dict:
        """Extract URLs, IPs, Hashes, CVEs"""
        iocs = {
            "urls": self.url_pattern.findall(text),
            "ips": self.ip_pattern.findall(text),
            "hashes": self.hash_pattern.findall(text),
            "cves": self.cve_pattern.findall(text),
            "entities": []
        }
        if self.nlp:
            doc = self.nlp(text)
            iocs["entities"] = [(ent.text, ent.label_) for ent in doc.ents if ent.label_ in ("ORG", "PERSON", "GPE")]
        return iocs

    def clean_text(self, text: str) -> str:
        """Lowercase, remove special chars, tokenize, lemmatize, remove stopwords"""
        text = text.lower()
        # Remove URLs and Hashes to prevent them from breaking the ML feature
        text = self.url_pattern.sub(" [URL] ", text)
        text = self.hash_pattern.sub(" [HASH] ", text)
        text = self.ip_pattern.sub(" [IP] ", text)

        # Remove punctuation except spaces
        text = re.sub(r'[^\w\s]', ' ', text)

        try:
            tokens = word_tokenize(text)
            tokens = [self.lemmatizer.lemmatize(t) for t in tokens if t not in self.stop_words]
            return " ".join(tokens)
        except LookupError:
            # Fallback if punkt is missing
            return text
