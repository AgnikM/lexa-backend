import json
import os
from typing import Dict, Any
from backend.utils.logger import log

class PlaybookEngine:
    def __init__(self):
        self.playbooks_dir = os.path.join("backend", "data", "playbooks")
        self.playbooks: Dict[str, dict] = {}
        self.load_playbooks()

    def load_playbooks(self):
        """Pre-load all JSON playbooks into memory"""
        if not os.path.exists(self.playbooks_dir):
            log.warning(f"Playbook directory {self.playbooks_dir} not found.")
            return

        for filename in os.listdir(self.playbooks_dir):
            if filename.endswith(".json"):
                threat_type = filename.replace(".json", "")
                with open(os.path.join(self.playbooks_dir, filename), "r") as f:
                    try:
                        self.playbooks[threat_type] = json.load(f)
                    except json.JSONDecodeError as e:
                        log.error(f"Failed to load playbook {filename}: {e}")

    def generate_playbook(self, threat_type: str, severity_score: float) -> dict:
        """
        Produce actionable responses based on threat_type and severity.
        If severity > 8.5, dynamically inject 'Critical' escalation actions.
        """
        # Fallback to unknown if not strictly matched
        if threat_type not in self.playbooks:
            threat_type = "unknown"
            
        base_playbook = self.playbooks.get(threat_type, {
            "summary": "No playbook available.",
            "actions": [],
            "prevention": [],
            "references": []
        })

        # Deep copy to avoid modifying the cached dictionary
        playbook = json.loads(json.dumps(base_playbook))

        # Severity Overrides Layer
        if severity_score >= 8.5:
            # Inject a critical response directive
            playbook["actions"].insert(0, {
                "description": "CRITICAL INCIDENT DECLARED. Paging Incident Response Team...",
                "priority": "Critical"
            })
            playbook["summary"] = f"[CRITICAL OVERRIDE] {playbook['summary']}"
        elif severity_score < 4.0:
            # Lower priority if score is low but label happened to trigger
            for action in playbook["actions"]:
                if action["priority"] == "High":
                    action["priority"] = "Medium"

        return playbook
