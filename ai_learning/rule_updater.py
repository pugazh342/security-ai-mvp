# ai_learning/rule_updater.py
import logging
import yaml
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)

class RuleUpdater:
    def __init__(self, sigma_rules_dir="detection/rules/sigma/"):
        self.sigma_rules_dir = Path(sigma_rules_dir)
        self.sigma_rules_dir.mkdir(parents=True, exist_ok=True)
        logger.info("[LEARNING] RuleUpdater initialized.")

    def generate_sigma_rule_from_event(self, event, name_prefix="auto"):
        """
        Automatically generate a Sigma rule from a suspicious event.
        """
        rule_id = f"{name_prefix}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        title = f"Auto-generated: Suspicious {event.get('event_type')} from {event.get('ip')}"
        ip = event.get("ip")
        user = event.get("user")

        # Simple rule template
        rule = {
            "title": title,
            "id": rule_id,
            "status": "experimental",
            "description": "Automatically generated due to anomalous behavior.",
            "author": "AI-Learning-Module",
            "date": datetime.utcnow().strftime("%Y-%m-%d"),
            "logsource": {
                "category": "authentication",
                "product": "custom-app"
            },
            "detection": {
                "selection": {
                    "ip": ip,
                    "event_type": event.get("event_type")
                },
                "condition": "selection"
            },
            "level": "high"
        }

        # Save to file
        rule_path = self.sigma_rules_dir / f"{rule_id}.yml"
        try:
            with open(rule_path, "w", encoding="utf-8") as f:
                yaml.dump(rule, f, indent=2)
            logger.info(f"[LEARNING] Generated new Sigma rule: {rule_path}")
        except Exception as e:
            logger.error(f"[LEARNING] Failed to save rule: {e}")

    def update_heuristic_model(self):
        """
        Placeholder: Retrain PyOD model with new labeled data
        Future: Use feedback loop from analyst or Shuffle
        """
        logger.info("[LEARNING] Heuristic model update triggered (stub).")