# detection/sigma_engine.py
import os
import yaml
import logging
from pathlib import Path
from datetime import datetime, timedelta

from automation.shuffle_client import trigger_shuffle_playbook
from automation.containment import block_ip
from ai_learning.rule_updater import RuleUpdater

logger = logging.getLogger(__name__)

class SigmaEngine:
    def __init__(self, rules_dir="detection/rules/sigma/"):
        self.rules_dir = Path(rules_dir)
        self.rules = []
        self.alerts = []
        self.event_history = []  # In-memory buffer for frequency-based detection
        self.rule_updater = RuleUpdater()
        self.load_rules()

    def load_rules(self):
        """Load all Sigma rules from YAML files in the rules directory."""
        if not self.rules_dir.exists():
            logger.error(f"[SIGMA] Rules directory not found: {self.rules_dir}")
            return

        loaded_count = 0
        for file_path in self.rules_dir.glob("*.yml"):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    rule = yaml.safe_load(f)
                    self.rules.append(rule)
                    logger.info(f"[SIGMA] Loaded rule: {rule.get('title')} (ID: {rule.get('id')})")
                    loaded_count += 1
            except Exception as e:
                logger.error(f"[SIGMA] Failed to load {file_path}: {e}")

        logger.info(f"[SIGMA] Total Sigma rules loaded: {loaded_count}")

    def check_event(self, event):
        """
        Check if the given event matches any Sigma rule.
        Handles both direct matches and frequency-based conditions.
        """
        # Add event to history for temporal analysis
        self.event_history.append({
            "timestamp": datetime.utcnow(),
            "event_type": event.get("event_type"),
            "ip": event.get("ip"),
            "user": event.get("user"),
            "severity": event.get("severity")
        })

        # Clean up old events (> 10 minutes)
        cutoff = datetime.utcnow() - timedelta(minutes=10)
        self.event_history = [e for e in self.event_history if e["timestamp"] > cutoff]

        for rule in self.rules:
            try:
                if self._matches_rule(event, rule):
                    alert = {
                        "rule_id": rule["id"],
                        "rule_title": rule["title"],
                        "severity": rule["level"],
                        "match": event,
                        "timestamp": datetime.utcnow().isoformat() + "Z",
                        "description": rule["description"]
                    }
                    self.alerts.append(alert)

                    ip = event.get("ip", "unknown")
                    user = event.get("user", "unknown")
                    rule_title = rule["title"]

                    # Log alert
                    logger.warning(f"[ALERT] {rule['level'].upper()} - {rule_title} | IP: {ip} | User: {user}")

                    # Auto-contain threat
                    if rule["level"] in ["high", "critical"]:
                        block_ip(ip, rule_title)

                    # Trigger SOAR playbook
                    trigger_shuffle_playbook(
                        alert_type="sigma_alert",
                        ip=ip,
                        details=f"{rule_title}: {event.get('raw', 'No raw log')}"
                    )

                    # Feed into learning module
                    self.rule_updater.generate_sigma_rule_from_event(event, name_prefix="learned")

                    return alert
            except Exception as e:
                logger.error(f"[SIGMA] Error evaluating rule {rule.get('id')}: {e}")
        return None

    def _matches_rule(self, event, rule):
        """
        Check if the event matches the rule's selection criteria.
        Supports frequency-based conditions.
        """
        selection = rule.get("detection", {}).get("selection", {})

        # Field matching
        for key, value in selection.items():
            if event.get(key) != value:
                return False

        # Frequency-based detection (e.g., count() by ip > 3 in 60s)
        freq = rule.get("frequency")
        if freq:
            window_sec = int(freq.get("time_window", "60s").replace("s", ""))
            threshold = freq.get("threshold", 3)
            start_time = datetime.utcnow() - timedelta(seconds=window_sec)

            matching_events = [
                e for e in self.event_history
                if e["ip"] == event["ip"] and e["timestamp"] >= start_time
            ]
            return len(matching_events) >= threshold

        return True  # Simple field match