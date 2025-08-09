# ai_learning/feedback.py
import logging
import json
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)

PENDING_DIR = Path("ai_learning/pending_rules/")
ACTIVE_DIR = Path("detection/rules/sigma/")
REJECTED_DIR = Path("ai_learning/rejected_rules/")

for p in [PENDING_DIR, REJECTED_DIR]:
    p.mkdir(exist_ok=True)

class AnalystFeedback:
    def __init__(self):
        logger.info("[FEEDBACK] Analyst feedback system initialized.")

    def submit_rule_for_review(self, rule):
        """Submit an auto-generated rule for manual approval"""
        rule_id = rule["id"]
        filepath = PENDING_DIR / f"{rule_id}.yml"
        try:
            with open(filepath, "w") as f:
                json.dump(rule, f, indent=2)
            logger.info(f"[FEEDBACK] Rule submitted for review: {filepath}")
        except Exception as e:
            logger.error(f"[FEEDBACK] Failed to save rule: {e}")

    def approve_rule(self, rule_id):
        """Move rule from pending to active Sigma rules"""
        src = PENDING_DIR / f"{rule_id}.yml"
        dst = ACTIVE_DIR / f"{rule_id}.yml"
        if not src.exists():
            logger.error(f"[FEEDBACK] Rule not found in pending: {src}")
            return False
        try:
            import shutil
            shutil.move(str(src), str(dst))
            logger.info(f"[FEEDBACK] ✅ Rule approved and activated: {rule_id}")
            return True
        except Exception as e:
            logger.error(f"[FEEDBACK] Failed to approve rule: {e}")
            return False

    def reject_rule(self, rule_id):
        """Reject rule and move to rejected folder"""
        src = PENDING_DIR / f"{rule_id}.yml"
        dst = REJECTED_DIR / f"{rule_id}.yml"
        if not src.exists():
            logger.error(f"[FEEDBACK] Rule not found: {src}")
            return False
        try:
            import shutil
            shutil.move(str(src), str(dst))
            logger.warning(f"[FEEDBACK] ❌ Rule rejected: {rule_id}")
            return True
        except Exception as e:
            logger.error(f"[FEEDBACK] Failed to reject rule: {e}")
            return False

    def list_pending_reviews(self):
        """List all rules waiting for approval"""
        return [f.stem for f in PENDING_DIR.glob("*.yml")]