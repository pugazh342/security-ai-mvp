# parser/log_parser.py
import re
import logging
import yaml
from datetime import datetime
from config import load_config

logger = logging.getLogger(__name__)

class LogParser:
    def __init__(self, patterns_file="parser/patterns.yaml"):
        self.config = load_config()
        self.patterns = []
        self.load_patterns(patterns_file)
        logger.info(f"[PARSER] Successfully loaded {len(self.patterns)} log parsing patterns.")

    def load_patterns(self, filepath):
        """Load regex patterns from YAML configuration."""
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                for item in data["patterns"]:
                    compiled_regex = re.compile(item["regex"])
                    self.patterns.append({
                        "name": item["name"],
                        "regex": compiled_regex,
                        "event_type": item["event_type"],
                        "severity": item["severity"]
                    })
        except Exception as e:
            logger.error(f"[PARSER] Failed to load patterns from {filepath}: {e}")
            raise

    def parse(self, raw_log: str):
        """
        Parse a raw log line into structured JSON format.
        Returns a dictionary with extracted fields or None if no match.
        """
        if not raw_log or not raw_log.strip():
            return None

        raw_log = raw_log.strip()
        for pattern in self.patterns:
            match = pattern["regex"].match(raw_log)
            if match:
                event = match.groupdict()
                event.update({
                    "event_type": pattern["event_type"],
                    "severity": pattern["severity"],
                    "raw": raw_log,
                    "parsed_at": datetime.utcnow().isoformat() + "Z"
                })
                return event

        # Fallback for unmatched logs
        logger.warning(f"[PARSER] No pattern matched for log entry: {raw_log}")
        return {
            "raw": raw_log,
            "event_type": "unknown",
            "severity": "unknown",
            "parsed_at": datetime.utcnow().isoformat() + "Z"
        }