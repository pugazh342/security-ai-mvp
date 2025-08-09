# detection/yara_scanner.py
import yara
import logging
import os
from pathlib import Path
from datetime import datetime ,time

logger = logging.getLogger(__name__)

class YARAScanner:
    def __init__(self, rules_dir="detection/rules/yara/"):
        self.rules_dir = Path(rules_dir)
        self.compiled_rule = None
        self._load_rules()

    def _load_rules(self):
        """Compile YARA rules at startup"""
        rule_file = self.rules_dir / "malware.yar"
        if not rule_file.exists():
            logger.warning(f"[YARA] Rule file not found: {rule_file}")
            return

        try:
            self.compiled_rule = yara.compile(str(rule_file))
            logger.info(f"[YARA] Loaded rules from {rule_file}")
        except Exception as e:
            logger.error(f"[YARA] Failed to compile rules: {e}")

    def scan_file(self, file_path):
        """Scan a single file and return matches"""
        if not self.compiled_rule:
            return None

        try:
            matches = self.compiled_rule.match(file_path)
            if matches:
                result = [{
                    "rule": m.rule,
                    "tags": m.tags,
                    "matched_strings": [[s[0], s[1], s[2].decode(errors='replace')] for s in m.strings]
                } for m in matches]
                logger.warning(f"[YARA] Malicious file detected: {file_path} | Matches: {result}")
                return result
            return None
        except Exception as e:
            logger.error(f"[YARA] Error scanning {file_path}: {e}")
            return None

    def scan_directory(self, target_dir, extensions=None):
        """Continuously scan a directory for new/modified files"""
        target = Path(target_dir)
        if not target.exists():
            logger.error(f"[YARA] Target directory does not exist: {target}")
            return

        # Track file modification times
        file_mtime = {}

        logger.info(f"[YARA] Starting auto-scan on directory: {target}")
        while True:
            try:
                for file_path in target.rglob("*"):
                    if file_path.is_file() and self._is_target_file(file_path, extensions):
                        mtime = file_path.stat().st_mtime
                        if file_path not in file_mtime or file_mtime[file_path] < mtime:
                            logger.info(f"[YARA] Scanning new/modified file: {file_path}")
                            match = self.scan_file(str(file_path))
                            if match:
                                yield str(file_path), match
                            file_mtime[file_path] = mtime
                # Wait before next scan
                time.sleep(3)
            except KeyboardInterrupt:
                logger.info("[YARA] File monitoring stopped.")
                break
            except Exception as e:
                logger.error(f"[YARA] Error during directory scan: {e}")
                time.sleep(5)

    def _is_target_file(self, file_path, extensions=None):
        """Check if file should be scanned based on extension"""
        exts = extensions or ['.py', '.js', '.exe', '.dll', '.sh', '.bat', '.ps1']
        return file_path.suffix.lower() in exts