# collectors/log_collector.py
import logging
import os
import time
import threading
from pathlib import Path

logger = logging.getLogger(__name__)

class LogCollector:
    def __init__(self, parser, sigma_engine, anomaly_detector, yara_scanner=None):
        self.parser = parser
        self.sigma_engine = sigma_engine
        self.anomaly_detector = anomaly_detector
        self.yara_scanner = yara_scanner
        self.config = parser.config
        self.log_paths = self.config['collector']['log_paths']
        self.interval = self.config['collector']['watch_interval']
        self.running = False
        self.thread = None
        self.offsets = {}

    def _ensure_log_files(self):
        """Create mock log files if they don't exist."""
        for path in self.log_paths:
            if not os.path.exists(path):
                dir_path = os.path.dirname(path)
                Path(dir_path).mkdir(parents=True, exist_ok=True)
                with open(path, "w", encoding="utf-8") as f:
                    f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} localhost System started.\n")
                logger.info(f"[COLLECTOR] Created mock log file: {path}")

    def _tail_file(self, filepath):
        """Simulate tail -f behavior with parsing and detection."""
        if filepath not in self.offsets:
            self.offsets[filepath] = 0

        while self.running:
            try:
                if os.path.exists(filepath):
                    with open(filepath, "r", encoding="utf-8") as f:
                        f.seek(self.offsets[filepath])
                        lines = f.readlines()
                        self.offsets[filepath] = f.tell()

                        for line in lines:
                            line = line.strip()
                            if line:
                                structured_log = self.parser.parse(line)
                                if structured_log:
                                    logger.info(f"[PARSED] {structured_log}")
                                    # Send to detection engines
                                    self.sigma_engine.check_event(structured_log)
                                    self.anomaly_detector.add_event(structured_log)
                                    self.anomaly_detector.detect(structured_log)
                time.sleep(1)
            except Exception as e:
                logger.error(f"[COLLECTOR] Error reading {filepath}: {e}")
                time.sleep(self.interval)

    def start(self):
        """Start monitoring log files."""
        logger.info("[COLLECTOR] Starting log collector...")
        self._ensure_log_files()
        self.running = True

        for path in self.log_paths:
            thread = threading.Thread(target=self._tail_file, args=(path,), daemon=True)
            thread.start()
            logger.info(f"[COLLECTOR] Monitoring log file: {path}")

        logger.info(f"[COLLECTOR] Actively monitoring {len(self.log_paths)} log file(s).")

    def stop(self):
        """Stop the log collector."""
        self.running = False
        logger.info("[COLLECTOR] Log collector stopped.")