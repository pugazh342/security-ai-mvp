# run.py
import sys
import io
import logging
from config import load_config
from collectors.log_collector import LogCollector
from automation.containment import block_ip
from parser.log_parser import LogParser
from detection.sigma_engine import SigmaEngine
from detection.yara_scanner import YARAScanner
from detection.shuffle_client import trigger_shuffle_playbook

# Force UTF-8 encoding for Windows compatibility
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

# Load config
config = load_config()

# Setup logging
logging.basicConfig(
    level=config['logging']['level'],
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(config['logging']['file'], encoding='utf-8'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)


def main():
    logger.info("[START] Starting Free AI-Powered Security MVP")

    # Initialize components
    parser = LogParser()
    sigma_engine = SigmaEngine()

    # Start log collector and pass parser/engine to it
    collector = LogCollector(parser, sigma_engine)
    collector.start()

    try:
        while True:
            input("Press Enter to exit...\n")
    except KeyboardInterrupt:
        logger.info("[STOP] Shutting down MVP...")
        collector.stop()


if __name__ == "__main__":
    main()# run.py
import sys
import io
import logging
from config import load_config
from collectors.log_collector import LogCollector
from parser.log_parser import LogParser
from detection.sigma_engine import SigmaEngine
from detection.anomaly_detector import AnomalyDetector
from detection.yara_scanner import YARAScanner

# UTF-8 fix for Windows
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

config = load_config()
logging.basicConfig(
    level=config['logging']['level'],
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(config['logging']['file'], encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def main():
    logger.info("[START] Security MVP is starting...")

    # Initialize components
    parser = LogParser()
    sigma_engine = SigmaEngine()
    anomaly_detector = AnomalyDetector()
    yara_scanner = YARAScanner()

    # Start collector
    collector = LogCollector(parser, sigma_engine, anomaly_detector, yara_scanner)
    collector.start()

    try:
        input("Press Enter to exit...\n")
    except KeyboardInterrupt:
        logger.info("[STOP] Shutting down...")
        collector.stop()

if __name__ == "__main__":
    main()