# automation/containment.py
import logging

logger = logging.getLogger(__name__)

def block_ip(ip, reason):
    with open("logs/blocked_ips.txt", "a") as f:
        f.write(f"{ip} blocked - {reason}\n")
    logger.critical(f"[BLOCK] IP {ip} blocked: {reason}")