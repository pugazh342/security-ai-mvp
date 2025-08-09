# automation/shuffle_client.py
import logging
import requests

logger = logging.getLogger(__name__)
SHUFFLE_WEBHOOK_URL = "http://localhost:3000/api/v1/hooks/execute/YOUR_WEBHOOK_ID_HERE"

def trigger_shuffle_playbook(alert_type, ip, details=None):
    payload = {
        "source": "security-mvp",
        "alert_type": alert_type,
        "malicious_ip": ip,
        "details": details
    }
    try:
        resp = requests.post(SHUFFLE_WEBHOOK_URL, json=payload, timeout=5)
        if resp.status_code == 200:
            logger.info(f"[SOAR] Shuffle playbook triggered for IP: {ip}")
        else:
            logger.error(f"[SOAR] Shuffle returned {resp.status_code}: {resp.text}")
    except Exception as e:
        logger.error(f"[SOAR] Failed to reach Shuffle: {e}")