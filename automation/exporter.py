# automation/exporter.py
import logging
import requests
from datetime import datetime

logger = logging.getLogger(__name__)

# Configure your MISP instance
MISP_URL = "https://your-misp-instance.com"
MISP_API_KEY = "YOUR_API_KEY"
MISP_VERIFY_CERT = False  # Set to True in production

def export_to_misp(ip: str, event_type: str, description: str = "Auto-detected by Security MVP"):
    """Export a malicious IP to MISP as an event"""
    headers = {
        "Authorization": MISP_API_KEY,
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    data = {
        "Event": {
            "info": f"Security MVP Alert: {event_type}",
            "distribution": 1,  # Org-only
            "threat_level_id": 2,  # Medium
            "analysis": 2,  # TLP: Amber
            "date": datetime.utcnow().strftime("%Y-%m-%d"),
            "Attribute": [
                {
                    "type": "ip-dst",
                    "category": "Network activity",
                    "value": ip,
                    "to_ids": True,
                    "comment": description
                }
            ]
        }
    }

    try:
        resp = requests.post(
            f"{MISP_URL}/events",
            json=data,
            headers=headers,
            verify=MISP_VERIFY_CERT
        )
        if resp.status_code in [200, 201]:
            logger.info(f"[EXPORT] Successfully sent IP {ip} to MISP")
            return True
        else:
            logger.error(f"[EXPORT] MISP API error {resp.status_code}: {resp.text}")
    except Exception as e:
        logger.error(f"[EXPORT] Failed to connect to MISP: {e}")
    return False