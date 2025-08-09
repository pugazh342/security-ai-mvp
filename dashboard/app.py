# dashboard/app.py
from flask import Flask, jsonify
import os
import re
from datetime import datetime

app = Flask(__name__)

LOG_FILE = "../logs/app.log"
BLOCKED_FILE = "../logs/blocked_ips.txt"

def read_log_lines(filepath, limit=100):
    if not os.path.exists(filepath):
        return []
    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()
    return [line.strip() for line in lines[-limit:]]

@app.route('/api/logs')
def get_logs():
    logs = []
    pattern = r'(\S+\s+\S+)\s+(\S+)\s+(AUTH|SECURITY):\s+(.*)'
    for line in read_log_lines(LOG_FILE):
        match = re.match(pattern, line)
        if match:
            timestamp, host, component, message = match.groups()
            logs.append({
                "time": timestamp,
                "host": host,
                "component": component,
                "message": message
            })
    return jsonify(logs)

@app.route('/api/alerts')
def get_alerts():
    alerts = []
    for line in read_log_lines("../logs/mvp.log"):
        if "[ALERT]" in line or "[ANOMALY]" in line:
            alerts.append({"text": line, "time": datetime.now().isoformat()})
    return jsonify(alerts[-20:])

@app.route('/api/blocked_ips')
def get_blocked_ips():
    ips = []
    for line in read_log_lines(BLOCKED_FILE):
        if "BLOCKED" in line:
            parts = line.split("|")
            ips.append({
                "timestamp": parts[0].strip(),
                "ip": parts[2].strip(),
                "reason": parts[3].strip()
            })
    return jsonify(ips)

if __name__ == '__main__':
    app.run(port=5000)