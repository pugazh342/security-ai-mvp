# 🔐 Free AI-Powered Security MVP

A free, open-source AI-driven cybersecurity platform that detects both **known** and **unknown threats**, automatically responds to incidents, and learns from new attack patterns.

Built with Python, Sigma, YARA, PyOD, and Shuffle — designed for startups, researchers, and security teams.

## 🚀 Vision

Develop a **free, self-learning security platform** that:
- Collects logs from systems and applications
- Detects known threats (via Sigma/YARA) and zero-day attacks (via AI)
- Automatically responds using SOAR playbooks
- Learns from new patterns and updates detection rules
- Is 100% open-source and self-hostable

## ✅ Features

| Feature | Description |
|-------|-------------|
| 📥 Log Collection | Monitor system, network, and app logs |
| 🔍 Signature Detection | Detect known threats using Sigma & YARA rules |
| 🤖 Anomaly Detection | Catch zero-day attacks using PyOD (AI) |
| 🤖 SOAR Automation | Auto-respond with Shuffle or Python scripts |
| 🧠 Adaptive Learning | Generate new rules from detected threats |
| 👨‍💼 Analyst Feedback | Human-in-the-loop approval for new rules |
| 📊 Dashboard | Visualize logs and alerts via Grafana |
| 🐳 Docker Ready | Full container support for easy deployment |

## 🏗️ Architecture Overview

```txt
[Data Sources]
     ↓
Log Collector (Python)
     ↓
Detection Engine
   ├── Known Threats: Sigma + YARA
   └── Unknown Threats: PyOD Anomaly Detection
     ↓
SOAR & Automation
   ├── Shuffle Playbooks
   └── Python Response Scripts
     ↓
Learning Module
   └── Auto-generates & submits rules for approval
     ↓
UI / Dashboard
   └── Grafana (via JSON API)
```

## 📁 Folder Structure

```txt
security-ai-mvp/
├── collectors/        # Log collection agents
├── parser/            # Log parsing & normalization
├── detection/         # Sigma, YARA, AI-based detection
├── automation/        # SOAR playbooks & response scripts
├── ai_learning/       # Rule generation & feedback loop
├── dashboard/         # Grafana integration (JSON API)
├── logs/              # Stored logs
├── config/            # Configuration files
├── run.py             # Main execution script
└── requirements.txt   # Dependencies
```

## ⚙️ Technology Stack

| Component | Tool |
|--------|------|
| Log Collection | Python (custom) |
| Signature Detection | Sigma, YARA |
| Anomaly Detection | PyOD |
| SOAR Platform | Shuffle |
| Automation | Python |
| Dashboard | Grafana + Flask |
| Deployment | Docker Compose |

## 📦 Prerequisites

- Python 3.8+
- Docker (optional, for Shuffle & Grafana)

## 🔧 Installation

### 1. Clone the repo

```bash
git clone https://github.com/yourusername/security-ai-mvp.git
cd security-ai-mvp
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

> 💡 On Windows? Install `yara-python` using the pre-built wheel:
>
> ```bash
> pip install https://github.com/BurntSushi/yara-python/releases/download/v4.4.0/yara_python-4.4.0-py310-win_amd64.whl
> ```

### 3. Start the MVP

```bash
python run.py
```

## 🧪 Test with Simulated Attack

Run this in PowerShell to simulate a brute-force attack:

```powershell
for ($i=1; $i -le 5; $i++) {
    $time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    echo "$time localhost AUTH: Failed login for admin from 192.168.1.100" >> logs/app.log
    Start-Sleep -Seconds 2
}
```

You should see:
```
[ALERT] HIGH - Multiple Failed Login Attempts...
[AUTOMATION] IP Blocked: 192.168.1.100
[SOAR] Shuffle playbook triggered
[LEARNING] Generated new rule: learned_anomaly_20250810_...
```

## 📊 Grafana Dashboard (Optional)

1. Start the JSON API:
   ```bash
   python dashboard/app.py
   ```

2. Run Grafana:
   ```bash
   docker-compose up -d grafana
   ```

3. Open: [http://localhost:3001](http://localhost:3001) → Log in → Import dashboard

## 🛠️ Extensibility

You can extend this MVP to:
- Add YARA file scanning
- Integrate with MISP/SIEM
- Build a React dashboard
- Deploy on Kubernetes
- Add email alerts

## 📄 License

MIT License – feel free to use, modify, and distribute.

## 🙌 Contributing

PRs welcome! This project is built for community collaboration.

---

> **Built with ❤️ for the open-source security community**
