# HNG Stage 3 — Anomaly Detection Engine

## Live URLs
- **Metrics Dashboard:** http://anitacloud.duckdns.org:8080
- **Server IP:** 13.50.99.229
- **Nextcloud:** http://13.50.99.229
- **Blog Post:** [link here]
- **GitHub:** https://github.com/AnitaAliCloud/hng-stage3-devops

## Language Choice
Python — chosen for its rich standard library, easy threading,
and readable code that makes the detection logic clear and auditable.

## How the Sliding Window Works
Each IP gets its own `deque` of request timestamps. On every request:
1. Append current timestamp to the IP's deque
2. Evict all timestamps older than 60 seconds from the LEFT side
3. Current rate = length of deque / 60

This gives an accurate rolling 60-second request rate per IP
and globally without storing full history.

## How the Baseline Works
- Window size: 30 minutes of per-second counts
- Recalculation interval: every 60 seconds
- Per-hour slots maintained separately
- Prefers current hour's data when it has 10+ samples
- Floor values: mean minimum 1.0, stddev minimum 1.0

## Anomaly Detection Logic
An IP is flagged anomalous if EITHER:
- Z-score > 3.0: (current_rate - mean) / stddev > 3.0
- Rate multiplier > 5x: current_rate / mean > 5.0

Error surge: if 4xx/5xx rate > 3x baseline error rate,
thresholds tighten to z-score > 2.0 and rate > 3x mean.

## Setup Instructions

### Prerequisites
- Ubuntu 24.04 VPS (2 vCPU, 2GB RAM minimum)
- Docker and Docker Compose installed
- Python 3.11+

### Steps

**1. Clone the repo**

```bash
git clone https://github.com/AnitaAliCloud/hng-stage3-devops.git
cd hng-stage3-devops
```

**2. Create .env file**

```bash
cp .env.example .env
nano .env
```

Add your SLACK_WEBHOOK_URL and SERVER_IP

**3. Start Nginx and Nextcloud**

```bash
docker compose up -d nginx nextcloud
```

**4. Install Python dependencies**

```bash
sudo pip3 install pyyaml psutil requests python-dotenv --break-system-packages
```

**5. Create log directory**

```bash
sudo mkdir -p /var/log/detector
sudo chmod 777 /var/log/detector
```

**6. Start the detector**

```bash
cd detector
nohup sudo python3 main.py > /var/log/detector/output.log 2>&1 &
```

**7. Verify everything is running**

```bash
curl http://localhost:8080
docker compose ps
```

## Architecture

```
Internet Traffic
      ↓
Nginx (port 80) → writes JSON logs to HNG-nginx-logs volume
      ↓
Nextcloud (the actual app)

HNG-nginx-logs volume
      ↓
Detector daemon reads logs continuously
      ↓
┌─────────────────────────────────┐
│  Sliding Window (60s deques)    │
│  Rolling Baseline (30min)       │
│  Z-score Detection              │
│  iptables Blocking              │
│  Slack Alerts                   │
│  Dashboard (port 8080)          │
└─────────────────────────────────┘
```

## Repository Structure

```
detector/
  main.py         - Entry point, starts all components
  monitor.py      - Tails nginx log file continuously
  baseline.py     - Calculates rolling traffic baseline
  detector.py     - Anomaly detection using sliding windows
  blocker.py      - iptables ban/unban management
  notifier.py     - Slack webhook alerts
  dashboard.py    - Live web metrics UI
  config.yaml     - All configuration settings
  requirements.txt
nginx/
  nginx.conf      - Nginx config with JSON logging
screenshots/      - Required screenshots
docs/             - Architecture diagram
README.md
```

## Repository
https://github.com/AnitaAliCloud/hng-stage3-devops

## Blog Post
https://dev.to/anitaalicloud/how-i-built-an-anomaly-detection-engine-for-ddos-protection-1ibg