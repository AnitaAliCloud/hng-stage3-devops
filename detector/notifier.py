import requests
import yaml
import logging
from datetime import datetime

# Load config
with open("config.yaml", "r") as f:
    config = yaml.safe_load(f)

WEBHOOK_URL = config["slack"]["webhook_url"]
logger = logging.getLogger(__name__)


def send_slack(message: str):
    """Send a message to Slack webhook"""
    try:
        payload = {"text": message}
        response = requests.post(WEBHOOK_URL, json=payload, timeout=5)
        if response.status_code != 200:
            logger.error(f"Slack error: {response.status_code} {response.text}")
    except Exception as e:
        logger.error(f"Failed to send Slack message: {e}")


def alert_ban(ip: str, rate: float, baseline: float, duration: int):
    """Send a ban alert to Slack"""
    duration_str = "permanent" if duration == -1 else f"{duration // 60} minutes"
    message = (
        f"🚨 *IP BANNED*\n"
        f"*IP:* `{ip}`\n"
        f"*Condition:* Anomalous request rate\n"
        f"*Current Rate:* {rate:.2f} req/s\n"
        f"*Baseline:* {baseline:.2f} req/s\n"
        f"*Ban Duration:* {duration_str}\n"
        f"*Timestamp:* {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC"
    )
    send_slack(message)


def alert_unban(ip: str, reason: str):
    """Send an unban alert to Slack"""
    message = (
        f"✅ *IP UNBANNED*\n"
        f"*IP:* `{ip}`\n"
        f"*Reason:* {reason}\n"
        f"*Timestamp:* {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC"
    )
    send_slack(message)


def alert_global(rate: float, baseline: float):
    """Send a global traffic anomaly alert to Slack"""
    message = (
        f"⚠️ *GLOBAL TRAFFIC ANOMALY*\n"
        f"*Condition:* Global request rate spike detected\n"
        f"*Current Rate:* {rate:.2f} req/s\n"
        f"*Baseline:* {baseline:.2f} req/s\n"
        f"*Timestamp:* {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC"
    )
    send_slack(message)