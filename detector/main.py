import logging
import threading
import yaml
import sys
import os

from monitor import tail_log
from baseline import BaselineTracker
from detector import AnomalyDetector
from blocker import Blocker
from notifier import alert_ban, alert_unban, alert_global
from dashboard import DashboardServer

# ── Logging setup ─────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("/var/log/detector/detector.log")
    ]
)
logger = logging.getLogger(__name__)


def load_config(path="config.yaml") -> dict:
    """Load configuration from yaml file"""
    with open(path, "r") as f:
        return yaml.safe_load(f)


def main():
    """Main entry point — starts all components"""

    # ── Load config ────────────────────────────────────────
    logger.info("Loading config...")
    config = load_config()

    detection_cfg = config["detection"]
    nginx_cfg = config["nginx"]
    dashboard_cfg = config["dashboard"]

    # ── Create log directory ───────────────────────────────
    os.makedirs("/var/log/detector", exist_ok=True)

    # ── Build notifier functions ───────────────────────────
    # We pass the functions directly since notifier.py
    # exports them at module level
    class Notifier:
        def alert_ban(self, ip, rate, baseline, duration):
            alert_ban(ip, rate, baseline, duration)

        def alert_unban(self, ip, reason):
            alert_unban(ip, reason)

        def alert_global(self, rate, baseline):
            alert_global(rate, baseline)

    notifier = Notifier()

    # ── Initialize components ──────────────────────────────
    logger.info("Initializing baseline tracker...")
    baseline = BaselineTracker(
        window_minutes=detection_cfg["baseline_window_minutes"],
        recalc_interval=detection_cfg["baseline_recalc_interval"],
        min_requests=detection_cfg["min_requests_for_baseline"]
    )

    logger.info("Initializing blocker...")
    blocker = Blocker(notifier=notifier)

    logger.info("Initializing anomaly detector...")
    detector = AnomalyDetector(
        baseline_tracker=baseline,
        blocker=blocker,
        notifier=notifier,
        window_seconds=detection_cfg["window_seconds"]
    )

    # ── Start dashboard ────────────────────────────────────
    logger.info("Starting dashboard...")
    dashboard = DashboardServer(
        detector=detector,
        baseline=baseline,
        blocker=blocker,
        port=dashboard_cfg["port"]
    )
    dashboard.start()

    # ── Start log monitoring ───────────────────────────────
    log_path = nginx_cfg["log_path"]
    logger.info(f"Starting log monitor on {log_path}")
    logger.info("Anomaly detection engine is running! 🚀")

    # This runs forever in the main thread
    # calling detector.process_request() for every log line
    try:
        tail_log(log_path, detector.process_request)
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        sys.exit(0)


if __name__ == "__main__":
    main()