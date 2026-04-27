import time
import logging
import threading
from collections import deque
from datetime import datetime

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """
    Detects anomalies using sliding windows.

    How sliding window works:
    - Each IP has its own deque of request timestamps
    - Global deque tracks ALL requests
    - Every check, we remove timestamps older than 60 seconds
      from the LEFT side of the deque
    - Current rate = length of deque / window_seconds
    """

    def __init__(self, baseline_tracker, blocker, notifier,
                 window_seconds=60):
        self.baseline = baseline_tracker
        self.blocker = blocker
        self.notifier = notifier
        self.window_seconds = window_seconds

        # Per-IP sliding windows
        # key = ip, value = deque of timestamps
        self.ip_windows = {}

        # Per-IP error windows
        self.ip_error_windows = {}

        # Global sliding window
        self.global_window = deque()

        # Track which IPs are already banned
        self.banned_ips = set()

        # Thread lock
        self._lock = threading.Lock()

        # Last time global anomaly alert was sent
        # Prevents alert spam
        self._last_global_alert = 0
        self._global_alert_cooldown = 60

        # Audit log path
        self.audit_log_path = "/var/log/detector/audit.log"

    def process_request(self, entry: dict):
        """
        Process a single log entry.
        Called by monitor for every new nginx log line.
        """
        ip = entry["source_ip"]
        now = time.time()
        is_error = entry["status"] >= 400

        # Record in baseline tracker
        self.baseline.record_request(is_error=is_error)

        with self._lock:
            # ── Per-IP sliding window ──────────────────────────
            if ip not in self.ip_windows:
                self.ip_windows[ip] = deque()
                self.ip_error_windows[ip] = deque()

            # Add this request timestamp
            self.ip_windows[ip].append(now)
            if is_error:
                self.ip_error_windows[ip].append(now)

            # Evict timestamps older than window_seconds
            cutoff = now - self.window_seconds
            while (self.ip_windows[ip] and
                   self.ip_windows[ip][0] < cutoff):
                self.ip_windows[ip].popleft()
            while (self.ip_error_windows[ip] and
                   self.ip_error_windows[ip][0] < cutoff):
                self.ip_error_windows[ip].popleft()

            # ── Global sliding window ──────────────────────────
            self.global_window.append(now)
            while (self.global_window and
                   self.global_window[0] < cutoff):
                self.global_window.popleft()

            # ── Calculate current rates ────────────────────────
            ip_rate = len(self.ip_windows[ip]) / self.window_seconds
            ip_error_rate = (
                len(self.ip_error_windows[ip]) / self.window_seconds
            )
            global_rate = (
                len(self.global_window) / self.window_seconds
            )

        # ── Check for anomalies ────────────────────────────────
        # Skip already banned IPs
        if ip not in self.banned_ips:
            self._check_ip_anomaly(
                ip, ip_rate, ip_error_rate
            )

        self._check_global_anomaly(global_rate)

    def _check_ip_anomaly(self, ip: str, rate: float,
                          error_rate: float):
        """Check if a single IP is behaving anomalously"""

        # Check error surge — tighten thresholds if errors are high
        error_threshold = self.baseline.error_mean * 3.0
        if error_rate > error_threshold:
            # Tighten: use z-score threshold of 2.0 instead of 3.0
            z_score = self.baseline.get_z_score(rate)
            is_anomalous = z_score > 2.0 or rate > (
                self.baseline.effective_mean * 3.0
            )
            condition = "error-surge"
        else:
            is_anomalous = self.baseline.is_anomalous(rate)
            condition = "rate-anomaly"

        if is_anomalous:
            logger.warning(
                f"Anomaly detected! IP={ip} "
                f"rate={rate:.2f} "
                f"baseline={self.baseline.effective_mean:.2f} "
                f"condition={condition}"
            )
            self._ban_ip(ip, rate, condition)

    def _check_global_anomaly(self, global_rate: float):
        """Check if overall traffic is anomalous"""
        if not self.baseline.is_anomalous(global_rate):
            return

        now = time.time()
        # Don't spam alerts — cooldown period
        if now - self._last_global_alert < self._global_alert_cooldown:
            return

        self._last_global_alert = now
        logger.warning(
            f"Global anomaly! rate={global_rate:.2f} "
            f"baseline={self.baseline.effective_mean:.2f}"
        )

        # Global anomaly = Slack alert only, no IP ban
        self.notifier.alert_global(
            global_rate,
            self.baseline.effective_mean
        )

        self._write_audit(
            "GLOBAL_ANOMALY",
            "global",
            condition="rate-anomaly",
            rate=global_rate,
            baseline=self.baseline.effective_mean,
            duration=0
        )

    def _ban_ip(self, ip: str, rate: float, condition: str):
        """Ban an IP — add iptables rule and send Slack alert"""
        # Get ban duration based on offence count
        duration = self.blocker.get_ban_duration(ip)

        # Add to banned set
        self.banned_ips.add(ip)

        # Add iptables rule
        self.blocker.ban(ip, duration)

        # Send Slack alert
        self.notifier.alert_ban(
            ip, rate,
            self.baseline.effective_mean,
            duration
        )

        # Write audit log
        self._write_audit(
            "BAN", ip,
            condition=condition,
            rate=rate,
            baseline=self.baseline.effective_mean,
            duration=duration
        )

    def unban_ip(self, ip: str):
        """Remove an IP from banned set"""
        with self._lock:
            self.banned_ips.discard(ip)

    def get_top_ips(self, n=10) -> list:
        """Return top N IPs by request rate"""
        with self._lock:
            now = time.time()
            cutoff = now - self.window_seconds
            rates = {}
            for ip, window in self.ip_windows.items():
                # Count requests in window
                count = sum(1 for t in window if t > cutoff)
                if count > 0:
                    rates[ip] = round(
                        count / self.window_seconds, 2
                    )
            return sorted(
                rates.items(),
                key=lambda x: x[1],
                reverse=True
            )[:n]

    def get_stats(self) -> dict:
        """Return current detector stats for dashboard"""
        with self._lock:
            return {
                "banned_ips": list(self.banned_ips),
                "global_rate": round(
                    len(self.global_window) / self.window_seconds,
                    2
                ),
                "top_ips": self.get_top_ips(),
            }

    def _write_audit(self, action: str, ip: str,
                     condition: str, rate: float,
                     baseline: float, duration: int):
        """Write structured audit log entry"""
        try:
            import os
            os.makedirs("/var/log/detector", exist_ok=True)
            timestamp = datetime.utcnow().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            duration_str = (
                "permanent" if duration == -1
                else f"{duration}s"
            )
            entry = (
                f"[{timestamp}] {action} {ip} | "
                f"condition={condition} | "
                f"rate={rate:.2f} | "
                f"baseline={baseline:.2f} | "
                f"duration={duration_str}\n"
            )
            with open(self.audit_log_path, "a") as f:
                f.write(entry)
        except Exception as e:
            logger.error(f"Audit log error: {e}")