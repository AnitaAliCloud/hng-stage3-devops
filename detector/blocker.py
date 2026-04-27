import subprocess
import logging
import threading
import time
from datetime import datetime

logger = logging.getLogger(__name__)


class Blocker:
    """
    Manages iptables bans and auto-unban schedule.

    Unban schedule (backoff):
    - 1st offence: 10 minutes
    - 2nd offence: 30 minutes
    - 3rd offence: 2 hours
    - 4th+:        permanent (-1)
    """

    UNBAN_SCHEDULE = [
        600,    # 10 minutes
        1800,   # 30 minutes
        7200,   # 2 hours
        -1      # permanent
    ]

    def __init__(self, notifier, audit_log_path="/var/log/detector/audit.log"):
        self.notifier = notifier
        self.audit_log_path = audit_log_path

        # Track offence count per IP
        # key = ip, value = number of times banned
        self.offence_count = {}

        # Currently banned IPs and their unban time
        # key = ip, value = unban timestamp (or -1 for permanent)
        self.banned = {}

        # Thread lock
        self._lock = threading.Lock()

        # Start the auto-unban background thread
        self._unban_thread = threading.Thread(
            target=self._unban_loop,
            daemon=True
        )
        self._unban_thread.start()
        logger.info("Blocker started — auto-unban thread running")

    def get_ban_duration(self, ip: str) -> int:
        """
        Get ban duration for IP based on offence count.
        Returns seconds or -1 for permanent.
        """
        with self._lock:
            count = self.offence_count.get(ip, 0)
            if count >= len(self.UNBAN_SCHEDULE):
                return -1
            return self.UNBAN_SCHEDULE[count]

    def ban(self, ip: str, duration: int):
        """
        Ban an IP using iptables DROP rule.
        Schedules auto-unban if not permanent.
        """
        with self._lock:
            # Increment offence count
            self.offence_count[ip] = self.offence_count.get(ip, 0) + 1

            # Calculate unban time
            if duration == -1:
                unban_at = -1
            else:
                unban_at = time.time() + duration

            self.banned[ip] = unban_at

        # Add iptables rule
        self._iptables_ban(ip)

        duration_str = (
            "permanent" if duration == -1
            else f"{duration // 60} minutes"
        )
        logger.warning(
            f"Banned IP {ip} for {duration_str} "
            f"(offence #{self.offence_count[ip]})"
        )

    def unban(self, ip: str, reason: str = "auto-unban"):
        """
        Remove iptables rule and unban IP.
        Sends Slack notification.
        """
        with self._lock:
            self.banned.pop(ip, None)

        # Remove iptables rule
        self._iptables_unban(ip)

        # Send Slack notification
        self.notifier.alert_unban(ip, reason)

        # Write audit log
        self._write_audit(ip, reason)

        logger.info(f"Unbanned IP {ip} — reason: {reason}")

    def _iptables_ban(self, ip: str):
        """Add DROP rule to iptables"""
        try:
            subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                check=True,
                capture_output=True
            )
            logger.info(f"iptables DROP rule added for {ip}")
        except subprocess.CalledProcessError as e:
            logger.error(f"iptables ban failed for {ip}: {e}")
        except FileNotFoundError:
            # iptables not available (e.g. on Mac during dev)
            logger.warning(
                f"iptables not found — simulating ban for {ip}"
            )

    def _iptables_unban(self, ip: str):
        """Remove DROP rule from iptables"""
        try:
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                check=True,
                capture_output=True
            )
            logger.info(f"iptables DROP rule removed for {ip}")
        except subprocess.CalledProcessError as e:
            logger.error(f"iptables unban failed for {ip}: {e}")
        except FileNotFoundError:
            logger.warning(
                f"iptables not found — simulating unban for {ip}"
            )

    def _unban_loop(self):
        """
        Background thread that checks every 10 seconds
        if any IPs are ready to be unbanned.
        """
        while True:
            try:
                now = time.time()
                to_unban = []

                with self._lock:
                    for ip, unban_at in self.banned.items():
                        # -1 means permanent — never unban
                        if unban_at != -1 and now >= unban_at:
                            to_unban.append(ip)

                for ip in to_unban:
                    self.unban(ip, reason="ban-expired")

            except Exception as e:
                logger.error(f"Unban loop error: {e}")

            time.sleep(10)

    def get_banned_ips(self) -> list:
        """Return list of currently banned IPs with info"""
        with self._lock:
            result = []
            now = time.time()
            for ip, unban_at in self.banned.items():
                if unban_at == -1:
                    remaining = "permanent"
                else:
                    remaining = max(0, int(unban_at - now))
                    remaining = f"{remaining}s remaining"
                result.append({
                    "ip": ip,
                    "offences": self.offence_count.get(ip, 0),
                    "unban_in": remaining
                })
            return result

    def _write_audit(self, ip: str, reason: str):
        """Write unban event to audit log"""
        try:
            import os
            os.makedirs("/var/log/detector", exist_ok=True)
            timestamp = datetime.utcnow().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            entry = (
                f"[{timestamp}] UNBAN {ip} | "
                f"reason={reason} | "
                f"offences={self.offence_count.get(ip, 0)}\n"
            )
            with open(self.audit_log_path, "a") as f:
                f.write(entry)
        except Exception as e:
            logger.error(f"Audit log write error: {e}")