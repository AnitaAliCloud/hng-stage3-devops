import time
import math
import logging
import threading
from collections import deque
from datetime import datetime

logger = logging.getLogger(__name__)


class BaselineTracker:
    """
    Tracks rolling baseline of requests per second.

    How it works:
    - Keeps a 30 minute window of per-second counts
    - Recalculates mean and stddev every 60 seconds
    - Maintains per-hour slots — prefers current hour
      when it has enough data
    - Floor values prevent division by zero
    """

    def __init__(self, window_minutes=30, recalc_interval=60,
                 min_requests=10):
        self.window_minutes = window_minutes
        self.recalc_interval = recalc_interval
        self.min_requests = min_requests

        # Rolling window of per-second counts
        # Max size = 30 minutes * 60 seconds = 1800 slots
        self.max_slots = window_minutes * 60
        self.per_second_counts = deque(maxlen=self.max_slots)

        # Per-hour slots — key is hour (0-23), value is list of counts
        self.hourly_slots = {}

        # Current calculated baseline values
        self.effective_mean = 1.0      # floor of 1.0 req/s
        self.effective_stddev = 1.0    # floor of 1.0

        # Error rate baseline
        self.error_mean = 0.1
        self.error_stddev = 0.1

        # Per-second counter (reset every second)
        self._current_second_count = 0
        self._current_second_errors = 0
        self._last_second = int(time.time())

        # Thread lock for safety
        self._lock = threading.Lock()

        # Last time we recalculated
        self._last_recalc = time.time()

        # Audit log path
        self.audit_log_path = "/var/log/detector/audit.log"

    def record_request(self, is_error: bool = False):
        """Record a single incoming request"""
        with self._lock:
            now = int(time.time())

            # If we've moved to a new second, save the last second's count
            if now != self._last_second:
                self.per_second_counts.append(
                    self._current_second_count
                )

                # Save to hourly slot
                hour = datetime.utcnow().hour
                if hour not in self.hourly_slots:
                    self.hourly_slots[hour] = deque(maxlen=self.max_slots)
                self.hourly_slots[hour].append(
                    self._current_second_count
                )

                # Reset counter for new second
                self._current_second_count = 0
                self._current_second_errors = 0
                self._last_second = now

            self._current_second_count += 1
            if is_error:
                self._current_second_errors += 1

        # Recalculate baseline if interval has passed
        if time.time() - self._last_recalc >= self.recalc_interval:
            self.recalculate()

    def recalculate(self):
        """
        Recalculate mean and stddev from rolling window.
        Prefers current hour's data if it has enough samples.
        """
        with self._lock:
            current_hour = datetime.utcnow().hour
            hourly = self.hourly_slots.get(current_hour, deque())

            # Use current hour if it has enough data
            if len(hourly) >= self.min_requests:
                counts = list(hourly)
                source = f"hour-{current_hour}"
            elif len(self.per_second_counts) >= self.min_requests:
                counts = list(self.per_second_counts)
                source = "rolling-window"
            else:
                logger.info("Not enough data for baseline yet")
                self._last_recalc = time.time()
                return

            # Calculate mean
            mean = sum(counts) / len(counts)

            # Calculate stddev
            variance = sum((x - mean) ** 2 for x in counts) / len(counts)
            stddev = math.sqrt(variance)

            # Apply floors to prevent false positives on quiet traffic
            self.effective_mean = max(mean, 1.0)
            self.effective_stddev = max(stddev, 1.0)

            self._last_recalc = time.time()

            logger.info(
                f"Baseline recalculated [{source}] "
                f"mean={self.effective_mean:.2f} "
                f"stddev={self.effective_stddev:.2f} "
                f"samples={len(counts)}"
            )

            # Write to audit log
            self._write_audit(source)

    def get_z_score(self, current_rate: float) -> float:
        """Calculate how far current rate is from normal"""
        return (current_rate - self.effective_mean) / self.effective_stddev

    def is_anomalous(self, current_rate: float) -> bool:
        """
        Returns True if rate is anomalous.
        Fires if z-score > 3.0 OR rate > 5x mean
        """
        z_score = self.get_z_score(current_rate)
        rate_multiplier = current_rate / self.effective_mean

        return z_score > 3.0 or rate_multiplier > 5.0

    def _write_audit(self, source: str):
        """Write baseline recalculation to audit log"""
        try:
            import os
            os.makedirs(
                "/var/log/detector",
                exist_ok=True
            )
            timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
            entry = (
                f"[{timestamp}] BASELINE_RECALC "
                f"source={source} | "
                f"mean={self.effective_mean:.2f} | "
                f"stddev={self.effective_stddev:.2f}\n"
            )
            with open(self.audit_log_path, "a") as f:
                f.write(entry)
        except Exception as e:
            logger.error(f"Audit log error: {e}")

    def get_stats(self) -> dict:
        """Return current baseline stats for dashboard"""
        with self._lock:
            return {
                "effective_mean": round(self.effective_mean, 2),
                "effective_stddev": round(self.effective_stddev, 2),
                "samples": len(self.per_second_counts),
                "hourly_slots": list(self.hourly_slots.keys()),
            }