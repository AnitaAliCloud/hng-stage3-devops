import json
import time
import logging
import os
from datetime import datetime

logger = logging.getLogger(__name__)


def parse_log_line(line: str) -> dict:
    """
    Parse a single JSON log line from Nginx.
    Returns a dict with source_ip, timestamp, method,
    path, status, response_size or None if invalid.
    """
    try:
        data = json.loads(line.strip())
        return {
            "source_ip": data.get("source_ip", ""),
            "timestamp": datetime.utcnow(),
            "method": data.get("method", ""),
            "path": data.get("path", ""),
            "status": int(data.get("status", 0)),
            "response_size": int(data.get("response_size", 0)),
        }
    except (json.JSONDecodeError, ValueError) as e:
        logger.debug(f"Could not parse log line: {e}")
        return None


def tail_log(log_path: str, callback):
    """
    Continuously tail a log file line by line.
    Calls callback(parsed_entry) for every valid line.
    Handles log rotation by checking if file was recreated.
    """
    logger.info(f"Starting to tail log file: {log_path}")

    # Wait for log file to exist
    while not os.path.exists(log_path):
        logger.warning(f"Waiting for log file: {log_path}")
        time.sleep(2)

    with open(log_path, "r") as f:
        # Start at end of file — don't replay old logs
        f.seek(0, 2)
        current_inode = os.fstat(f.fileno()).st_ino

        while True:
            line = f.readline()

            if line:
                entry = parse_log_line(line)
                if entry:
                    callback(entry)
            else:
                # No new line — check if file was rotated
                try:
                    new_inode = os.stat(log_path).st_ino
                    if new_inode != current_inode:
                        logger.info("Log file rotated, reopening...")
                        f.close()
                        f = open(log_path, "r")
                        current_inode = new_inode
                except FileNotFoundError:
                    logger.warning("Log file disappeared, waiting...")

                time.sleep(0.1)