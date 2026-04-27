import time
import psutil
import logging
import threading
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler

logger = logging.getLogger(__name__)


class DashboardHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the live metrics dashboard"""

    # These get set by DashboardServer before starting
    detector = None
    baseline = None
    blocker = None
    start_time = None

    def do_GET(self):
        """Handle GET requests"""
        if self.path == "/":
            self._serve_dashboard()
        elif self.path == "/api/stats":
            self._serve_stats()
        else:
            self.send_response(404)
            self.end_headers()

    def _serve_stats(self):
        """Return JSON stats for API endpoint"""
        import json
        stats = self._get_stats()
        body = json.dumps(stats).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def _get_stats(self) -> dict:
        """Gather all stats from detector, baseline, blocker"""
        uptime_seconds = int(time.time() - self.start_time)
        hours = uptime_seconds // 3600
        minutes = (uptime_seconds % 3600) // 60
        seconds = uptime_seconds % 60

        detector_stats = self.detector.get_stats()
        baseline_stats = self.baseline.get_stats()
        banned_ips = self.blocker.get_banned_ips()

        return {
            "uptime": f"{hours:02d}:{minutes:02d}:{seconds:02d}",
            "global_rate": detector_stats["global_rate"],
            "top_ips": detector_stats["top_ips"],
            "banned_ips": banned_ips,
            "baseline": baseline_stats,
            "cpu_percent": psutil.cpu_percent(),
            "memory_percent": psutil.virtual_memory().percent,
            "timestamp": datetime.utcnow().strftime(
                "%Y-%m-%d %H:%M:%S UTC"
            ),
        }

    def _serve_dashboard(self):
        """Serve the HTML dashboard page"""
        stats = self._get_stats()
        html = self._build_html(stats)
        body = html.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def _build_html(self, stats: dict) -> str:
        """Build the dashboard HTML"""
        banned_rows = ""
        for b in stats["banned_ips"]:
            banned_rows += f"""
            <tr>
                <td>{b['ip']}</td>
                <td>{b['offences']}</td>
                <td>{b['unban_in']}</td>
            </tr>"""

        top_ip_rows = ""
        for ip, rate in stats["top_ips"]:
            top_ip_rows += f"""
            <tr>
                <td>{ip}</td>
                <td>{rate} req/s</td>
            </tr>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Anomaly Detector Dashboard</title>
    <meta http-equiv="refresh" content="3">
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'Courier New', monospace;
            background: #0d1117;
            color: #c9d1d9;
            padding: 20px;
        }}
        h1 {{
            color: #58a6ff;
            margin-bottom: 20px;
            font-size: 24px;
        }}
        h2 {{
            color: #58a6ff;
            font-size: 16px;
            margin-bottom: 10px;
        }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }}
        .card {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 16px;
        }}
        .metric {{
            font-size: 36px;
            font-weight: bold;
            color: #58a6ff;
        }}
        .metric.danger {{ color: #f85149; }}
        .metric.warning {{ color: #e3b341; }}
        .label {{
            font-size: 12px;
            color: #8b949e;
            margin-top: 4px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }}
        th {{
            text-align: left;
            padding: 8px;
            background: #21262d;
            color: #8b949e;
            font-weight: normal;
        }}
        td {{
            padding: 8px;
            border-bottom: 1px solid #21262d;
        }}
        tr:hover td {{ background: #21262d; }}
        .badge-banned {{
            background: #f85149;
            color: white;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 11px;
        }}
        .footer {{
            color: #8b949e;
            font-size: 12px;
            margin-top: 20px;
        }}
        .status-dot {{
            display: inline-block;
            width: 8px;
            height: 8px;
            background: #3fb950;
            border-radius: 50%;
            margin-right: 6px;
            animation: pulse 2s infinite;
        }}
        @keyframes pulse {{
            0% {{ opacity: 1; }}
            50% {{ opacity: 0.3; }}
            100% {{ opacity: 1; }}
        }}
    </style>
</head>
<body>
    <h1>
        <span class="status-dot"></span>
        Anomaly Detection Engine
    </h1>

    <div class="grid">
        <div class="card">
            <div class="metric {'danger' if stats['global_rate'] > 100 else ''}">
                {stats['global_rate']}
            </div>
            <div class="label">Global req/s</div>
        </div>

        <div class="card">
            <div class="metric {'danger' if len(stats['banned_ips']) > 0 else ''}">
                {len(stats['banned_ips'])}
            </div>
            <div class="label">Banned IPs</div>
        </div>

        <div class="card">
            <div class="metric">
                {stats['baseline']['effective_mean']}
            </div>
            <div class="label">
                Baseline mean req/s
                (stddev: {stats['baseline']['effective_stddev']})
            </div>
        </div>

        <div class="card">
            <div class="metric">
                {stats['cpu_percent']}%
            </div>
            <div class="label">
                CPU Usage
                (Memory: {stats['memory_percent']}%)
            </div>
        </div>

        <div class="card">
            <div class="metric">{stats['uptime']}</div>
            <div class="label">Uptime</div>
        </div>

        <div class="card">
            <div class="metric">
                {stats['baseline']['samples']}
            </div>
            <div class="label">Baseline samples</div>
        </div>
    </div>

    <div class="grid">
        <div class="card">
            <h2>🚫 Banned IPs</h2>
            <table>
                <tr>
                    <th>IP Address</th>
                    <th>Offences</th>
                    <th>Unban In</th>
                </tr>
                {banned_rows if banned_rows else
                    '<tr><td colspan="3" style="color:#8b949e">'
                    'No banned IPs</td></tr>'}
            </table>
        </div>

        <div class="card">
            <h2>📊 Top 10 Source IPs</h2>
            <table>
                <tr>
                    <th>IP Address</th>
                    <th>Rate</th>
                </tr>
                {top_ip_rows if top_ip_rows else
                    '<tr><td colspan="2" style="color:#8b949e">'
                    'No traffic yet</td></tr>'}
            </table>
        </div>
    </div>

    <div class="footer">
        Last updated: {stats['timestamp']} •
        Auto-refreshes every 3 seconds
    </div>
</body>
</html>"""

    def log_message(self, format, *args):
        """Suppress default HTTP server logs"""
        pass


class DashboardServer:
    """Starts the dashboard HTTP server in a background thread"""

    def __init__(self, detector, baseline, blocker, port=8080):
        self.port = port

        # Inject dependencies into handler
        DashboardHandler.detector = detector
        DashboardHandler.baseline = baseline
        DashboardHandler.blocker = blocker
        DashboardHandler.start_time = time.time()

        self.server = HTTPServer(("0.0.0.0", port), DashboardHandler)

    def start(self):
        """Start dashboard in background thread"""
        thread = threading.Thread(
            target=self.server.serve_forever,
            daemon=True
        )
        thread.start()
        logger.info(f"Dashboard running on port {self.port}")