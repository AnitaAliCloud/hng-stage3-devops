sudo kill $(sudo lsof -t -i:8080) 2>/dev/null
cat > ~/hng-stage3-devops/detector/dashboard.py << 'ENDOFFILE'
import time
import psutil
import logging
import threading
import socket
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler

logger = logging.getLogger(__name__)

_detector = None
_baseline = None
_blocker = None
_start_time = None


def get_stats():
    uptime_seconds = int(time.time() - _start_time)
    h = uptime_seconds // 3600
    m = (uptime_seconds % 3600) // 60
    s = uptime_seconds % 60
    ds = _detector.get_stats()
    bs = _baseline.get_stats()
    bi = _blocker.get_banned_ips()
    return {
        "uptime": "{:02d}:{:02d}:{:02d}".format(h, m, s),
        "global_rate": ds["global_rate"],
        "top_ips": ds["top_ips"],
        "banned_ips": bi,
        "baseline": bs,
        "cpu": psutil.cpu_percent(),
        "mem": psutil.virtual_memory().percent,
        "ts": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
    }


def build_html(st):
    br = ""
    for b in st["banned_ips"]:
        br += "<tr><td>{}</td><td>{}</td><td>{}</td></tr>".format(
            b["ip"], b["offences"], b["unban_in"])
    if not br:
        br = "<tr><td colspan='3'>No banned IPs</td></tr>"
    tr = ""
    for ip, rate in st["top_ips"]:
        tr += "<tr><td>{}</td><td>{} req/s</td></tr>".format(ip, rate)
    if not tr:
        tr = "<tr><td colspan='2'>No traffic</td></tr>"

    html = """<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Anomaly Detector</title>
<meta http-equiv="refresh" content="3">
<style>
body{{font-family:monospace;background:#0d1117;color:#c9d1d9;padding:20px}}
h1{{color:#58a6ff}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:15px;margin:20px 0}}
.card{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:15px}}
.metric{{font-size:32px;font-weight:bold;color:#58a6ff}}
.label{{font-size:12px;color:#8b949e;margin-top:4px}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th{{text-align:left;padding:8px;background:#21262d;color:#8b949e}}
td{{padding:8px;border-bottom:1px solid #21262d}}
</style>
</head>
<body>
<h1>Anomaly Detection Engine</h1>
<div class="grid">
<div class="card"><div class="metric">{global_rate}</div><div class="label">Global req/s</div></div>
<div class="card"><div class="metric">{banned_count}</div><div class="label">Banned IPs</div></div>
<div class="card"><div class="metric">{mean}</div><div class="label">Baseline mean</div></div>
<div class="card"><div class="metric">{cpu}%</div><div class="label">CPU</div></div>
<div class="card"><div class="metric">{mem}%</div><div class="label">Memory</div></div>
<div class="card"><div class="metric">{uptime}</div><div class="label">Uptime</div></div>
</div>
<div class="grid">
<div class="card">
<h2 style="color:#58a6ff">Banned IPs</h2>
<table><tr><th>IP</th><th>Offences</th><th>Unban In</th></tr>{banned_rows}</table>
</div>
<div class="card">
<h2 style="color:#58a6ff">Top 10 IPs</h2>
<table><tr><th>IP</th><th>Rate</th></tr>{top_rows}</table>
</div>
</div>
<p style="color:#8b949e;font-size:12px">Updated: {ts}</p>
</body>
</html>""".format(
        global_rate=st["global_rate"],
        banned_count=len(st["banned_ips"]),
        mean=st["baseline"]["effective_mean"],
        cpu=st["cpu"],
        mem=st["mem"],
        uptime=st["uptime"],
        banned_rows=br,
        top_rows=tr,
        ts=st["ts"]
    )
    return html


class DashboardHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            st = get_stats()
            if self.path == "/api/stats":
                import json
                body = json.dumps(st).encode("utf-8")
                ct = "application/json"
            else:
                body = build_html(st).encode("utf-8")
                ct = "text/html; charset=utf-8"
            self.send_response(200)
            self.send_header("Content-Type", ct)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except Exception as e:
            import traceback
            traceback.print_exc()
            body = str(e).encode()
            self.send_response(500)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def log_message(self, format, *args):
        pass


class DashboardServer:
    def __init__(self, detector, baseline, blocker, port=8080):
        global _detector, _baseline, _blocker, _start_time
        _detector = detector
        _baseline = baseline
        _blocker = blocker
        _start_time = time.time()
        self.port = port
        self.server = HTTPServer(("0.0.0.0", port), DashboardHandler)

    def start(self):
        t = threading.Thread(target=self.server.serve_forever, daemon=True)
        t.start()
        time.sleep(1)
        logger.info("Dashboard running on port %d", self.port)
ENDOFFILE