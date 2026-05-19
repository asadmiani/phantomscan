from flask import Flask, render_template_string
import sqlite3
import os
from collections import Counter

app = Flask(__name__)

# ✅ Absolute path to project root
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "storage", "knowledge.db")


def fetch_findings():
    if not os.path.exists(DB_PATH):
        return []

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            page TEXT,
            param TEXT,
            sqli INTEGER,
            xss INTEGER,
            severity INTEGER
        )
    """)

    cur.execute("SELECT sqli, xss, severity FROM findings")
    rows = cur.fetchall()
    conn.close()

    results = []
    for sqli, xss, severity in rows:
        if sqli:
            results.append((severity, "SQL Injection"))
        if xss:
            results.append((severity, "XSS"))

    return results



@app.route("/")
def dashboard():
    data = fetch_findings()

    severities = [row[0] for row in data]
    vuln_types = [row[1] for row in data]

    severity_count = Counter(severities)
    vuln_count = Counter(vuln_types)

    return render_template_string("""
<!DOCTYPE html>
<html>
<head>
    <title>Autonomous Security Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: Arial; background:#0f172a; color:white; padding:20px }
        .card { background:#1e293b; padding:20px; border-radius:12px; margin-bottom:30px }
        h1,h2 { text-align:center }
        canvas { max-width:600px; margin:auto }
    </style>
</head>
<body>

<h1>🔐 Autonomous Security Platform Dashboard</h1>

<div class="card">
    <h2>Severity Distribution</h2>
    <canvas id="severityChart"></canvas>
</div>

<div class="card">
    <h2>Vulnerability Types</h2>
    <canvas id="vulnChart"></canvas>
</div>

<script>
new Chart(document.getElementById('severityChart'), {
    type: 'bar',
    data: {
        labels: {{ severity_labels }},
        datasets: [{
            label: 'Findings',
            data: {{ severity_values }},
        }]
    }
});

new Chart(document.getElementById('vulnChart'), {
    type: 'pie',
    data: {
        labels: {{ vuln_labels }},
        datasets: [{
            data: {{ vuln_values }},
        }]
    }
});
</script>

</body>
</html>
""",
        severity_labels=list(severity_count.keys()),
        severity_values=list(severity_count.values()),
        vuln_labels=list(vuln_count.keys()),
        vuln_values=list(vuln_count.values())
    )


if __name__ == "__main__":
    app.run(debug=True)
