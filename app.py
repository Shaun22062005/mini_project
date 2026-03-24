from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import sqlite3
import os
os.environ["PYTHONUNBUFFERED"] = "1"
import sys
import datetime
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "ml"))
from feature_extractor import scan_url
app = Flask(__name__, static_folder="Frontend", static_url_path="")
CORS(app)
DB_FILE = os.path.join(os.path.dirname(__file__), "scan_logs.db")

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS scan_logs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            url         TEXT    NOT NULL,
            label       TEXT    NOT NULL,
            risk_score  REAL    NOT NULL,
            confidence  REAL    NOT NULL,
            scanned_at  TEXT    NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def log_scan(url, label, risk_score, confidence):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute(
        "INSERT INTO scan_logs (url, label, risk_score, confidence, scanned_at) VALUES (?,?,?,?,?)",
        (url, label, risk_score, confidence, datetime.datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()

@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")

@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(silent=True)
    if not data or "url" not in data:
        return jsonify({"error": "Missing 'url' in request body"}), 400
    url = data["url"].strip()
    if not url:
        return jsonify({"error": "URL cannot be empty"}), 400
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    local_hosts = ("http://localhost", "https://localhost", "http://127.0.0.1", "https://127.0.0.1")
    if url.startswith(local_hosts):
        return jsonify({"error": "Cannot scan local addresses"}), 400
    try:
        fetch_html = data.get("fetch_html", True)
        skip_whois = data.get("skip_whois", False)
        result = scan_url(url, fetch_html=fetch_html, skip_whois=skip_whois)
        if "error" in result:
            return jsonify(result), 500
        log_scan(
            url=result["url"],
            label=result["label"],
            risk_score=result["risk_score"],
            confidence=result["confidence"],
        )
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/history", methods=["GET"])
def api_history():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM scan_logs ORDER BY id DESC LIMIT 50")
    rows = [dict(row) for row in c.fetchall()]
    conn.close()
    return jsonify(rows), 200

@app.route("/api/history", methods=["DELETE"])
def api_clear_history():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM scan_logs")
    conn.commit()
    conn.close()
    return jsonify({"status": "success", "message": "History cleared"}), 200

@app.route("/api/stats", methods=["GET"])
def api_stats():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM scan_logs")
    total = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM scan_logs WHERE label='PHISHING'")
    phishing = c.fetchone()[0]
    conn.close()
    return jsonify({
        "total_scans": total,
        "phishing_detected": phishing,
        "legitimate": total - phishing,
        "phishing_rate": round(phishing / total * 100, 1) if total > 0 else 0
    }), 200

if __name__ == "__main__":
    init_db()
    print("\n  PhishGuard API  –  http://localhost:5000")
    print("  POST /api/scan    →  scan a URL")
    print("  GET  /api/history →  scan history")
    print("  GET  /api/stats   →  aggregate stats\n")
    app.run(debug=True, host="0.0.0.0", port=5000)
