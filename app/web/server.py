import time
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO
from app.db.db import connect

def create_app(cfg: dict):
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config["SECRET_KEY"] = cfg.get("web", {}).get("secret_key", "devkey")
    socketio = SocketIO(app, async_mode="eventlet", cors_allowed_origins="*")

    db_path = cfg["storage"]["sqlite_path"]
    print("[ITD][WEB] DB:", db_path)

    @app.get("/")
    def home():
        return render_template("index.html")

    @app.get("/api/summary")
    def api_summary():
        now = int(time.time())
        with connect(db_path) as conn:
            alerts_24h = conn.execute(
                "SELECT COUNT(*) AS c FROM events WHERE score >= 35 AND ts > ?",
                (now - 86400,)
            ).fetchone()["c"]

            high_24h = conn.execute(
                "SELECT COUNT(*) AS c FROM events WHERE score >= 70 AND ts > ?",
                (now - 86400,)
            ).fetchone()["c"]

            active_blocks = conn.execute(
                "SELECT COUNT(*) AS c FROM blocks WHERE active=1"
            ).fetchone()["c"]

            top = conn.execute("""
              SELECT src_ip, SUM(total_bytes) AS total_bytes
              FROM metrics_window
              WHERE ts > ?
              GROUP BY src_ip
              ORDER BY total_bytes DESC
              LIMIT 7
            """, (now - 3600,)).fetchall()

        return jsonify({
            "alerts_24h": int(alerts_24h),
            "high_24h": int(high_24h),
            "active_blocks": int(active_blocks),
            "top_talkers_1h": [{"src_ip": r["src_ip"], "total_bytes": int(r["total_bytes"])} for r in top]
        })

    @app.get("/api/events")
    def api_events():
        limit = int(request.args.get("limit", "50"))
        with connect(db_path) as conn:
            rows = conn.execute("""
              SELECT ts, src_ip, dst_ip, proto, dst_port, bytes, score, reasons
              FROM events
              ORDER BY id DESC
              LIMIT ?
            """, (limit,)).fetchall()
        return jsonify([dict(r) for r in rows])

    @app.get("/api/blocks")
    def api_blocks():
        with connect(db_path) as conn:
            rows = conn.execute("""
              SELECT id, ts, src_ip, seconds, active, reason
              FROM blocks
              ORDER BY id DESC
              LIMIT 100
            """).fetchall()
        return jsonify([dict(r) for r in rows])

    # Optional: allow backend to push live messages later if you emit socketio events
    return app, socketio
