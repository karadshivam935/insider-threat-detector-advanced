import yaml
from threading import Thread

from app.db.init_db import init_db
from app.web.server import create_app
from app.core.collector import run_collector

def load_cfg(path="config.yaml"):
    with open(path, "r") as f:
        return yaml.safe_load(f)

def main():
    cfg = load_cfg()

    # --- ensure sqlite path is absolute (fix sudo/working-dir mismatch) ---
    from pathlib import Path as _Path
    _root = _Path(__file__).resolve().parents[1]  # project root (..../app/main.py -> root)
    _db = cfg["storage"]["sqlite_path"]
    if not str(_db).startswith("/"):
        cfg["storage"]["sqlite_path"] = str((_root / _db).resolve())
    # ---------------------------------------------------------------

    init_db(cfg["storage"]["sqlite_path"])

    app, socketio = create_app(cfg)

    def emit(msg):
        socketio.emit("event", msg)

    # Collector in background thread (needs sudo for sniff + iptables)
    t = Thread(target=run_collector, args=(cfg, emit), daemon=True)
    t.start()

    socketio.run(app, host=cfg["web"]["host"], port=int(cfg["web"]["port"]))

if __name__ == "__main__":
    main()
