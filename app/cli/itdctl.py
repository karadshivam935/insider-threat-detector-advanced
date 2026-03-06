import argparse
import time
import yaml
from rich import print

from app.db.init_db import init_db
from app.db.db import connect
from app.core.firewall import ensure_chain, unblock_ip, list_blocked

def load_cfg(path="config.yaml"):
    with open(path, "r") as f:
        return yaml.safe_load(f)

def cmd_initdb(cfg):
    init_db(cfg["storage"]["sqlite_path"])
    print("[green]DB initialized[/green]")

def cmd_events(cfg, limit):
    with connect(cfg["storage"]["sqlite_path"]) as conn:
        rows = conn.execute("""
          SELECT ts, src_ip, bytes, score, reasons
          FROM events ORDER BY id DESC LIMIT ?
        """, (limit,)).fetchall()
    for r in rows:
        print(f"{time.strftime('%F %T', time.localtime(r['ts']))} src={r['src_ip']} bytes={r['bytes']} score={r['score']} reasons={r['reasons']}")

def cmd_blocks(cfg):
    with connect(cfg["storage"]["sqlite_path"]) as conn:
        rows = conn.execute("""
          SELECT id, ts, src_ip, seconds, active, reason
          FROM blocks ORDER BY id DESC LIMIT 50
        """).fetchall()
    for r in rows:
        print(f"#{r['id']} {time.strftime('%F %T', time.localtime(r['ts']))} src={r['src_ip']} active={r['active']} seconds={r['seconds']} reason={r['reason']}")

def cmd_unblock(cfg, ip):
    chain = cfg["response"]["iptables_chain"]
    ensure_chain(chain)
    unblock_ip(chain, ip)
    with connect(cfg["storage"]["sqlite_path"]) as conn:
        conn.execute("UPDATE blocks SET active=0 WHERE src_ip=? AND active=1", (ip,))
    print(f"[yellow]Unblocked[/yellow] {ip}")

def cmd_fw(cfg):
    chain = cfg["response"]["iptables_chain"]
    ensure_chain(chain)
    print(list_blocked(chain))

def main():
    p = argparse.ArgumentParser(prog="itdctl", description="Insider Threat Detector controller")
    p.add_argument("--config", default="config.yaml")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("initdb")
    pe = sub.add_parser("events")
    pe.add_argument("--limit", type=int, default=30)

    sub.add_parser("blocks")

    pu = sub.add_parser("unblock")
    pu.add_argument("ip")

    sub.add_parser("fw")

    args = p.parse_args()
    cfg = load_cfg(args.config)

    if args.cmd == "initdb":
        cmd_initdb(cfg)
    elif args.cmd == "events":
        cmd_events(cfg, args.limit)
    elif args.cmd == "blocks":
        cmd_blocks(cfg)
    elif args.cmd == "unblock":
        cmd_unblock(cfg, args.ip)
    elif args.cmd == "fw":
        cmd_fw(cfg)

if __name__ == "__main__":
    main()
