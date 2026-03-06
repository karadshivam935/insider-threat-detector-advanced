import time
from collections import defaultdict, Counter
from dataclasses import asdict
from typing import Dict, Set, Tuple, Optional

from scapy.all import sniff, IP, TCP, UDP  # type: ignore

from app.db.db import connect
from app.core.detect import WindowStats, Baseline, compute_score_and_reasons, update_baseline
from app.core.firewall import ensure_chain, block_ip, now_ts
from app.utils.timeutil import local_hour_now

def load_baseline(conn, src_ip: str) -> Optional[Baseline]:
    row = conn.execute("SELECT avg_bytes, avg_unique_ports, avg_unique_dsts, last_update_ts FROM baseline WHERE src_ip=?",
                       (src_ip,)).fetchone()
    if not row:
        return None
    return Baseline(
        avg_bytes=float(row["avg_bytes"]),
        avg_unique_ports=float(row["avg_unique_ports"]),
        avg_unique_dsts=float(row["avg_unique_dsts"]),
        last_update_ts=int(row["last_update_ts"])
    )

def save_baseline(conn, src_ip: str, b: Baseline) -> None:
    conn.execute("""
      INSERT INTO baseline(src_ip, avg_bytes, avg_unique_ports, avg_unique_dsts, last_update_ts)
      VALUES(?,?,?,?,?)
      ON CONFLICT(src_ip) DO UPDATE SET
        avg_bytes=excluded.avg_bytes,
        avg_unique_ports=excluded.avg_unique_ports,
        avg_unique_dsts=excluded.avg_unique_dsts,
        last_update_ts=excluded.last_update_ts
    """, (src_ip, b.avg_bytes, b.avg_unique_ports, b.avg_unique_dsts, b.last_update_ts))

def record_metrics(conn, ws: WindowStats) -> None:
    conn.execute("""
      INSERT INTO metrics_window(ts, src_ip, window_seconds, total_bytes, unique_dst_ips, unique_dst_ports, top_dst_ip, top_dst_port)
      VALUES(?,?,?,?,?,?,?,?)
    """, (ws.ts, ws.src_ip, 0, ws.total_bytes, len(ws.dst_ips), len(ws.dst_ports), ws.top_dst_ip, ws.top_dst_port))

def record_event(conn, ts: int, src_ip: str, dst_ip: str, proto: str, dst_port: Optional[int], size: int, score: int, reasons: str) -> None:
    conn.execute("""
      INSERT INTO events(ts, src_ip, dst_ip, proto, dst_port, bytes, score, reasons)
      VALUES(?,?,?,?,?,?,?,?)
    """, (ts, src_ip, dst_ip, proto, dst_port, size, score, reasons))

def record_block(conn, ts: int, src_ip: str, seconds: int, reason: str) -> None:
    conn.execute("""
      INSERT INTO blocks(ts, src_ip, seconds, active, reason)
      VALUES(?,?,?,?,?)
    """, (ts, src_ip, seconds, 1, reason))

def is_allowlisted(ip: str, cfg: dict) -> bool:
    return ip in set(cfg["detection"].get("allowlist_ips", []))

class WindowAgg:
    def __init__(self, window_seconds: int):
        self.window_seconds = int(window_seconds)
        # Persist across windows so "new ports" detection works
        self.hist_ports_by_src = defaultdict(set)
        self.reset()

    def reset(self):
        self.start_ts = int(time.time())
        self.bytes_by_src = defaultdict(int)
        self.dst_ips_by_src = defaultdict(set)
        self.dst_ports_by_src = defaultdict(set)
        self.top_dst_ip_by_src = defaultdict(Counter)
        self.top_dst_port_by_src = defaultdict(Counter)

    def add_packet(self, src: str, dst: str, proto: str, dport, size: int):
        self.bytes_by_src[src] += size
        self.dst_ips_by_src[src].add(dst)
        if dport is not None:
            dport = int(dport)
            self.dst_ports_by_src[src].add(dport)
            self.top_dst_port_by_src[src][dport] += 1
        self.top_dst_ip_by_src[src][dst] += 1

    def due(self) -> bool:
        return int(time.time()) - self.start_ts >= self.window_seconds

    def build_stats(self, src: str) -> WindowStats:
        top_ip = None
        top_port = None
        if self.top_dst_ip_by_src[src]:
            top_ip = self.top_dst_ip_by_src[src].most_common(1)[0][0]
        if self.top_dst_port_by_src[src]:
            top_port = self.top_dst_port_by_src[src].most_common(1)[0][0]

        return WindowStats(
            ts=int(time.time()),
            src_ip=src,
            total_bytes=int(self.bytes_by_src[src]),
            dst_ips=set(self.dst_ips_by_src[src]),
            dst_ports=set(self.dst_ports_by_src[src]),
            top_dst_ip=top_ip,
            top_dst_port=top_port
        )

    def seen_ports(self, src: str):
        return set(self.hist_ports_by_src[src])

    def commit_ports(self, src: str, ports):
        self.hist_ports_by_src[src].update(set(ports))


def run_collector(cfg: dict, emit_callback=None) -> None:
    db_path = cfg["storage"]["sqlite_path"]
    iface = cfg["capture"]["interface"]
    bpf = cfg["capture"].get("bpf_filter", "ip")
    window_seconds = int(cfg["detection"]["window_seconds"])
    alpha = float(cfg["detection"]["baseline_alpha"])
    auto_block = bool(cfg["response"]["auto_block"])
    block_seconds = int(cfg["response"]["block_seconds"])
    chain = cfg["response"]["iptables_chain"]

    ensure_chain(chain)

    agg = WindowAgg(window_seconds)

    def on_packet(pkt):
        if IP not in pkt:
            return
        ip = pkt[IP]
        src = ip.src
        dst = ip.dst
        proto = "IP"
        dport = None

        if TCP in pkt:
            proto = "TCP"
            dport = int(pkt[TCP].dport)
        elif UDP in pkt:
            proto = "UDP"
            dport = int(pkt[UDP].dport)

        size = int(len(pkt))
        agg.add_packet(src, dst, proto, dport, size)

        # store raw-ish event row with score=0 for now (optional; we store with score later too)
        # Keeping it light: only store anomalies as events in DB, otherwise DB grows fast.

    while True:
        sniff(iface=iface, filter=bpf, prn=on_packet, store=False, timeout=2)

        if not agg.due():
            continue

        ts_now = int(time.time())
        hour = local_hour_now(cfg["project"].get("timezone", "Asia/Kolkata"))

        with connect(db_path) as conn:
            for src in list(agg.bytes_by_src.keys()):
                if is_allowlisted(src, cfg):
                    continue

                ws = agg.build_stats(src)
                baseline = load_baseline(conn, src)
                seen_ports = agg.seen_ports(src)

                score, reasons = compute_score_and_reasons(ws, baseline, cfg, seen_ports, hour)

                agg.commit_ports(src, ws.dst_ports)
                print(f"[ITD] src={src} bytes={ws.total_bytes} ports={len(ws.dst_ports)} dsts={len(ws.dst_ips)} score={score} reasons={reasons}")

                # Always record window metrics
                conn.execute("""
                  INSERT INTO metrics_window(ts, src_ip, window_seconds, total_bytes, unique_dst_ips, unique_dst_ports, top_dst_ip, top_dst_port)
                  VALUES(?,?,?,?,?,?,?,?)
                """, (ws.ts, ws.src_ip, window_seconds, ws.total_bytes, len(ws.dst_ips), len(ws.dst_ports), ws.top_dst_ip, ws.top_dst_port))

                # Update baseline (even if suspicious, you can decide to freeze it; here we still update but lightly)
                new_b = update_baseline(baseline, ws, alpha=alpha)
                save_baseline(conn, src, new_b)

                if score >= 35:  # alert threshold
                    reasons_str = ",".join(reasons) if reasons else "suspicious_window"
                    # store ONE representative event record
                    record_event(conn, ts_now, src, ws.top_dst_ip or "unknown", "WINDOW", ws.top_dst_port, ws.total_bytes, score, reasons_str)

                    if emit_callback:
                        emit_callback({
                            "type": "alert",
                            "ts": ts_now,
                            "src_ip": src,
                            "score": score,
                            "reasons": reasons,
                            "total_bytes": ws.total_bytes,
                            "unique_dst_ips": len(ws.dst_ips),
                            "unique_dst_ports": len(ws.dst_ports),
                            "top_dst_ip": ws.top_dst_ip,
                            "top_dst_port": ws.top_dst_port
                        })

                    if auto_block and score >= 70:
                        # block high-risk
                        block_ip(chain, src)
                        record_block(conn, ts_now, src, block_seconds, f"auto_block(score={score})")
                        if emit_callback:
                            emit_callback({
                                "type": "block",
                                "ts": ts_now,
                                "src_ip": src,
                                "seconds": block_seconds,
                                "reason": f"auto_block(score={score})"
                            })

        agg.reset()
