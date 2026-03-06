import time
from dataclasses import dataclass
from typing import List, Tuple, Optional, Set

@dataclass
class WindowStats:
    ts: int
    src_ip: str
    total_bytes: int
    dst_ips: Set[str]
    dst_ports: Set[int]
    top_dst_ip: Optional[str]
    top_dst_port: Optional[int]

@dataclass
class Baseline:
    avg_bytes: float
    avg_unique_ports: float
    avg_unique_dsts: float
    last_update_ts: int

def compute_score_and_reasons(
    ws: WindowStats,
    baseline: Optional[Baseline],
    cfg: dict,
    seen_ports: Set[int],
    local_hour: int
) -> Tuple[int, List[str]]:
    reasons: List[str] = []
    score = 0

    # New ports (this should reliably trigger during scanning)
    if cfg["detection"].get("new_port_alert", True):
        new_ports = [p for p in ws.dst_ports if p not in seen_ports]
        if new_ports:
            score += min(40, 8 * len(new_ports))
            reasons.append(f"new_dst_ports({sorted(new_ports)[:10]})")

    # Risky ports
    risky = set(int(x) for x in cfg["detection"].get("risky_ports", []))
    hit_risky = sorted([p for p in ws.dst_ports if p in risky])
    if hit_risky:
        score += min(50, 12 * len(hit_risky))
        reasons.append(f"risky_ports({hit_risky})")

    # Bytes spike (baseline required)
    if baseline:
        mult = float(cfg["detection"].get("spike_multiplier", 1.6))
        if baseline.avg_bytes > 0 and ws.total_bytes > baseline.avg_bytes * mult:
            score += 35
            ratio = ws.total_bytes / max(1.0, baseline.avg_bytes)
            reasons.append(f"bytes_spike(x{ratio:.1f})")
    else:
        # Cold-start: still alert if bytes are high enough
        if ws.total_bytes > 1_000_000:
            score += 25
            reasons.append("cold_start_high_bytes")

    # Many destinations/ports (no baseline needed)
    if len(ws.dst_ports) >= 25:
        score += 25
        reasons.append("many_unique_dst_ports")
    if len(ws.dst_ips) >= 20:
        score += 15
        reasons.append("many_unique_dst_ips")

    return min(100, score), reasons

def update_baseline(prev: Optional[Baseline], ws: WindowStats, alpha: float) -> Baseline:
    ts = int(time.time())
    b_bytes = float(ws.total_bytes)
    b_ports = float(len(ws.dst_ports))
    b_dsts = float(len(ws.dst_ips))

    if not prev:
        return Baseline(b_bytes, b_ports, b_dsts, ts)

    def ema(old: float, new: float) -> float:
        return (1 - alpha) * old + alpha * new

    return Baseline(
        avg_bytes=ema(prev.avg_bytes, b_bytes),
        avg_unique_ports=ema(prev.avg_unique_ports, b_ports),
        avg_unique_dsts=ema(prev.avg_unique_dsts, b_dsts),
        last_update_ts=ts
    )
