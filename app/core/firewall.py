import subprocess
import time
from dataclasses import dataclass
from typing import Optional, List

@dataclass
class BlockEntry:
    src_ip: str
    seconds: int
    reason: str
    ts: int

def _run(cmd: List[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

def ensure_chain(chain: str) -> None:

    # ITD_ALLOW_ESTABLISHED
    # Keep admin control (SSH) working even if employee IP is blocked
    try:
        admin_ip = cfg.get("network", {}).get("admin_ip")
        if admin_ip:
            run(f"iptables -C {chain} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT || iptables -I {chain} 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")
            # Allow SSH server replies from employee -> admin (src port 22)
            run(f"iptables -C {chain} -p tcp -s 0.0.0.0/0 -d {admin_ip} --sport 22 -j ACCEPT || iptables -I {chain} 2 -p tcp -d {admin_ip} --sport 22 -j ACCEPT")
    except Exception:
        pass
    # Create chain if not exists
    r = _run(["sudo", "iptables", "-S", chain])
    if r.returncode != 0:
        _run(["sudo", "iptables", "-N", chain])

    # Ensure INPUT jumps to chain (insert at top if missing)
    rules = _run(["sudo", "iptables", "-S", "INPUT"]).stdout
    jump_rule = f"-A INPUT -j {chain}"
    if jump_rule not in rules:
        _run(["sudo", "iptables", "-I", "INPUT", "1", "-j", chain])

def block_ip(chain: str, ip: str) -> None:
    # Add DROP rule if not already
    rules = _run(["sudo", "iptables", "-S", chain]).stdout
    rule = f"-A {chain} -s {ip}/32 -j DROP"
    if rule not in rules:
        _run(["sudo", "iptables", "-A", chain, "-s", ip, "-j", "DROP"])

def unblock_ip(chain: str, ip: str) -> None:
    # Remove all matching rules
    while True:
        r = _run(["sudo", "iptables", "-D", chain, "-s", ip, "-j", "DROP"])
        if r.returncode != 0:
            break

def list_blocked(chain: str) -> str:
    return _run(["sudo", "iptables", "-S", chain]).stdout

def now_ts() -> int:
    return int(time.time())
