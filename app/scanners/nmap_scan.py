import subprocess
import time
from typing import List, Dict

def run_nmap(targets: List[str], args: str) -> Dict[str, str]:
    # Returns raw output per target
    out = {}
    for t in targets:
        cmd = ["nmap"] + args.split() + [t]
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        out[t] = (r.stdout or "") + ("\n" + r.stderr if r.stderr else "")
    return out
