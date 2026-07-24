"""Jointure entre les flux et le snapshot d'etat hote pris a la capture.

Le snapshot (produit par capture/capture.ps1 ou capture.sh) repond a la
question que le pcap seul ne peut pas trancher : QUI detient cette socket,
et dans quel etat etait la machine. C'est lui qui transforme un verdict
HOTE en verdict APP (process identifie, machine saine) ou OS (machine
saturee).

Format attendu (snapshot.json) :
{
  "host": "SRV-APP01", "os": "windows", "taken_at": "2026-07-24T14:03:22",
  "connections": [{"local_ip": "10.0.0.5", "local_port": 8443,
                   "remote_ip": "10.0.0.42", "remote_port": 51234,
                   "state": "ESTABLISHED", "pid": 4212, "process": "java"}],
  "top_cpu": [{"pid": 4212, "process": "java", "cpu_pct": 97.0}],
  "cpu_pct": 63.0, "mem_free_mb": 512, "disk_busy_pct": 98.0
}
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .signals import FlowSignals


@dataclass
class HostContext:
    host: str
    process: Optional[str]       # process qui detient la socket du flux
    pid: Optional[int]
    cpu_pct: Optional[float]
    disk_busy_pct: Optional[float]
    mem_free_mb: Optional[float]
    process_cpu_pct: Optional[float]

    def summary(self) -> str:
        parts = []
        if self.process:
            p = f"socket detenue par {self.process}"
            if self.pid:
                p += f" (pid {self.pid})"
            if self.process_cpu_pct is not None:
                p += f", cpu process {self.process_cpu_pct:.0f}%"
            parts.append(p)
        if self.cpu_pct is not None:
            parts.append(f"cpu machine {self.cpu_pct:.0f}%")
        if self.disk_busy_pct is not None:
            parts.append(f"disque {self.disk_busy_pct:.0f}%")
        if self.mem_free_mb is not None:
            parts.append(f"ram libre {self.mem_free_mb:.0f} Mo")
        return f"[{self.host}] " + ", ".join(parts) if parts else ""


class HostSnapshot:
    def __init__(self, data: dict):
        self.data = data
        self.host = data.get("host", "?")
        self._by_local_port: dict[int, list[dict]] = {}
        for c in data.get("connections", []):
            self._by_local_port.setdefault(int(c.get("local_port", -1)), []).append(c)
        self._cpu_by_pid = {int(t["pid"]): float(t.get("cpu_pct", 0))
                            for t in data.get("top_cpu", []) if "pid" in t}

    @classmethod
    def load(cls, path: str | Path) -> "HostSnapshot":
        # utf-8-sig : PowerShell 5.1 ecrit l'UTF-8 avec BOM, json.loads
        # s'etrangle dessus ; -sig tolere les deux formes.
        return cls(json.loads(Path(path).read_text(encoding="utf-8-sig")))

    _WILDCARDS = {"0.0.0.0", "::", ""}

    def _lookup(self, ip: str, port: int) -> Optional[dict]:
        """Le PORT seul ne suffit pas : un port-forward local (VBoxHeadless,
        ssh -L, docker-proxy) ecoute le meme numero qu'un service distant et
        se ferait attribuer le flux a tort (constate sur capture reelle).
        L'IP locale doit correspondre a l'extremite du flux ; une ecoute
        wildcard reste acceptee, une IP differente est rejetee."""
        for c in self._by_local_port.get(port, []):
            local_ip = str(c.get("local_ip", ""))
            if local_ip == ip or local_ip in self._WILDCARDS:
                return c
        return None

    def context_for(self, sig: FlowSignals) -> Optional[HostContext]:
        """Le snapshot vient d'UNE machine : on matche (ip, port) locaux,
        cote serveur (cas le plus courant) puis cote client."""
        conn = (self._lookup(sig.server, sig.sport)
                or self._lookup(sig.client, sig.cport))
        pid = conn.get("pid") if conn else None
        return HostContext(
            host=self.host,
            process=(conn or {}).get("process"),
            pid=pid,
            cpu_pct=self.data.get("cpu_pct"),
            disk_busy_pct=self.data.get("disk_busy_pct"),
            mem_free_mb=self.data.get("mem_free_mb"),
            process_cpu_pct=self._cpu_by_pid.get(int(pid)) if pid else None,
        )
