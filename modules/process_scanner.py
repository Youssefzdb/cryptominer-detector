#!/usr/bin/env python3
"""Process Scanner - Detect mining processes by name and CPU usage"""
import subprocess
import re

MINER_PROCESS_NAMES = [
    "xmrig", "xmr-stak", "minerd", "ethminer", "cgminer",
    "bfgminer", "nheqminer", "ccminer", "nbminer", "gminer",
    "t-rex", "phoenixminer", "lolminer", "teamredminer"
]

class ProcessScanner:
    def scan(self):
        findings = []
        print("[*] Scanning processes for miner signatures...")
        try:
            out = subprocess.check_output(["ps", "aux"], text=True, timeout=5)
            for line in out.splitlines():
                lower = line.lower()
                for miner in MINER_PROCESS_NAMES:
                    if miner in lower:
                        findings.append({
                            "type": "Miner Process",
                            "process": line[:120],
                            "miner": miner,
                            "severity": "CRITICAL"
                        })
                        print(f"[!!!] MINER DETECTED: {miner}")
                        break

            # Check for high-CPU processes
            lines = out.splitlines()[1:]
            for line in lines:
                parts = line.split()
                if len(parts) > 2:
                    try:
                        cpu = float(parts[2])
                        if cpu > 80:
                            findings.append({
                                "type": "High CPU Process",
                                "process": " ".join(parts[10:])[:80],
                                "cpu": cpu,
                                "severity": "HIGH"
                            })
                            print(f"[!] High CPU: {cpu}% — {' '.join(parts[10:])[:50]}")
                    except:
                        pass
        except Exception as e:
            print(f"[-] Process scan failed: {e}")
        return findings
