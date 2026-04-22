#!/usr/bin/env python3
"""Process Scanner - Detect suspicious mining processes"""
import subprocess
import re

MINER_SIGNATURES = [
    "xmrig", "cgminer", "bfgminer", "cpuminer", "minerd",
    "ethminer", "claymore", "nicehash", "phoenix", "lolminer",
    "gminer", "t-rex", "nanominer", "srbminer", "teamredminer",
    "stratum+tcp", "pool.minexmr", "moneropool", "nanopool"
]

class ProcessScanner:
    def scan(self):
        findings = []
        print("[*] Scanning running processes for miner signatures...")
        try:
            result = subprocess.run(
                ["ps", "aux"],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.splitlines():
                line_lower = line.lower()
                for sig in MINER_SIGNATURES:
                    if sig in line_lower:
                        parts = line.split()
                        findings.append({
                            "type": "Suspicious Process",
                            "pid": parts[1] if len(parts) > 1 else "?",
                            "user": parts[0] if parts else "?",
                            "signature": sig,
                            "cmdline": " ".join(parts[10:])[:100],
                            "severity": "CRITICAL"
                        })
                        print(f"[!] MINER PROCESS: {sig} | PID={parts[1] if len(parts) > 1 else '?'}")
                        break
        except Exception as e:
            findings.append({"type": "Error", "detail": str(e), "severity": "INFO"})

        # Check crontab for persistence
        try:
            cron = subprocess.check_output(["crontab", "-l"], stderr=subprocess.DEVNULL).decode()
            for sig in MINER_SIGNATURES:
                if sig in cron.lower():
                    findings.append({
                        "type": "Miner in Crontab",
                        "signature": sig,
                        "severity": "CRITICAL",
                        "detail": "Cryptominer persistence via cron"
                    })
                    print(f"[!] Miner in crontab: {sig}")
        except:
            pass

        print(f"[+] Process scan: {len(findings)} suspicious entries")
        return findings
