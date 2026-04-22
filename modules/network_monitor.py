#!/usr/bin/env python3
"""Network Monitor - Detect mining pool connections"""
import subprocess
import re

MINING_PORTS = [3333, 4444, 5555, 7777, 8888, 9999, 14444, 45560, 45700]
MINING_POOL_DOMAINS = [
    "pool.minexmr.com", "monerohash.com", "nanopool.org",
    "f2pool.com", "antpool.com", "nicehash.com", "2miners.com",
    "ethermine.org", "flypool.org", "supportxmr.com"
]

class NetworkMonitor:
    def check(self):
        findings = []
        print("[*] Checking network connections for mining activity...")

        try:
            result = subprocess.run(
                ["ss", "-tnp"],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.splitlines():
                for port in MINING_PORTS:
                    if f":{port} " in line or f":{port}\t" in line:
                        findings.append({
                            "type": "Mining Port Connection",
                            "port": port,
                            "detail": line.strip()[:120],
                            "severity": "HIGH"
                        })
                        print(f"[!] Mining port {port} in use: {line[:80]}")
        except Exception as e:
            findings.append({"type": "Error", "detail": str(e), "severity": "INFO"})

        # Check /etc/hosts for mining pool blocking bypass
        try:
            with open("/etc/hosts") as f:
                hosts = f.read()
            for pool in MINING_POOL_DOMAINS:
                if pool in hosts:
                    findings.append({
                        "type": "Mining Pool in /etc/hosts",
                        "domain": pool,
                        "severity": "MEDIUM",
                        "detail": "Mining pool domain found in /etc/hosts"
                    })
        except:
            pass

        print(f"[+] Network check: {len(findings)} issues found")
        return findings
