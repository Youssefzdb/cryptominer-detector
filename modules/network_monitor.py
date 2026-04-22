#!/usr/bin/env python3
"""Network Monitor - Detect mining pool connections"""
import subprocess
import socket

# Common mining pool ports
MINING_PORTS = [3333, 4444, 5555, 7777, 8888, 9999, 14444, 45700]
# Known mining pool domains
MINING_DOMAINS = [
    "pool.minexmr.com", "xmrpool.eu", "nanopool.org",
    "f2pool.com", "antpool.com", "nicehash.com",
    "dwarfpool.com", "ethermine.org", "2miners.com"
]

class NetworkMonitor:
    def check(self):
        findings = []
        print("[*] Checking network connections for mining activity...")
        try:
            out = subprocess.check_output(["ss", "-tnp"], text=True, timeout=5)
            for line in out.splitlines():
                for port in MINING_PORTS:
                    if f":{port}" in line:
                        findings.append({
                            "type": "Mining Port Connection",
                            "detail": line[:120],
                            "port": port,
                            "severity": "CRITICAL"
                        })
                        print(f"[!!!] Mining port {port} connection: {line[:60]}")
        except:
            pass

        # DNS check against known pools
        for domain in MINING_DOMAINS[:5]:
            try:
                socket.getaddrinfo(domain, None)
                findings.append({
                    "type": "Mining Pool DNS Resolved",
                    "detail": domain,
                    "severity": "HIGH"
                })
                print(f"[!] Mining pool resolvable: {domain}")
            except:
                pass

        return findings
