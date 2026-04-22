#!/usr/bin/env python3
"""Signature Checker - Check filesystem for known miner binaries"""
import os
import hashlib

# Known miner binary hashes (MD5)
KNOWN_MINER_HASHES = {
    "3395856ce81f2b7382dee72602f798b642f14d40": "XMRig v6.x",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4": "Empty/placeholder",
}

SUSPICIOUS_PATHS = [
    "/tmp", "/dev/shm", "/var/tmp", "/run",
    os.path.expanduser("~/.local/bin"),
    os.path.expanduser("~/.config"),
]

MINER_STRINGS = [b"stratum+tcp", b"xmrig", b"cryptonight", b"monero", b"nicehash"]

class SignatureChecker:
    def check(self):
        findings = []
        print("[*] Scanning filesystem for miner signatures...")

        for path in SUSPICIOUS_PATHS:
            if not os.path.exists(path):
                continue
            try:
                for fname in os.listdir(path):
                    fpath = os.path.join(path, fname)
                    if not os.path.isfile(fpath):
                        continue
                    try:
                        with open(fpath, "rb") as f:
                            data = f.read(8192)
                        for sig in MINER_STRINGS:
                            if sig in data:
                                findings.append({
                                    "type": "Miner Signature in File",
                                    "path": fpath,
                                    "signature": sig.decode(),
                                    "severity": "CRITICAL"
                                })
                                print(f"[!!!] Miner signature '{sig.decode()}' in {fpath}")
                                break
                    except:
                        pass
            except:
                pass
        return findings
