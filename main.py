#!/usr/bin/env python3
"""
cryptominer-detector - Detect unauthorized cryptomining on systems/networks
Checks processes, CPU usage, network connections, and known miner signatures
"""
import argparse
from modules.process_scanner import ProcessScanner
from modules.network_monitor import NetworkMonitor
from modules.signature_checker import SignatureChecker
from modules.report import MinerReport

def main():
    parser = argparse.ArgumentParser(description="cryptominer-detector")
    parser.add_argument("--mode", choices=["process","network","signature","full"], default="full")
    parser.add_argument("--output", default="miner_report.html")
    args = parser.parse_args()

    print("[*] CryptoMiner Detector starting...")
    results = {}

    if args.mode in ["process","full"]:
        ps = ProcessScanner()
        results["processes"] = ps.scan()

    if args.mode in ["network","full"]:
        nm = NetworkMonitor()
        results["network"] = nm.check()

    if args.mode in ["signature","full"]:
        sc = SignatureChecker()
        results["signatures"] = sc.check()

    report = MinerReport(results)
    report.save(args.output)
    total = sum(len(v) for v in results.values() if isinstance(v, list))
    print(f"[+] {total} indicators found. Report: {args.output}")

if __name__ == "__main__":
    main()
