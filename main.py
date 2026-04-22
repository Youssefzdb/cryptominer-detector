#!/usr/bin/env python3
"""
cryptominer-detector - Cryptomining Malware Detection Tool
Detects unauthorized cryptocurrency mining on systems and networks
"""
import argparse
from modules.process_scanner import ProcessScanner
from modules.network_monitor import NetworkMonitor
from modules.cpu_analyzer import CPUAnalyzer
from modules.report import CryptoMinerReport

def main():
    parser = argparse.ArgumentParser(description="cryptominer-detector")
    parser.add_argument("--mode", choices=["process","network","cpu","full"], default="full")
    parser.add_argument("--output", default="cryptominer_report.html")
    args = parser.parse_args()

    print("[*] CryptoMiner Detector starting...")
    results = {}

    if args.mode in ["process", "full"]:
        scanner = ProcessScanner()
        results["processes"] = scanner.scan()

    if args.mode in ["network", "full"]:
        monitor = NetworkMonitor()
        results["network"] = monitor.check()

    if args.mode in ["cpu", "full"]:
        cpu = CPUAnalyzer()
        results["cpu"] = cpu.analyze()

    report = CryptoMinerReport(results)
    report.save(args.output)
    print(f"[+] Report: {args.output}")

if __name__ == "__main__":
    main()
