#!/usr/bin/env python3
"""CPU Analyzer - Detect abnormal CPU usage patterns"""
import subprocess
import time

class CPUAnalyzer:
    def analyze(self):
        findings = []
        print("[*] Analyzing CPU usage patterns...")

        try:
            # Get top CPU consumers
            result = subprocess.run(
                ["ps", "aux", "--sort=-%cpu"],
                capture_output=True, text=True, timeout=10
            )
            lines = result.stdout.splitlines()[1:11]  # Top 10 processes
            high_cpu = []
            for line in lines:
                parts = line.split()
                if len(parts) > 2:
                    try:
                        cpu = float(parts[2])
                        if cpu > 80:
                            high_cpu.append({
                                "pid": parts[1],
                                "user": parts[0],
                                "cpu_pct": cpu,
                                "cmd": " ".join(parts[10:])[:80]
                            })
                            print(f"[!] High CPU: {cpu}% | {' '.join(parts[10:])[:60]}")
                    except:
                        pass

            if high_cpu:
                findings.append({
                    "type": "High CPU Usage",
                    "processes": high_cpu,
                    "severity": "HIGH",
                    "detail": f"{len(high_cpu)} process(es) using >80% CPU"
                })

            # Check system load average
            with open("/proc/loadavg") as f:
                load = f.read().split()
                load1 = float(load[0])
                if load1 > 4.0:
                    findings.append({
                        "type": "High Load Average",
                        "load": load1,
                        "severity": "MEDIUM",
                        "detail": f"1-min load average: {load1} (suspicious if sustained)"
                    })
                    print(f"[!] High load average: {load1}")

        except Exception as e:
            findings.append({"type": "Error", "detail": str(e), "severity": "INFO"})

        return findings
