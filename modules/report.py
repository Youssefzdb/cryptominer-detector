#!/usr/bin/env python3
from datetime import datetime

class CryptoMinerReport:
    def __init__(self, results):
        self.results = results

    def save(self, filename):
        all_findings = []
        for section, items in self.results.items():
            if isinstance(items, list):
                for item in items:
                    item["section"] = section
                    all_findings.append(item)

        critical = [f for f in all_findings if f.get("severity") == "CRITICAL"]
        high = [f for f in all_findings if f.get("severity") == "HIGH"]

        rows = "".join(
            f"<tr><td class='{f.get(\"severity\",\"\").lower()}'>{f.get('severity','')}</td>"
            f"<td>{f.get('type','')}</td>"
            f"<td>{f.get('detail', f.get('signature', f.get('domain', '')))}</td></tr>"
            for f in all_findings
        )

        html = f"""<!DOCTYPE html><html><head><title>CryptoMiner Detector</title>
<style>
body{{font-family:Arial;background:#0a0a0a;color:#e0e0e0;padding:20px}}
h1{{color:#f59e0b}} .critical{{color:#ef4444}} .high{{color:#f97316}} .medium{{color:#facc15}}
.stats{{display:flex;gap:15px;margin:15px 0}}
.stat{{background:#1c1c1c;padding:12px 20px;border-radius:8px;text-align:center}}
.stat .n{{font-size:2em;font-weight:bold}}
table{{width:100%;border-collapse:collapse;margin:10px 0}}
td,th{{padding:8px;border:1px solid #333}} th{{background:#1a1a1a}}
</style></head><body>
<h1>🪙 CryptoMiner Detector Report</h1>
<p>{datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
<div class="stats">
  <div class="stat"><div class="n" style="color:#ef4444">{len(critical)}</div>CRITICAL</div>
  <div class="stat"><div class="n" style="color:#f97316">{len(high)}</div>HIGH</div>
  <div class="stat"><div class="n">{len(all_findings)}</div>TOTAL</div>
</div>
<table><tr><th>Severity</th><th>Type</th><th>Detail</th></tr>
{rows if rows else '<tr><td colspan=3>No miners detected ✓</td></tr>'}
</table></body></html>"""

        with open(filename, "w") as f:
            f.write(html)
        print(f"[+] Report saved: {filename}")
