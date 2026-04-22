#!/usr/bin/env python3
from datetime import datetime

class MinerReport:
    def __init__(self, results):
        self.results = results

    def save(self, filename):
        all_items = []
        for section, items in self.results.items():
            for item in items:
                item["section"] = section
                all_items.append(item)

        critical = [i for i in all_items if i.get("severity") == "CRITICAL"]
        rows = "".join(
            f"<tr class='{i.get(\"severity\",\"\").lower()}'>"
            f"<td>{i.get('section','')}</td>"
            f"<td>{i.get('type','')}</td>"
            f"<td>{i.get('detail', i.get('process', i.get('path','')))[:100]}</td>"
            f"<td><b>{i.get('severity','')}</b></td></tr>"
            for i in all_items
        )

        html = f"""<!DOCTYPE html><html><head><title>CryptoMiner Detector</title>
<style>body{{font-family:Arial;background:#0f0f0f;color:#e0e0e0;padding:20px}}
h1{{color:#f59e0b}}
.alert{{background:#2d1a00;border-left:4px solid #f59e0b;padding:12px;border-radius:6px;margin:10px 0}}
table{{width:100%;border-collapse:collapse}}td,th{{padding:8px;border:1px solid #333}}
th{{background:#1a1a1a}}.critical td:last-child{{color:#ff4444}}.high td:last-child{{color:#ff8800}}
</style></head>
<body>
<h1>⛏ CryptoMiner Detector Report</h1>
<p>{datetime.now().strftime('%Y-%m-%d %H:%M')} | Total findings: {len(all_items)} | Critical: {len(critical)}</p>
{"<div class='alert'>⚠️ CRITICAL: Cryptominer activity detected!</div>" if critical else "<div class='alert' style='border-color:#22c55e'>✅ No critical mining indicators found.</div>"}
<table><tr><th>Section</th><th>Type</th><th>Detail</th><th>Severity</th></tr>
{rows if rows else "<tr><td colspan=4>No findings</td></tr>"}
</table></body></html>"""
        with open(filename, "w") as f:
            f.write(html)

cat > /tmp/crypto/requirements.txt << 'EOF'
colorama>=0.4.6
psutil>=5.9.0
