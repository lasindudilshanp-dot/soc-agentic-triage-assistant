import json, csv

rows = []
with open("alerts_export.json", encoding="utf-8", errors="ignore") as f:
    for line in f:
        try:
            a = json.loads(line)
        except json.JSONDecodeError:
            continue
        r, d = a.get("rule", {}), a.get("data", {})
        text = (f"[{a.get('timestamp')}] rule {r.get('id')} (level {r.get('level')}): "
                f"{r.get('description')} | srcip={d.get('srcip', 'n/a')} | "
                f"srcuser={d.get('srcuser', 'n/a')} | log={a.get('full_log', '')}")
        rows.append(text)

with open("labelled_alerts.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["alert_num", "alert_text", "your_label", "your_notes"])
    for i, t in enumerate(rows, 1):
        w.writerow([i, t, "", ""])
print(len(rows), "alerts written")
