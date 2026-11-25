import json, csv
from agent import triage_alert

results = []
with open("labelled_alerts.csv", newline="", encoding="utf-8") as f:
    for row in csv.DictReader(f):
        v = triage_alert(row["alert_text"])
        agent = {"true_positive": "TP", "false_positive": "FP"}.get(v.get("verdict"), "ESCALATE")
        results.append({"alert_num": row["alert_num"], "your_label": row["your_label"].strip(),
                        "agent_label": agent, "match": row["your_label"].strip() == agent,
                        "agent_evidence": v.get("evidence")})
        print(row["alert_num"], "you:", row["your_label"], "| agent:", agent, "|", v.get("evidence"))

n = len(results)
m = sum(r["match"] for r in results)
print(f"\nAgreement: {m}/{n} ({m/n*100:.1f}%)")
print("Escalated (counted as non-matches):", sum(r["agent_label"] == "ESCALATE" for r in results))
with open("evaluation_results.json", "w") as f:
    json.dump(results, f, indent=2)