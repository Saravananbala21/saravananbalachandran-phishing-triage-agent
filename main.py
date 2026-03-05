import os
import json
from datetime import datetime
from dotenv import load_dotenv
from rich import print, print_json

from workflows.triage_graph import build_graph

load_dotenv()

print("[bold green]Phishing Triage Agent Starting...[/bold green]")

# Load phishing triage playbook
with open("playbooks/phishing_triage_playbook.md", "r", encoding="utf-8") as f:
    playbook_text = f.read()

# Load sample alerts
ALERT_FOLDER = "data/sample_alerts"
alerts = []
for file in os.listdir(ALERT_FOLDER):
    if file.endswith(".json"):
        path = os.path.join(ALERT_FOLDER, file)
        with open(path, "r", encoding="utf-8") as f:
            alerts.append(json.load(f))

print(f"[cyan]Loaded {len(alerts)} alerts[/cyan]")

graph = build_graph()

results = []
for alert in alerts:
    print("\n[bold yellow]Analyzing Alert:[/bold yellow]", alert["alert_id"])

    result_state = graph.invoke(
        {
            "alert": alert,
            "playbook_text": playbook_text,
            "classification_json": {},
            "evidence": {},
            "response_plan": {},
        }
    )

    record = {
        "alert": alert,
        "classification": result_state["classification_json"],
        "evidence": result_state["evidence"],
        "response_plan": result_state["response_plan"],
    }
    results.append(record)

    print("[bold green]Classification:[/bold green]")
    print_json(data=record["classification"])

    print("[bold blue]Collected Evidence (deterministic):[/bold blue]")
    print_json(data=record["evidence"])

    print("[bold magenta]Response Plan:[/bold magenta]")
    print_json(data=record["response_plan"])

# Write report
os.makedirs("data/output", exist_ok=True)
report_path = os.path.join("data/output", "triage_report.json")

report = {
    "generated_at": datetime.utcnow().isoformat() + "Z",
    "total_alerts": len(results),
    "results": results,
}

with open(report_path, "w", encoding="utf-8") as f:
    json.dump(report, f, indent=2)

print(f"\n[bold cyan]Saved report to:[/bold cyan] {report_path}")