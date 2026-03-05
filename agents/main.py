import os
import json
from dotenv import load_dotenv
from rich import print

from agents.phishing_classifier import classify_alert

# Load environment variables
load_dotenv()

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

print("[bold green]Phishing Triage Agent Starting...[/bold green]")

# Load phishing triage playbook
with open("playbooks/phishing_triage_playbook.md", "r") as f:
    playbook_text = f.read()

# Path to sample alerts
ALERT_FOLDER = "data/sample_alerts"

alerts = []

for file in os.listdir(ALERT_FOLDER):
    if file.endswith(".json"):
        path = os.path.join(ALERT_FOLDER, file)

        with open(path, "r") as f:
            alert = json.load(f)
            alerts.append(alert)

print(f"[cyan]Loaded {len(alerts)} alerts[/cyan]")

# Analyze each alert using the AI classifier
for alert in alerts:

    print("\n[bold yellow]Analyzing Alert:[/bold yellow]", alert["alert_id"])

    result = classify_alert(alert, playbook_text)

    print(result)