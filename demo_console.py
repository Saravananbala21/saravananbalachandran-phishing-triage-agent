import os
import json
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns
from rich.rule import Rule

from workflows.triage_graph import build_graph

console = Console()
load_dotenv()


def load_playbook() -> str:
    with open("playbooks/phishing_triage_playbook.md", "r", encoding="utf-8") as f:
        return f.read()


def load_alerts() -> list[dict]:
    alerts = []
    folder = "data/sample_alerts"
    for file in sorted(os.listdir(folder)):
        if file.endswith(".json"):
            with open(os.path.join(folder, file), "r", encoding="utf-8") as f:
                alerts.append(json.load(f))
    return alerts


def render_alerts_table(alerts: list[dict]) -> Table:
    t = Table(title="Phishing Alerts (Offline Sample)", show_lines=True)
    t.add_column("#", justify="right", style="cyan", no_wrap=True)
    t.add_column("Alert ID", style="bold")
    t.add_column("User")
    t.add_column("Sender")
    t.add_column("Subject")

    for i, a in enumerate(alerts, start=1):
        t.add_row(
            str(i),
            a.get("alert_id", ""),
            a.get("user", ""),
            a.get("sender", ""),
            a.get("subject", ""),
        )
    return t


def render_details_panel(text: str) -> Panel:
    return Panel(text, title="Details", border_style="green")


def main():
    playbook_text = load_playbook()
    alerts = load_alerts()
    graph = build_graph()

    while True:
        console.clear()

        left = render_alerts_table(alerts)
        right = render_details_panel(
            "Choose an alert number and press Enter.\n\n"
            "[bold]Commands[/bold]\n"
            "- Type a number (e.g., 1)\n"
            "- q = quit\n\n"
            "After selection, you will see stages:\n"
            "1) Classifier → 2) Evidence → 3) Response (Risk score next step)"
        )

        console.print(Columns([left, right], equal=True))
        console.print(Rule())

        choice = console.input("[bold yellow]Select alert # (or q): [/bold yellow]").strip()

        if choice.lower() == "q":
            break

        if not choice.isdigit():
            continue

        idx = int(choice) - 1
        if idx < 0 or idx >= len(alerts):
            continue

        alert = alerts[idx]

        console.clear()
        console.print(Panel(f"[bold]Analyzing[/bold] {alert['alert_id']}  |  {alert.get('subject','')}", border_style="yellow"))
        console.print()

        # Stage-by-stage (we’ll animate these in next steps)
        console.print("[bold cyan]Stage 1:[/bold cyan] Classifier Agent running...")
        console.print("[dim]Stage 2 will run after classifier completes[/dim]")
        console.print("[dim]Stage 3 will run after evidence completes[/dim]")
        console.print()

        # Run the graph (currently runs end-to-end; next steps will show live per-node progress)
        result_state = graph.invoke(
            {
                "alert": alert,
                "playbook_text": playbook_text,
                "classification_json": {},
                "evidence": {},
                "response_plan": {},
            }
        )

        console.print(Rule("RESULTS"))
        console.print(Panel(json.dumps(result_state["classification_json"], indent=2), title="Classifier Output (JSON)", border_style="green"))
        console.print(Panel(json.dumps(result_state["evidence"], indent=2), title="Evidence Output (Deterministic)", border_style="blue"))
        console.print(Panel(json.dumps(result_state["response_plan"], indent=2), title="Response Plan", border_style="magenta"))

        console.print()
        console.input("[bold]Press Enter to go back to alert list...[/bold]")


if __name__ == "__main__":
    main()