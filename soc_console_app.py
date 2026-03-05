import os
import json
from datetime import datetime
from dotenv import load_dotenv

from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, ListView, ListItem, Label, Button, Static
from textual.containers import Horizontal, Vertical
from textual.reactive import reactive

from workflows.triage_graph import build_graph


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


class PanelBox(Static):
    """A simple bordered panel with a title + body."""
    def __init__(self, title: str, body: str = "", **kwargs):
        super().__init__(**kwargs)
        self.title = title
        self.body = body

    def render(self) -> str:
        return f"[b]{self.title}[/b]\n\n{self.body}"


class RiskGauge(Static):
    """Simple ASCII gauge (0-100)."""
    score: int = reactive(0)

    def render(self) -> str:
        s = max(0, min(100, int(self.score)))
        filled = int(s / 5)  # 20 blocks
        bar = "█" * filled + "░" * (20 - filled)

        if s >= 80:
            level = "HIGH RISK"
        elif s >= 50:
            level = "MEDIUM RISK"
        else:
            level = "LOW RISK"

        return (
            f"[b]CONSOLIDATED ALERT SCORE[/b]\n\n"
            f"Score: [b]{s}[/b] / 100\n"
            f"[{bar}]\n"
            f"Level: [b]{level}[/b]\n"
        )


def compute_risk_score(classification_json: dict, evidence: dict) -> int:
    """Deterministic risk score (demo). We'll improve later."""
    base = 0
    label = (classification_json.get("classification") or "").lower()
    conf = int(classification_json.get("confidence") or 0)

    if label == "malicious":
        base = 70
    elif label == "suspicious":
        base = 45
    elif label == "benign":
        base = 10

    # confidence bump
    base += int(conf * 0.2)

    # evidence bump
    if evidence.get("has_attachment") and evidence.get("attachment_type") in {"zip", "exe", "js"}:
        base += 10
    if evidence.get("has_url"):
        base += 5
    if evidence.get("external_sender"):
        base += 5

    return max(0, min(100, base))


class SOCConsoleApp(App):
    CSS = """
    Screen {
        layout: vertical;
    }

    #body {
        height: 1fr;
    }

    #left {
        width: 32%;
        border: solid gray;
        padding: 1;
    }

    #center {
        width: 46%;
        border: solid gray;
        padding: 1;
    }

    #right {
        width: 22%;
        border: solid gray;
        padding: 1;
    }

    .panel {
        border: solid #444444;
        padding: 1;
        margin-bottom: 1;
        height: auto;
        min-height: 8;
    }

    #alerts_title {
        margin-bottom: 1;
    }

    #analyze_btn {
        margin-top: 1;
        width: 100%;
    }

    #actions_box Button {
        margin-top: 1;
        width: 100%;
    }
    """

    selected_index: int | None = reactive(None)

    def __init__(self):
        super().__init__()
        load_dotenv()
        self.playbook_text = load_playbook()
        self.alerts = load_alerts()
        self.graph = build_graph()

        # UI references (set in compose)
        self.alert_list: ListView | None = None
        self.classifier_panel: PanelBox | None = None
        self.evidence_panel: PanelBox | None = None
        self.response_panel: PanelBox | None = None
        self.risk_gauge: RiskGauge | None = None
        self.meta_box: PanelBox | None = None

    def compose(self) -> ComposeResult:
        yield Header()

        with Horizontal(id="body"):
            # LEFT: Alert Inbox
            with Vertical(id="left"):
                yield Label("[b]SOC • ALERT INBOX[/b]", id="alerts_title")
                self.alert_list = ListView()
                for a in self.alerts:
                    title = f"{a.get('alert_id')} • {a.get('subject','')}"
                    subtitle = f"{a.get('sender','')} → {a.get('user','')}"
                    self.alert_list.append(ListItem(Label(f"{title}\n[dim]{subtitle}[/dim]")))
                yield self.alert_list
                yield Button("Analyze Selected Alert", id="analyze_btn", variant="primary")

            # CENTER: Agent Panels
            with Vertical(id="center"):
                self.classifier_panel = PanelBox("Classifier Agent", "Select an alert, then click Analyze.", classes="panel")
                self.evidence_panel = PanelBox("Evidence Collector", "Waiting…", classes="panel")
                self.response_panel = PanelBox("Response Agent", "Waiting…", classes="panel")
                yield self.classifier_panel
                yield self.evidence_panel
                yield self.response_panel

            # RIGHT: Score + Actions
            with Vertical(id="right"):
                self.risk_gauge = RiskGauge(classes="panel")
                self.meta_box = PanelBox("Selected Alert", "None", classes="panel")
                yield self.risk_gauge
                yield self.meta_box

                with Vertical(id="actions_box"):
                    yield Label("[b]AUTOMATED RESPONSE[/b]")
                    yield Button("Execute Quarantine (demo)", id="btn_quarantine", variant="warning")
                    yield Button("Send to Analyst (demo)", id="btn_analyst", variant="default")

        yield Footer()

    def on_list_view_highlighted(self, event: ListView.Highlighted) -> None:
        self.selected_index = event.index
        a = self.alerts[self.selected_index]
        if self.meta_box:
            self.meta_box.body = (
                f"Alert ID: {a.get('alert_id')}\n"
                f"User: {a.get('user')}\n"
                f"Sender: {a.get('sender')}\n"
                f"Subject: {a.get('subject')}\n"
                f"Reported by user: {a.get('reported_by_user')}\n"
            )
            self.meta_box.refresh()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "analyze_btn":
            self.run_analysis()
        elif event.button.id == "btn_quarantine":
            self.notify("Demo: would quarantine email in Defender/Exchange.")
        elif event.button.id == "btn_analyst":
            self.notify("Demo: would create ticket / notify analyst.")

    def run_analysis(self) -> None:
        if self.selected_index is None:
            self.notify("Select an alert first.")
            return

        alert = self.alerts[self.selected_index]

        # Stage banners (we will animate these in the next step)
        if self.classifier_panel:
            self.classifier_panel.body = "Running…"
            self.classifier_panel.refresh()
        if self.evidence_panel:
            self.evidence_panel.body = "Waiting…"
            self.evidence_panel.refresh()
        if self.response_panel:
            self.response_panel.body = "Waiting…"
            self.response_panel.refresh()

        # Run the graph end-to-end (next step we show live per-stage transitions)
        state = self.graph.invoke(
            {
                "alert": alert,
                "playbook_text": self.playbook_text,
                "classification_json": {},
                "evidence": {},
                "response_plan": {},
            }
        )

        classification = state["classification_json"]
        evidence = state["evidence"]
        response_plan = state["response_plan"]

        if self.classifier_panel:
            self.classifier_panel.body = json.dumps(classification, indent=2)
            self.classifier_panel.refresh()

        if self.evidence_panel:
            self.evidence_panel.body = json.dumps(evidence, indent=2)
            self.evidence_panel.refresh()

        if self.response_panel:
            self.response_panel.body = json.dumps(response_plan, indent=2)
            self.response_panel.refresh()

        score = compute_risk_score(classification, evidence)
        if self.risk_gauge:
            self.risk_gauge.score = score
            self.risk_gauge.refresh()


if __name__ == "__main__":
    SOCConsoleApp().run()