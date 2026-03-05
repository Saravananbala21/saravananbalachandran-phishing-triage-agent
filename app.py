import os
import json
import time
from datetime import datetime

import streamlit as st
from dotenv import load_dotenv

from agents.phishing_classifier import classify_alert
from agents.evidence_collector import collect_evidence
from agents.response_agent import generate_response

load_dotenv()


# -----------------------------
# Data helpers
# -----------------------------
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


def compute_risk_score(classification_json: dict, evidence: dict) -> int:
    label = (classification_json.get("classification") or "").lower()
    conf = int(classification_json.get("confidence") or 0)

    if label == "malicious":
        score = 70
    elif label == "suspicious":
        score = 45
    else:
        score = 10

    score += int(conf * 0.2)

    if evidence.get("has_attachment") and evidence.get("attachment_type") in {"zip", "exe", "js"}:
        score += 10
    if evidence.get("has_url"):
        score += 5
    if evidence.get("external_sender"):
        score += 5

    return max(0, min(100, score))


def risk_meta(score: int) -> tuple[str, str]:
    if score >= 80:
        return "HIGH", "🔴"
    if score >= 50:
        return "MEDIUM", "🟠"
    return "LOW", "🟢"


def save_report(selected_alert: dict, classification: dict, evidence: dict, response_plan: dict) -> str:
    os.makedirs("data/output", exist_ok=True)
    report_path = os.path.join("data/output", "triage_report_streamlit.json")
    report = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "alert": selected_alert,
        "classification": classification,
        "evidence": evidence,
        "response_plan": response_plan,
    }
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    return report_path


# -----------------------------
# SOC handoff logic (NEW)
# -----------------------------
def soc_handoff_plan(classification: dict, evidence: dict, score: int) -> dict:
    """
    Produces what L1/L2/L3 should do, based on outcome.
    This is what management wants to see clearly in the UI.
    """
    label = (classification.get("classification") or "").lower()

    # default (benign-ish)
    plan = {
        "L1": [
            "Validate sender & subject match normal business context",
            "Confirm URL/attachment signals are low-risk",
            "Close alert with notes + classification evidence",
        ],
        "L2": [
            "No action required (unless multiple similar alerts appear)",
        ],
        "L3": [
            "No action required",
        ],
    }

    if label == "suspicious" or (50 <= score < 80):
        plan = {
            "L1": [
                "Do quick verification: sender legitimacy + user confirmation",
                "Preserve evidence (URLs, headers, attachment metadata)",
                "Escalate to L2 with evidence + risk score",
            ],
            "L2": [
                "Perform deeper enrichment: domain/URL reputation + mailbox search",
                "Check if campaign exists (similar subjects/senders)",
                "Decide containment: quarantine / block / user reset recommendation",
            ],
            "L3": [
                "Engage only if campaign confirmed or targeted executive phishing",
                "Hunt for related indicators across environment",
            ],
        }

    if label == "malicious" or score >= 80:
        plan = {
            "L1": [
                "Immediately quarantine email (if integrated) / isolate message",
                "Escalate to L2 with full evidence bundle",
                "Notify SOC lead (high-severity) if required by SOP",
            ],
            "L2": [
                "Confirm maliciousness (URL/attachment analysis, sandbox if available)",
                "Initiate containment: block sender/domain/URL, mailbox sweep",
                "Assess user impact: credential reset, MFA review, sign-in logs",
            ],
            "L3": [
                "Incident response: scope, eradication, recovery",
                "Threat intel correlation + attacker infrastructure mapping",
                "Hunting + detection engineering (rules, detections, automation)",
            ],
        }

    return plan


# -----------------------------
# Page + Theme (still “VP demo”)
# -----------------------------
st.set_page_config(page_title="SOC Phishing Triage Agent", layout="wide")

st.markdown(
    """
<style>
.block-container { padding-top: 1.2rem; padding-bottom: 2rem; max-width: 1400px; }
.main { background: linear-gradient(180deg, #f6fbff 0%, #ffffff 60%); }
section[data-testid="stSidebar"] { background: #f2f8ff; border-right: 1px solid #d6e7ff; }

/* Hero */
.hero {
  background: linear-gradient(90deg, #0b5cab 0%, #2b7bd6 55%, #58a6ff 100%);
  padding: 18px 18px; border-radius: 14px; color: white;
  box-shadow: 0 10px 30px rgba(11,92,171,0.18);
  margin-bottom: 18px;
}
.hero h1 { margin: 0; font-size: 28px; font-weight: 800; }
.hero p { margin: 6px 0 0 0; opacity: 0.95; }

/* Cards */
.card {
  background: white; border: 1px solid #e6f0ff; border-radius: 14px;
  padding: 14px 14px; box-shadow: 0 6px 18px rgba(16, 64, 128, 0.08);
  margin-bottom: 14px;
}
.card h3 { margin: 0 0 10px 0; font-size: 15px; color: #0b3a72; }
.subtle { color: #5a6b85; font-size: 12.5px; }

/* Small chips */
.chip {
  display:inline-block; padding: 4px 10px; border-radius: 999px;
  background:#eaf4ff; border: 1px solid #cfe6ff; color:#0b5cab;
  font-size:12px; font-weight:700; margin-right: 6px; margin-bottom: 6px;
}
.chip-gray { background:#f3f5f8; border:1px solid #e6e9ef; color:#4b5563; }
.chip-red { background:#ffe9ea; border:1px solid #ffc6c9; color:#b42318; }
.chip-amber { background:#fff4e5; border:1px solid #ffd9a6; color:#b54708; }
.chip-green { background:#e9f9ef; border:1px solid #bfe7ce; color:#067647; }

/* Stage strip */
.stage {
  display:flex; align-items:center; justify-content: space-between;
  padding: 10px 12px; border-radius: 12px;
  background: #f7fbff; border: 1px solid #e6f0ff;
  margin-bottom: 10px;
}
.stage b { color:#0b3a72; }
.ok { color:#067647; font-weight:800; }
.run { color:#0b5cab; font-weight:800; }
.wait { color:#5a6b85; font-weight:800; }

/* emphasis headers for SOC handoff */
.handoff-title { font-weight: 900; color:#0b3a72; margin-top: 8px; }
</style>
""",
    unsafe_allow_html=True,
)

# -----------------------------
# Load once
# -----------------------------
if "alerts" not in st.session_state:
    st.session_state.alerts = load_alerts()
if "playbook" not in st.session_state:
    st.session_state.playbook = load_playbook()

alerts = st.session_state.alerts
playbook_text = st.session_state.playbook

# -----------------------------
# Header
# -----------------------------
st.markdown(
    """
<div class="hero">
  <h1>SOC Phishing Triage Agent</h1>
  <p>Offline demo • Multi-agent pipeline (Classifier → Evidence → Response) • Localhost</p>
</div>
""",
    unsafe_allow_html=True,
)

# -----------------------------
# Sidebar
# -----------------------------
st.sidebar.markdown("### Alert Inbox")
alert_labels = [f"{a['alert_id']} — {a.get('subject','')}" for a in alerts]
selected_idx = st.sidebar.radio("Select an alert", list(range(len(alerts))), format_func=lambda i: alert_labels[i])
selected_alert = alerts[selected_idx]
st.sidebar.markdown("---")
analyze_clicked = st.sidebar.button("Analyze Selected Alert", type="primary")

# -----------------------------
# Layout columns
# -----------------------------
col_left, col_center, col_right = st.columns([1.15, 2.35, 1.05], gap="large")

# -----------------------------
# Render helpers
# -----------------------------
def chip(text: str, kind: str = "blue"):
    cls = "chip"
    if kind == "gray":
        cls = "chip chip-gray"
    elif kind == "red":
        cls = "chip chip-red"
    elif kind == "amber":
        cls = "chip chip-amber"
    elif kind == "green":
        cls = "chip chip-green"
    st.markdown(f'<span class="{cls}">{text}</span>', unsafe_allow_html=True)


def stage_row(name: str, status: str, cls: str):
    st.markdown(f'<div class="stage"><b>{name}</b><span class="{cls}">{status}</span></div>', unsafe_allow_html=True)


def card_open(title: str):
    st.markdown(f'<div class="card"><h3>{title}</h3>', unsafe_allow_html=True)


def card_close():
    st.markdown("</div>", unsafe_allow_html=True)


# -----------------------------
# LEFT: Selected Alert
# -----------------------------
with col_left:
    card_open("Selected Alert")
    a = selected_alert

    st.write(f"**Alert ID:** {a.get('alert_id','-')}")
    st.write(f"**Timestamp:** {a.get('timestamp','-')}")
    st.write(f"**User:** {a.get('user','-')}")
    st.write(f"**Sender:** {a.get('sender','-')}")
    st.write(f"**Subject:** {a.get('subject','-')}")
    st.write(f"**URL:** {a.get('url') or '-'}")

    attach = a.get("attachment")
    attach_txt = "-" if not attach else f"{attach.get('file_name','attachment')} ({attach.get('file_type','')})"
    st.write(f"**Attachment:** {attach_txt}")

    reported = "Yes" if a.get("reported_by_user") else "No"
    st.write(f"**Reported by user:** {reported}")

    snippet = a.get("email_body_snippet")
    if snippet:
        st.caption("Snippet")
        st.info(snippet)

    card_close()

# -----------------------------
# CENTER: Stages + 3 output sections
# -----------------------------
with col_center:
    card_open("Agent Stages")
    stage_placeholder = st.empty()
    card_close()

    classifier_box = st.container()
    evidence_box = st.container()
    response_box = st.container()

# -----------------------------
# RIGHT: Score + actions + HANDOFF (NEW)
# -----------------------------
with col_right:
    score_box = st.container()
    action_box = st.container()
    handoff_box = st.container()
    artifact_box = st.container()


def render_stages(s1, s2, s3):
    with stage_placeholder.container():
        stage_row("Classifier Agent", s1[0], s1[1])
        stage_row("Evidence Collector", s2[0], s2[1])
        stage_row("Response Agent", s3[0], s3[1])


def render_classifier_native(classification: dict):
    with classifier_box:
        card_open("Classifier Output")

        label = classification.get("classification", "-")
        conf = classification.get("confidence", "-")
        indicators = classification.get("indicators", []) or []
        reason = classification.get("reason") or ""

        c1, c2 = st.columns([1, 1])
        with c1:
            st.write("**Classification**")
            if str(label).lower() == "malicious":
                chip(label, "red")
            elif str(label).lower() == "suspicious":
                chip(label, "amber")
            else:
                chip(label, "green")
        with c2:
            st.metric("Confidence", f"{conf}%")

        st.write("**Key Indicators**")
        if indicators:
            for ind in indicators[:10]:
                chip(ind, "blue")
        else:
            chip("No indicators", "gray")

        if reason:
            st.write("**Analyst Summary**")
            st.info(reason)

        card_close()


def render_evidence_native(evidence: dict):
    with evidence_box:
        card_open("Evidence Collected (Deterministic)")

        c1, c2, c3 = st.columns(3)
        c1.metric("External Sender", "Yes" if evidence.get("external_sender") else "No")
        c2.metric("Has URL", "Yes" if evidence.get("has_url") else "No")
        c3.metric("Has Attachment", "Yes" if evidence.get("has_attachment") else "No")

        st.write("**Domains**")
        st.write(f"- Sender domain: `{evidence.get('sender_domain') or '-'}`")
        st.write(f"- URL domain: `{evidence.get('url_domain') or '-'}`")

        st.write("**Attachment**")
        st.write(f"- Type: `{evidence.get('attachment_type') or '-'}`")

        card_close()


def render_response_native(response_plan: dict):
    with response_box:
        card_open("Recommended Response")

        steps = response_plan.get("response_plan", []) or []
        if steps:
            st.write("**Actions (SOC Runbook-style)**")
            for i, step in enumerate(steps, start=1):
                st.write(f"{i}. {step}")
        else:
            st.write("No response actions produced.")

        card_close()


def render_score_and_actions(score: int):
    level, emoji = risk_meta(score)

    with score_box:
        card_open("Consolidated Score")
        st.markdown(f"### {score} / 100  &nbsp;  **{emoji} {level} RISK**")
        st.progress(score / 100.0)
        card_close()

    with action_box:
        card_open("Automated Response")
        c1, c2 = st.columns(2)
        with c1:
            if st.button("Execute Quarantine (demo)"):
                st.warning("Demo action: would quarantine email in Defender/Exchange.")
        with c2:
            if st.button("Send to Analyst (demo)"):
                st.info("Demo action: would create ticket / notify analyst.")
        card_close()


def render_handoff(classification: dict, evidence: dict, score: int):
    plan = soc_handoff_plan(classification, evidence, score)

    with handoff_box:
        card_open("SOC Handoff (L1 / L2 / L3)")
        st.caption("This makes responsibilities explicit for each SOC tier based on the triage outcome.")

        st.markdown("**L1 — Triage & Routing**")
        for x in plan["L1"]:
            st.write(f"- {x}")

        st.markdown("**L2 — Investigation & Enrichment**")
        for x in plan["L2"]:
            st.write(f"- {x}")

        st.markdown("**L3 — Incident Response / Threat Hunting**")
        for x in plan["L3"]:
            st.write(f"- {x}")

        card_close()


def render_artifact(path: str):
    with artifact_box:
        card_open("Run Artifact")
        st.caption("Saved demo report")
        st.code(path)
        card_close()


# -----------------------------
# Run analysis
# -----------------------------
if analyze_clicked:
    render_stages(("RUNNING…", "run"), ("WAITING…", "wait"), ("WAITING…", "wait"))
    time.sleep(0.25)

    raw = classify_alert(selected_alert, playbook_text)
    classification = json.loads(raw)
    render_classifier_native(classification)

    render_stages(("DONE ✓", "ok"), ("RUNNING…", "run"), ("WAITING…", "wait"))
    time.sleep(0.25)

    evidence = collect_evidence(selected_alert)
    render_evidence_native(evidence)

    render_stages(("DONE ✓", "ok"), ("DONE ✓", "ok"), ("RUNNING…", "run"))
    time.sleep(0.25)

    response_plan = generate_response(classification)
    render_response_native(response_plan)

    render_stages(("DONE ✓", "ok"), ("DONE ✓", "ok"), ("DONE ✓", "ok"))

    score = compute_risk_score(classification, evidence)
    render_score_and_actions(score)

    # NEW: show L1/L2/L3 responsibilities
    render_handoff(classification, evidence, score)

    path = save_report(selected_alert, classification, evidence, response_plan)
    render_artifact(path)

else:
    render_stages(("WAITING…", "wait"), ("WAITING…", "wait"), ("WAITING…", "wait"))
    with classifier_box:
        card_open("Classifier Output")
        st.caption("Awaiting analysis…")
        card_close()
    with evidence_box:
        card_open("Evidence Collected (Deterministic)")
        st.caption("Awaiting analysis…")
        card_close()
    with response_box:
        card_open("Recommended Response")
        st.caption("Awaiting analysis…")
        card_close()
    with score_box:
        card_open("Consolidated Score")
        st.caption("Select an alert and click Analyze Selected Alert.")
        card_close()
    with action_box:
        card_open("Automated Response")
        st.caption("Actions appear after analysis.")
        card_close()
    with handoff_box:
        card_open("SOC Handoff (L1 / L2 / L3)")
        st.caption("Will appear after analysis.")
        card_close()
    with artifact_box:
        card_open("Run Artifact")
        st.caption("A report path will appear after analysis.")
        card_close()