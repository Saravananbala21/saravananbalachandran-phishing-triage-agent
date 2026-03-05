import json
from typing import TypedDict, Any, Dict

from langgraph.graph import StateGraph, END

from agents.phishing_classifier import classify_alert
from agents.evidence_collector import collect_evidence
from agents.response_agent import generate_response


class TriageState(TypedDict):
    alert: Dict[str, Any]
    playbook_text: str
    classification_json: Dict[str, Any]
    evidence: Dict[str, Any]
    response_plan: Dict[str, Any]


def classifier_node(state: TriageState) -> TriageState:
    raw = classify_alert(state["alert"], state["playbook_text"])
    classification = json.loads(raw)
    return {
        **state,
        "classification_json": classification
    }


def evidence_node(state: TriageState) -> TriageState:
    evidence = collect_evidence(state["alert"])
    return {
        **state,
        "evidence": evidence
    }


def response_node(state: TriageState) -> TriageState:
    response_plan = generate_response(state["classification_json"])
    return {
        **state,
        "response_plan": response_plan
    }


def build_graph():
    g = StateGraph(TriageState)

    g.add_node("classifier", classifier_node)
    g.add_node("evidence", evidence_node)
    g.add_node("response", response_node)

    g.set_entry_point("classifier")
    g.add_edge("classifier", "evidence")
    g.add_edge("evidence", "response")
    g.add_edge("response", END)

    return g.compile()