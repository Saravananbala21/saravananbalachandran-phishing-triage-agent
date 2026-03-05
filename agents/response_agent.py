def generate_response(classification: dict) -> dict:

    label = classification.get("classification", "").lower()

    if label == "malicious":
        actions = [
            "Quarantine email",
            "Block sender domain",
            "Search mailbox for similar emails",
            "Notify SOC team"
        ]

    elif label == "suspicious":
        actions = [
            "Escalate to human analyst",
            "Monitor related emails",
            "Flag sender for review"
        ]

    else:
        actions = [
            "Close alert",
            "No further action required"
        ]

    return {
        "alert_id": classification.get("alert_id"),
        "response_plan": actions
    }