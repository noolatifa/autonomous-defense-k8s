def decide_action(analysis: dict) -> dict:
    score = analysis["risk_score"]

    if score >= 90:
        action = "delete_pod"
    elif score >= 70:
        action = "quarantine_pod"
    elif score >= 40:
        action = "alert_only"
    else:
        action = "ignore"

    return {
        "action": action,
        "reason": f"Risk score is {score}",
        "target_namespace": analysis["namespace"],
        "target_pod": analysis["pod"]
    }
