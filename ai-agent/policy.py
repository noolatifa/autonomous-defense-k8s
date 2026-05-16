ALLOWED_ACTIONS = ["delete_pod", "quarantine_pod", "alert_only", "ignore"]

def decide_action(analysis: dict) -> dict:
    score = analysis["risk_score"]
    
    # Use LLM action if available and valid
    action = analysis.get("action", "")
    if action not in ALLOWED_ACTIONS:
        # fallback to rule-based
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
        "reason": analysis.get("reason", f"Risk score is {score}"),
        "target_namespace": analysis["namespace"],
        "target_pod": analysis["pod"],
        "target_node": analysis["node"],
        "rule": analysis["rule"],
        "risk_score": score
    }
