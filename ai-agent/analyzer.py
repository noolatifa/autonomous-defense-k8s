
def analyze_alert(alert: dict) -> dict:
    rule = alert.get("rule", "unknown")
    priority = alert.get("priority", "unknown")
    fields = alert.get("output_fields", {})

    pod = fields.get("k8s.pod.name", "unknown")
    namespace = fields.get("k8s.ns.name", "unknown")
    command = fields.get("proc.cmdline", "unknown")
    user = fields.get("user.name", "unknown")
    file = fields.get("fd.name", "")
    node = alert.get("hostname", "unknown")


    risk_score = 0

    # Priority base score
    if priority in ["Emergency", "Alert", "Critical"]:
        risk_score += 80
    elif priority == "Warning":
        risk_score += 60
    elif priority == "Notice":
        risk_score += 40

    # Rule bonuses
    if "/etc/shadow" in file:
        risk_score += 30
    if "/etc/passwd" in file:
        risk_score += 20
    if "Terminal shell in container" in rule:
        risk_score += 30
    if "Privilege escalation" in rule:
        risk_score += 30
    if "Write below binary dir" in rule:
        risk_score += 20
    if "Outbound connection" in rule:
        risk_score += 20
    if priority == "Notice":
        risk_score += 30
    if "/etc/sudoers" in file:
        risk_score += 10



    risk_score = min(risk_score, 100)

    return {
        "rule": rule,
        "priority": priority,
        "namespace": namespace,
        "pod": pod,
        "node": node,
        "command": command,
        "user": user,
        "file": file,
        "risk_score": risk_score
    }
