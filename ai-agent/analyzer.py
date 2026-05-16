import os
import json
import logging
from groq import Groq

log = logging.getLogger("analyzer")

client = Groq(api_key=os.environ.get("GROQ_API_KEY"))

SYSTEM_PROMPT = """You are a Kubernetes security expert analyzing Falco runtime alerts.
Given a Falco alert JSON, you must respond ONLY with a valid JSON object, no other text.

The JSON must have exactly these fields:
{
  "risk_score": <integer 0-100>,
  "action": <"delete_pod" | "quarantine_pod" | "alert_only" | "ignore">,
  "reason": <string explaining the decision>
}

Scoring rules:
- Emergency/Critical/Alert priority: base score 80+
- Warning priority: base score 60
- Notice priority: base score 40
- /etc/shadow access: +30
- Shell in container: +30
- Privilege escalation: +30
- Score >= 90: delete_pod
- Score 70-89: quarantine_pod
- Score 40-69: alert_only
- Score < 40: ignore
- Max score: 100"""


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

    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": f"Analyze this Falco alert:\n{json.dumps(alert, indent=2)}"}
            ],
            temperature=0,
            max_tokens=200
        )

        raw = response.choices[0].message.content.strip()
        result = json.loads(raw)

        risk_score = min(int(result.get("risk_score", 50)), 100)
        action = result.get("action", "alert_only")
        reason = result.get("reason", "LLM analysis")

        log.info(f"LLM scored rule={rule} score={risk_score} action={action}")

    except Exception as e:
        log.warning(f"LLM failed, falling back to rules: {e}")
        risk_score = _rule_based_score(priority, rule, file)
        action = _score_to_action(risk_score)
        reason = f"Rule-based fallback: {e}"

    return {
        "rule": rule,
        "priority": priority,
        "namespace": namespace,
        "pod": pod,
        "node": node,
        "command": command,
        "user": user,
        "file": file,
        "risk_score": risk_score,
        "action": action,
        "reason": reason
    }


def _rule_based_score(priority: str, rule: str, file: str) -> int:
    score = 0
    if priority in ["Emergency", "Alert", "Critical"]:
        score += 80
    elif priority == "Warning":
        score += 60
    elif priority == "Notice":
        score += 40

    if "/etc/shadow" in file:
        score += 30
    if "Terminal shell in container" in rule:
        score += 30
    if "Privilege escalation" in rule:
        score += 30
    if priority == "Notice":
        score += 30

    return min(score, 100)


def _score_to_action(score: int) -> str:
    if score >= 90:
        return "delete_pod"
    elif score >= 70:
        return "quarantine_pod"
    elif score >= 40:
        return "alert_only"
    return "ignore"
