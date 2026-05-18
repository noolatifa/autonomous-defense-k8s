import json
import logging
from confluent_kafka import Consumer
from analyzer import analyze_alert
from policy import decide_action
from enforcer import enforce

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger("consumer")

IGNORED_PREFIXES = (
    "ai-agent",
    "defense-dashboard",
    "coredns",
    "calico",
    "prometheus",
    "grafana",
    "gatekeeper",
    "falco",
)

consumer = Consumer({
    "bootstrap.servers": "kafka.kafka-system.svc.cluster.local:9092",
    "group.id": "ai-detection-agent",
    "auto.offset.reset": "earliest"
})
consumer.subscribe(["falco-alerts"])
log.info("AI Detection Agent started. Waiting for Falco alerts...")

while True:
    msg = consumer.poll(1.0)
    if msg is None:
        continue
    if msg.error():
        log.error(f"Kafka error: {msg.error()}")
        continue
    try:
        alert = json.loads(msg.value().decode("utf-8"))
        pod = (alert.get("output_fields") or {}).get("k8s.pod.name", "") or ""
        if any(pod.startswith(p) for p in IGNORED_PREFIXES):
            log.debug(f"Ignoring system pod {pod}")
            continue
        analysis = analyze_alert(alert)
        decision = decide_action(analysis)
        log.info(f"ALERT  rule={analysis['rule']} score={analysis['risk_score']} "
                 f"pod={analysis['pod']} ns={analysis['namespace']}")
        log.info(f"DECISION action={decision['action']} reason={decision['reason']}")
        enforce(decision, analysis)
    except Exception as e:
        log.error(f"Error processing alert: {e}", exc_info=True)