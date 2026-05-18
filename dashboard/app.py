from flask import Flask, jsonify, render_template_string, Response
from kubernetes import client, config
import json, threading, time
from collections import deque

app = Flask(__name__)

try:
    config.load_incluster_config()
except:
    config.load_kube_config()

core_api = client.CoreV1Api()
net_api  = client.NetworkingV1Api()

NAMESPACES      = ["apps","security","kafka-system","monitoring","gatekeeper-system"]
KAFKA_BOOTSTRAP = "kafka.kafka-system.svc.cluster.local:9092"
agent_logs      = {"lines": [], "pod": ""}


def get_agent_pod():
    try:
        pods = core_api.list_namespaced_pod("apps", label_selector="app=ai-agent")
        if pods.items:
            return pods.items[0].metadata.name
    except:
        pass
    return None


def poll_agent_logs():
    while True:
        try:
            pod = get_agent_pod()
            if pod:
                combined = []

                for container in ["ai-agent", "istio-proxy"]:
                    try:
                        logs = core_api.read_namespaced_pod_log(
                            name=pod,
                            namespace="apps",
                            container=container,
                            tail_lines=100
                        )
                        combined.append(f"\n===== {container} logs =====\n")
                        combined.append(logs)
                    except Exception as e:
                        combined.append(f"\n===== {container} logs unavailable: {e} =====\n")

                agent_logs["lines"] = "\n".join(combined).split("\n")
                agent_logs["pod"] = pod
        except Exception:
            pass

        time.sleep(8)

threading.Thread(target=poll_agent_logs, daemon=True).start()


def kafka_fetch(topic, max_messages=100):
    """Fetch all messages from a Kafka topic using partition assign (no group coordinator)."""
    try:
        from confluent_kafka import Consumer, TopicPartition
        c = Consumer({
            "bootstrap.servers": KAFKA_BOOTSTRAP,
            "group.id": "dashboard-reader",
            "enable.auto.commit": False,
        })
        tp = TopicPartition(topic, 0, 0)
        c.assign([tp])
        messages = []
        deadline = time.time() + 4
        while time.time() < deadline and len(messages) < max_messages:
            msg = c.poll(0.3)
            if msg is None:
                continue
            if msg.error():
                break
            try:
                messages.append(json.loads(msg.value().decode("utf-8")))
            except:
                pass
        c.close()
        return messages
    except Exception as e:
        print(f"[ERROR] kafka_fetch {topic}: {e}", flush=True)
        return []


@app.route("/api/pods")
def pods():
    result = []
    for ns in NAMESPACES:
        try:
            for p in core_api.list_namespaced_pod(ns).items:
                labels = p.metadata.labels or {}
                sec = labels.get("security.status", "normal")
                ready = any(c.type=="Ready" and c.status=="True"
                            for c in (p.status.conditions or []))
                result.append({"name": p.metadata.name, "namespace": ns,
                                "status": p.status.phase, "ready": ready,
                                "security_status": sec})
        except:
            pass
    return jsonify(result)


@app.route("/api/audit")
def audit():
    msgs = kafka_fetch("agent-decisions")
    return jsonify(list(reversed(msgs)))


@app.route("/api/kafka")
def kafka():
    msgs = kafka_fetch("falco-alerts", max_messages=20)
    return jsonify({"messages": list(reversed(msgs))})


@app.route("/api/stats")
def stats():
    msgs = kafka_fetch("agent-decisions")
    counts = {"alert_only": 0, "quarantine_pod": 0, "delete_pod": 0, "ignore": 0}
    for e in msgs:
        a = e.get("action", "ignore")
        counts[a] = counts.get(a, 0) + 1

    pod_counts = {}
    running_total = 0
    for ns in NAMESPACES:
        try:
            pl = core_api.list_namespaced_pod(ns).items
            pod_counts[ns] = len(pl)
            running_total += sum(1 for p in pl if p.status.phase == "Running")
        except:
            pod_counts[ns] = 0

    np_count = 0
    try:
        np_count = len(net_api.list_namespaced_network_policy("apps").items)
    except:
        pass

    return jsonify({"actions": counts, "pod_counts": pod_counts,
                    "running_pods": running_total, "network_policies": np_count,
                    "total_events": sum(counts.values())})


@app.route("/api/networkpolicies")
def networkpolicies():
    result = []
    try:
        for np in net_api.list_namespaced_network_policy("apps").items:
            result.append({"name": np.metadata.name, "namespace": np.metadata.namespace})
    except:
        pass
    return jsonify(result)


@app.route("/api/agent-logs")
def api_agent_logs():
    return jsonify({"logs": "\n".join(agent_logs["lines"]), "pod": agent_logs["pod"]})


@app.route("/api/stream")
def stream():
    def generate():
        last = 0
        while True:
            try:
                msgs = kafka_fetch("agent-decisions")
                if len(msgs) > last:
                    for e in msgs[last:]:
                        yield f"data: {json.dumps(e)}\n\n"
                    last = len(msgs)
            except:
                pass
            time.sleep(3)
    return Response(generate(), mimetype="text/event-stream")


@app.route("/")
def index():
    return render_template_string(open("/app/dashboard.html").read())


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)