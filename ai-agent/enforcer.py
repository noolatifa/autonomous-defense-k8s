"""
enforcer.py — UPDATED FOR ISTIO
Changes vs original:
  1. quarantine_pod now creates an Istio AuthorizationPolicy (DENY) instead of
     only a NetworkPolicy. Both are applied so the quarantine works even if
     Istio sidecar injection is not yet ready on a pod.
  2. New helper: _apply_istio_quarantine() / _remove_istio_quarantine()
  3. delete_pod cleanup now also removes the Istio AuthorizationPolicy.
  4. All other logic (audit log, scale up/down, label, Kafka publish) unchanged.
"""

import json
import logging
import time
from datetime import datetime, timezone
from typing import Optional

from confluent_kafka import Producer
from kubernetes import client, config
from kubernetes.client.rest import ApiException

log = logging.getLogger("enforcer")

# ── Kubernetes clients ────────────────────────────────────────────────────────
try:
    config.load_incluster_config()
except config.ConfigException:
    config.load_kube_config()

core_api  = client.CoreV1Api()
apps_api  = client.AppsV1Api()
net_api   = client.NetworkingV1Api()
# CustomObjectsApi is used to create Istio AuthorizationPolicy CRs
crd_api   = client.CustomObjectsApi()

# ── Kafka producer (publishes decisions to agent-decisions topic) ─────────────
_producer = Producer({"bootstrap.servers": "kafka.kafka-system.svc.cluster.local:9092"})

AUDIT_LOG = "/var/log/agent/audit.log"
DECISIONS_TOPIC = "agent-decisions"

# Istio CRD info
ISTIO_GROUP   = "security.istio.io"
ISTIO_VERSION = "v1beta1"
AUTHZ_PLURAL  = "authorizationpolicies"


# ── Internal helpers ──────────────────────────────────────────────────────────

def _write_audit(record: dict):
    """Append a JSON line to the audit log."""
    record["timestamp"] = datetime.now(timezone.utc).isoformat()
    try:
        with open(AUDIT_LOG, "a") as f:
            f.write(json.dumps(record) + "\n")
    except Exception as e:
        log.error(f"Audit write failed: {e}")


def _publish_decision(record: dict):
    """Publish decision event to Kafka agent-decisions topic."""
    try:
        _producer.produce(DECISIONS_TOPIC, json.dumps(record).encode())
        _producer.flush()
    except Exception as e:
        log.error(f"Kafka publish failed: {e}")


def _label_pod(pod_name: str, namespace: str, labels: dict):
    try:
        core_api.patch_namespaced_pod(
            pod_name, namespace, {"metadata": {"labels": labels}}
        )
        log.info(f"Labelled pod={pod_name} labels={labels}")
    except ApiException as e:
        log.error(f"Failed to label pod {pod_name}: {e}")


def _get_owner_deployment(pod_name: str, namespace: str) -> Optional[str]:
    """Return the Deployment name that owns this pod (via ReplicaSet)."""
    try:
        pod = core_api.read_namespaced_pod(pod_name, namespace)
        for ref in pod.metadata.owner_references or []:
            if ref.kind == "ReplicaSet":
                rs = apps_api.read_namespaced_replica_set(ref.name, namespace)
                for rs_ref in rs.metadata.owner_references or []:
                    if rs_ref.kind == "Deployment":
                        return rs_ref.name
    except ApiException:
        pass
    return None


def _scale_deployment(deployment_name: str, namespace: str, replicas: int):
    try:
        apps_api.patch_namespaced_deployment(
            deployment_name, namespace, {"spec": {"replicas": replicas}}
        )
        log.info(f"Deployment {deployment_name} scaled to {replicas} replicas")
    except ApiException as e:
        log.error(f"Failed to scale deployment {deployment_name}: {e}")


def _wait_for_replacement(deployment_name: str, namespace: str,
                           original_pod: str, timeout: int = 60) -> bool:
    """Wait until a new Running pod (not the original) exists."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            pods = core_api.list_namespaced_pod(
                namespace,
                label_selector=f"app={deployment_name}"
            )
            for pod in pods.items:
                if (pod.metadata.name != original_pod
                        and pod.status.phase == "Running"
                        and all(cs.ready for cs in (pod.status.container_statuses or []))):
                    log.info(f"Clean replacement running — {pod.metadata.name}")
                    return True
        except ApiException:
            pass
        time.sleep(3)
    return False


# ── NetworkPolicy helpers (kept as fallback) ─────────────────────────────────

def _apply_network_isolation(pod_name: str, namespace: str):
    """Create a NetworkPolicy that blocks all ingress/egress for this pod."""
    policy_name = f"isolate-{pod_name}"
    policy = client.V1NetworkPolicy(
        metadata=client.V1ObjectMeta(name=policy_name, namespace=namespace),
        spec=client.V1NetworkPolicySpec(
            pod_selector=client.V1LabelSelector(
                match_labels={"security.status": "quarantined"}
            ),
            policy_types=["Ingress", "Egress"],
            ingress=[],
            egress=[]
        )
    )
    try:
        net_api.create_namespaced_network_policy(namespace, policy)
        log.info(f"NetworkPolicy {policy_name} applied — pod isolated")
    except ApiException as e:
        if e.status == 409:
            log.info(f"NetworkPolicy {policy_name} already exists")
        else:
            log.error(f"NetworkPolicy creation failed: {e}")


def _remove_network_isolation(pod_name: str, namespace: str):
    policy_name = f"isolate-{pod_name}"
    try:
        net_api.delete_namespaced_network_policy(policy_name, namespace)
        log.info(f"NetworkPolicy {policy_name} deleted")
    except ApiException as e:
        if e.status != 404:
            log.error(f"Failed to delete NetworkPolicy: {e}")


# ── NEW: Istio AuthorizationPolicy helpers ────────────────────────────────────

def _apply_istio_quarantine(pod_name: str, namespace: str):
    """
    Create an Istio AuthorizationPolicy that DENIES all traffic to this pod.
    The policy name is prefixed 'istio-quarantine-' so we can find and clean
    it up later independently of the NetworkPolicy.

    Only the ai-agent ServiceAccount is exempted so it can still read logs
    and call the K8s API on the quarantined pod.
    """
    policy_name = f"istio-quarantine-{pod_name}"

    # Extract a stable app label from pod name (e.g. web-cible-abc-xyz → web-cible)
    try:
        pod = core_api.read_namespaced_pod(pod_name, namespace)
        app_label = pod.metadata.labels.get("app", pod_name)
    except ApiException:
        app_label = pod_name

    body = {
        "apiVersion": f"{ISTIO_GROUP}/{ISTIO_VERSION}",
        "kind": "AuthorizationPolicy",
        "metadata": {
            "name": policy_name,
            "namespace": namespace,
        },
        "spec": {
            "selector": {
                "matchLabels": {"app": app_label}
            },
            "action": "DENY",
            "rules": [
                {
                    # Deny everyone EXCEPT the ai-agent service account
                    "from": [
                        {
                            "source": {
                                "notPrincipals": [
                                    f"cluster.local/ns/{namespace}/sa/ai-agent"
                                ]
                            }
                        }
                    ]
                }
            ]
        }
    }

    try:
        crd_api.create_namespaced_custom_object(
            group=ISTIO_GROUP,
            version=ISTIO_VERSION,
            namespace=namespace,
            plural=AUTHZ_PLURAL,
            body=body
        )
        log.info(f"Istio AuthorizationPolicy {policy_name} applied — mTLS traffic blocked")
    except ApiException as e:
        if e.status == 409:
            log.info(f"Istio AuthorizationPolicy {policy_name} already exists")
        elif e.status == 404:
            # Istio CRD not available yet — log warning but don't crash
            log.warning("Istio CRD not found — skipping Istio quarantine (NetworkPolicy only)")
        else:
            log.error(f"Istio AuthorizationPolicy creation failed: {e}")


def _remove_istio_quarantine(pod_name: str, namespace: str):
    """Delete the Istio AuthorizationPolicy for this pod."""
    policy_name = f"istio-quarantine-{pod_name}"
    try:
        crd_api.delete_namespaced_custom_object(
            group=ISTIO_GROUP,
            version=ISTIO_VERSION,
            namespace=namespace,
            plural=AUTHZ_PLURAL,
            name=policy_name
        )
        log.info(f"Istio AuthorizationPolicy {policy_name} deleted")
    except ApiException as e:
        if e.status != 404:
            log.error(f"Failed to delete Istio AuthorizationPolicy: {e}")


# ── Action implementations ────────────────────────────────────────────────────

def _alert_only(decision: dict, analysis: dict):
    pod  = analysis.get("pod")
    ns   = analysis.get("namespace")
    rule = analysis.get("rule")
    score = analysis.get("risk_score")

    log.warning(f"ALERT_ONLY pod={pod} ns={ns} score={score} rule={rule}")

    record = {
        "action": "alert_only",
        "pod": pod,
        "namespace": ns,
        "rule": rule,
        "risk_score": score,
        "reason": decision.get("reason"),
        "command": analysis.get("command"),
        "file": analysis.get("file"),
        "node": analysis.get("node"),
        "downtime_ms": 0,
        "new_pod": None,
        "elapsed_seconds": None,
    }
    _write_audit(record)
    _publish_decision(record)


def _quarantine(decision: dict, analysis: dict):
    """
    Quarantine flow (UPDATED FOR ISTIO):
      1. Label pod  security.status=quarantined
      2. Apply NetworkPolicy (layer 3/4 isolation — works even without sidecar)
      3. Apply Istio AuthorizationPolicy (layer 7 mTLS isolation)
      4. Scale deployment +1 so a clean replacement starts
      5. Wait for replacement
      6. Write audit + publish to Kafka
      Pod is kept alive for forensic investigation.
    """
    pod = analysis.get("pod")
    ns  = analysis.get("namespace")

    if not pod or not ns:
        log.warning("QUARANTINE called but pod/namespace unknown — skipping")
        return

    log.warning(f"QUARANTINE starting pod={pod} ns={ns}")
    t_start = time.time()

    # 1 — Label
    _label_pod(pod, ns, {"security.status": "quarantined"})

    # 2 — NetworkPolicy isolation (L3/L4)
    _apply_network_isolation(pod, ns)

    # 3 — Istio AuthorizationPolicy (L7 mTLS)  ← NEW
    _apply_istio_quarantine(pod, ns)

    # 4 — Scale up for replacement
    owner = _get_owner_deployment(pod, ns)
    if owner:
        dep = apps_api.read_namespaced_deployment(owner, ns)
        current_replicas = dep.spec.replicas or 1
        _scale_deployment(owner, ns, current_replicas + 1)

        # 5 — Wait for clean pod
        if _wait_for_replacement(owner, ns, pod):
            log.info("Clean replacement running — quarantined pod kept for forensics")
        else:
            log.warning("Replacement pod did not become ready in time")

    elapsed = round(time.time() - t_start, 2)

    record = {
        "action": "quarantine_pod",
        "pod": pod,
        "namespace": ns,
        "rule": analysis.get("rule"),
        "risk_score": analysis.get("risk_score"),
        "reason": decision.get("reason"),
        "command": analysis.get("command"),
        "file": analysis.get("file"),
        "node": analysis.get("node"),
        "downtime_ms": 0,
        "new_pod": owner,
        "elapsed_seconds": elapsed,
        "istio_policy": f"istio-quarantine-{pod}",   # NEW field in audit
        "network_policy": f"isolate-{pod}",
    }
    _write_audit(record)
    _publish_decision(record)
    log.warning(
        f"QUARANTINE complete pod={pod} ns={ns} "
        f"— isolated (NetworkPolicy + Istio AuthZ) and kept for forensics"
    )


def _delete_pod_action(decision: dict, analysis: dict):
    """
    Delete flow (UPDATED FOR ISTIO):
      1. Apply NetworkPolicy + Istio isolation first
      2. Scale up replacement
      3. Wait for replacement
      4. Delete compromised pod
      5. Scale back down
      6. Cleanup NetworkPolicy + Istio AuthorizationPolicy
      7. Write audit + publish to Kafka
    """
    pod = analysis.get("pod")
    ns  = analysis.get("namespace")

    if not pod or not ns:
        log.warning("DELETE called but pod/namespace unknown — skipping")
        return

    log.warning(f"DELETE starting pod={pod} ns={ns}")
    t_start = time.time()

    # 1 — Isolate first while we spin up replacement
    _label_pod(pod, ns, {"security.status": "quarantined"})
    _apply_network_isolation(pod, ns)
    _apply_istio_quarantine(pod, ns)  # ← NEW

    # 2 — Scale up
    owner = _get_owner_deployment(pod, ns)
    if owner:
        dep = apps_api.read_namespaced_deployment(owner, ns)
        current_replicas = dep.spec.replicas or 1
        _scale_deployment(owner, ns, current_replicas + 1)
        new_pod_ready = _wait_for_replacement(owner, ns, pod)
    else:
        new_pod_ready = False

    # 3 — Delete compromised pod
    try:
        core_api.delete_namespaced_pod(pod, ns)
        log.info(f"Pod {pod} deleted")
    except ApiException as e:
        log.error(f"Failed to delete pod {pod}: {e}")

    # 4 — Scale back down
    if owner:
        dep = apps_api.read_namespaced_deployment(owner, ns)
        current = dep.spec.replicas or 2
        _scale_deployment(owner, ns, max(1, current - 1))

    # 5 — Cleanup both isolation layers
    _remove_network_isolation(pod, ns)
    _remove_istio_quarantine(pod, ns)  # ← NEW

    elapsed = round(time.time() - t_start, 2)
    downtime_ms = int(elapsed * 1000) if not new_pod_ready else 0

    record = {
        "action": "delete_pod",
        "pod": pod,
        "namespace": ns,
        "rule": analysis.get("rule"),
        "risk_score": analysis.get("risk_score"),
        "reason": decision.get("reason"),
        "command": analysis.get("command"),
        "file": analysis.get("file"),
        "node": analysis.get("node"),
        "downtime_ms": downtime_ms,
        "new_pod": owner,
        "elapsed_seconds": elapsed,
        "istio_policy_cleaned": f"istio-quarantine-{pod}",  # NEW field
        "network_policy_cleaned": f"isolate-{pod}",
    }
    _write_audit(record)
    _publish_decision(record)
    log.warning(f"DELETE complete pod={pod} ns={ns} elapsed={elapsed}s")


# ── Public entry point ────────────────────────────────────────────────────────

def enforce(decision: dict, analysis: dict):
    action = decision.get("action", "alert_only")

    if action == "alert_only":
        _alert_only(decision, analysis)
    elif action == "quarantine_pod":
        _quarantine(decision, analysis)
    elif action == "delete_pod":
        _delete_pod_action(decision, analysis)
    else:
        log.warning(f"Unknown action '{action}' — defaulting to alert_only")
        _alert_only(decision, analysis)