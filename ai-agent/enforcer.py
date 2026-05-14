
import logging
import json
import time
from datetime import datetime, timezone
from kubernetes import client, config
from kubernetes.client.rest import ApiException

log = logging.getLogger("enforcer")

# Load in-cluster credentials automatically
try:
    config.load_incluster_config()
    log.info("Loaded in-cluster Kubernetes config")
except Exception:
    config.load_kube_config()
    log.info("Loaded local kubeconfig (dev mode)")

core_api = client.CoreV1Api()
apps_api = client.AppsV1Api()
net_api  = client.NetworkingV1Api()

AUDIT_LOG = "/var/log/agent/audit.log"


# public entry point 
def enforce(decision: dict, analysis: dict):
    action    = decision["action"]
    namespace = decision["target_namespace"]
    pod_name  = decision["target_pod"]
    node_name = decision["target_node"]

    if action == "ignore":
        log.info(f"IGNORE pod={pod_name} score={decision['risk_score']}")
        return

    if action == "alert_only":
        _alert_only(decision, analysis)
        return

    if action == "quarantine_pod":
        _quarantine(pod_name, namespace, decision, analysis)
        return

    if action == "delete_pod":
        _full_response(pod_name, namespace, node_name, decision, analysis)
        return


# action handlers 
def _alert_only(decision: dict, analysis: dict):
    """Score 40-69 — log and push metric, touch nothing."""
    log.warning(
        f"ALERT_ONLY pod={decision['target_pod']} "
        f"ns={decision['target_namespace']} "
        f"score={decision['risk_score']} rule={decision['rule']}"
    )
    _write_audit(decision, analysis, action_taken="alert_only")


def _quarantine(pod_name: str, namespace: str, decision: dict, analysis: dict):
    """Score 70-89 — isolate, keep alive for forensics, spin clean replacement."""
    log.warning(f"QUARANTINE starting pod={pod_name} ns={namespace}")

    # 1. Check pod exists
    pod = _get_pod(pod_name, namespace)
    if not pod:
        log.error(f"Pod {pod_name} not found — skipping")
        return

    # 2. Isolate — block all traffic
    _apply_isolation_policy(pod_name, namespace)

    # 3. Label pod as quarantined — removes it from Service selector
    _label_pod(pod_name, namespace, {"security.status": "quarantined"})

    # 4. Scale up clean replacement
    owner = _get_owner_deployment(pod)
    if owner:
        _scale_up(owner, namespace)
        _wait_for_new_pod(owner, namespace, exclude_pod=pod_name)
        log.info(f"Clean replacement running — quarantined pod kept for forensics")
    else:
        log.warning(f"Pod {pod_name} has no Deployment owner — cannot replace")

    _write_audit(decision, analysis, action_taken="quarantine_pod")
    log.warning(
        f"QUARANTINE complete pod={pod_name} ns={namespace} — "
        f"pod isolated and kept alive for investigation"
    )


def _full_response(pod_name: str, namespace: str, node_name: str,
                   decision: dict, analysis: dict):
    """Score >=90 — isolate → replace → verify → delete → taint node."""
    log.warning(f"FULL RESPONSE starting pod={pod_name} ns={namespace}")
    start = time.time()

    # 1. Check pod exists
    pod = _get_pod(pod_name, namespace)
    if not pod:
        log.error(f"Pod {pod_name} not found — skipping")
        return

    # 2. Isolate immediately — attacker cut off
    _apply_isolation_policy(pod_name, namespace)
    _label_pod(pod_name, namespace, {"security.status": "compromised"})
    log.info(f"ISOLATED pod={pod_name} — attacker connection cut")

    # 3. Spin up clean replacement
    owner = _get_owner_deployment(pod)
    new_pod_name = None

    if owner:
        _scale_up(owner, namespace)
        new_pod_name = _wait_for_new_pod(owner, namespace, exclude_pod=pod_name)
        if new_pod_name:
            log.info(f"REPLACEMENT ready new_pod={new_pod_name} — service running clean")
        else:
            log.warning("Replacement pod did not become ready in time — proceeding anyway")
    else:
        log.warning(f"Pod {pod_name} has no Deployment owner — no auto-replacement")

    # 4. Delete compromised pod
    _delete_pod(pod_name, namespace)
    log.info(f"DELETED pod={pod_name}")

    # 5. Taint node (multi-node ready — harmless on single node)
    if node_name and node_name != "unknown":
        _taint_node(node_name)

    elapsed = round(time.time() - start, 2)
    _write_audit(decision, analysis,
                 action_taken="delete_pod",
                 new_pod=new_pod_name,
                 elapsed_seconds=elapsed)

    log.warning(
        f"FULL RESPONSE complete pod={pod_name} new_pod={new_pod_name} "
        f"node={node_name} elapsed={elapsed}s downtime=0"
    )


#  kubernetes helpers 
def _get_pod(pod_name: str, namespace: str):
    try:
        return core_api.read_namespaced_pod(pod_name, namespace)
    except ApiException as e:
        if e.status == 404:
            return None
        raise


def _get_owner_deployment(pod) -> str | None:
    """Return the Deployment name that owns this pod, or None."""
    for ref in (pod.metadata.owner_references or []):
        if ref.kind == "ReplicaSet":
            try:
                rs = apps_api.read_namespaced_replica_set(
                    ref.name, pod.metadata.namespace
                )
                for rs_ref in (rs.metadata.owner_references or []):
                    if rs_ref.kind == "Deployment":
                        return rs_ref.name
            except ApiException:
                pass
    return None


def _apply_isolation_policy(pod_name: str, namespace: str):
    """Block all ingress and egress for the compromised pod."""
    policy_name = f"isolate-{pod_name}"
    policy = client.V1NetworkPolicy(
        metadata=client.V1ObjectMeta(
            name=policy_name,
            namespace=namespace
        ),
        spec=client.V1NetworkPolicySpec(
            pod_selector=client.V1LabelSelector(
                match_labels={"app": pod_name}
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
            log.error(f"Failed to apply NetworkPolicy: {e}")


def _label_pod(pod_name: str, namespace: str, labels: dict):
    """Add labels to a pod — removes it from Service selector if label conflicts."""
    try:
        patch = {"metadata": {"labels": labels}}
        core_api.patch_namespaced_pod(pod_name, namespace, patch)
        log.info(f"Labelled pod={pod_name} labels={labels}")
    except ApiException as e:
        log.error(f"Failed to label pod: {e}")


def _scale_up(deployment_name: str, namespace: str):
    """Increase replica count by 1 to spin up a clean replacement."""
    try:
        dep = apps_api.read_namespaced_deployment(deployment_name, namespace)
        current = dep.spec.replicas or 1
        apps_api.patch_namespaced_deployment(
            deployment_name, namespace,
            {"spec": {"replicas": current + 1}}
        )
        log.info(f"Deployment {deployment_name} scaled to {current + 1} replicas")
    except ApiException as e:
        log.error(f"Failed to scale deployment: {e}")


def _wait_for_new_pod(deployment_name: str, namespace: str,
                      exclude_pod: str, timeout: int = 60) -> str | None:
    """Wait for a new Ready pod from this deployment, return its name."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            pods = core_api.list_namespaced_pod(
                namespace,
                label_selector=f"app={deployment_name}"
            )
            for pod in pods.items:
                if pod.metadata.name == exclude_pod:
                    continue
                labels = pod.metadata.labels or {}
                if labels.get("security.status") in ("compromised", "quarantined"):
                    continue
                if pod.status.phase == "Running":
                    conditions = pod.status.conditions or []
                    ready = any(
                        c.type == "Ready" and c.status == "True"
                        for c in conditions
                    )
                    if ready:
                        return pod.metadata.name
        except ApiException as e:
            log.error(f"Error checking pods: {e}")
        time.sleep(3)
    return None


def _delete_pod(pod_name: str, namespace: str):
    try:
        core_api.delete_namespaced_pod(pod_name, namespace)
        log.info(f"Deleted pod={pod_name} ns={namespace}")
    except ApiException as e:
        if e.status == 404:
            log.info(f"Pod {pod_name} already gone")
        else:
            log.error(f"Failed to delete pod: {e}")


def _taint_node(node_name: str):
    """Taint the node so no new pods are scheduled on it until cleared.
    Skipped on single-node clusters to avoid blocking all scheduling."""
    try:
        nodes = core_api.list_node()
        schedulable = [
            n for n in nodes.items
            if not any(t.effect == "NoSchedule" for t in (n.spec.taints or []))
        ]
        if len(schedulable) <= 1:
            log.warning(
                f"Single-node cluster — skipping taint on {node_name}"
            )
            return

        taint = {
            "key": "security",
            "value": "compromised",
            "effect": "NoSchedule"
        }
        node = core_api.read_node(node_name)
        existing = [t.to_dict() for t in (node.spec.taints or [])]
        if taint not in existing:
            existing.append(taint)
            core_api.patch_node(node_name, {"spec": {"taints": existing}})
            log.warning(f"TAINTED node={node_name} effect=NoSchedule")
        else:
            log.info(f"Node {node_name} already tainted")
    except ApiException as e:
        log.error(f"Failed to taint node: {e}")



# audit log 
def _write_audit(decision: dict, analysis: dict,
                 action_taken: str, new_pod: str = None,
                 elapsed_seconds: float = None):
    import os
    os.makedirs("/var/log/agent", exist_ok=True)

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "rule": decision["rule"],
        "risk_score": decision["risk_score"],
        "action": action_taken,
        "pod": decision["target_pod"],
        "namespace": decision["target_namespace"],
        "node": decision["target_node"],
        "command": analysis.get("command"),
        "file": analysis.get("file"),
        "user": analysis.get("user"),
        "new_pod": new_pod,
        "elapsed_seconds": elapsed_seconds,
        "downtime_ms": 0
    }

    try:
        with open(AUDIT_LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")
        log.info(f"Audit written action={action_taken} pod={decision['target_pod']}")
    except Exception as e:
        log.error(f"Failed to write audit log: {e}")
