#!/bin/bash

# --- CONFIGURATION ---
REPO_URL="https://github.com/samugit83/redamon.git"
# Replace with your actual key or export it before running
AI_API_KEY=""
TARGET_NAMESPACE="testns"
TARGET_SERVICE_NAME="vuln-server-service"

mkdir -p staging
cd staging

echo "[+] Cloning RedAmon..."
git clone $REPO_URL
cd redamon

echo "[+] Configuring environment..."
cp .env.example .env
sed -i "s/ANTHROPIC_API_KEY=.*/ANTHROPIC_API_KEY=$AI_API_KEY/" .env

echo "[+] Starting RedAmon services (this may take a few minutes)..."
# Using the profile 'tools' includes vulnerability scanners like GVM/Nuclei
docker compose --profile tools up -d

echo "[+] Fetching K8s target information..."
# This assumes your service is a NodePort or LoadBalancer
TARGET_IP=$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
echo "TARGET_IP ${TARGET_IP}"
TARGET_PORT=$(kubectl get svc $TARGET_SERVICE_NAME -n $TARGET_NAMESPACE -o jsonpath='{.spec.ports[0].nodePort}')
echo "TARGET_PORT ${TARGET_PORT}"

if [ -z "$TARGET_PORT" ]; then
    echo "[!] Could not find NodePort for $TARGET_SERVICE_NAME. Checking for LoadBalancer IP..."
    TARGET_IP=$(kubectl get svc $TARGET_SERVICE_NAME -n $TARGET_NAMESPACE -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
    TARGET_PORT=$(kubectl get svc $TARGET_SERVICE_NAME -n $TARGET_NAMESPACE -o jsonpath='{.spec.ports[0].port}')
fi

echo "--------------------------------------------------------"
echo " REDAMON IS READY"
echo "--------------------------------------------------------"
echo "RedAmon UI: http://localhost:3000"
echo "Your K8s Target: http://$TARGET_IP:$TARGET_PORT"
echo "--------------------------------------------------------"
echo "Step to Test:"
echo "1. Open the UI at http://localhost:3000"
echo "2. Create a new Project."
echo "3. Use 'http://$TARGET_IP:$TARGET_PORT' as the target domain/URL."
echo "4. Click 'Start Recon' to begin the AI-driven attack simulation."