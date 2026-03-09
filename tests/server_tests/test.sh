#!/usr/bin/env bash
# test-curl.sh — tests the vuln-server TLS endpoint from outside the cluster
set -euo pipefail

NAMESPACE="testns"

# ── 1. Get the LoadBalancer IP assigned by MetalLB ─────────────────────────
LB_IP=$(kubectl get svc vuln-server-service -n "$NAMESPACE" \
  -o jsonpath='{.status.loadBalancer.ingress[0].ip}')

if [ -z "$LB_IP" ]; then
  echo "ERROR: No LoadBalancer IP assigned yet. Is MetalLB configured?"
  exit 1
fi
echo "LoadBalancer IP: $LB_IP"

# ── 2. Extract the CA cert from the Secret so curl can verify the cert ─────
kubectl get secret vuln-server-tls -n "$NAMESPACE" \
  -o jsonpath='{.data.ca\.crt}' | base64 -d > /tmp/vuln-server-ca.crt
echo "CA cert written to /tmp/vuln-server-ca.crt"

# ── 3. Health check ────────────────────────────────────────────────────────
echo ""
echo "==> GET /health"
curl -v \
  --cacert /tmp/vuln-server-ca.crt \
  --resolve "vuln-server-service:443:$LB_IP" \
  https://vuln-server-service/health

# ── 4. Valid compute request ───────────────────────────────────────────────
echo ""
echo "==> POST /run  (add 1 + 2)"
curl -v \
  --cacert /tmp/vuln-server-ca.crt \
  --resolve "vuln-server-service:443:$LB_IP" \
  -X POST https://vuln-server-service/run \
  -H "Content-Type: application/json" \
  -d '{"operation":"add","a":1,"b":2}'

# ── 5. Invalid operation (expect 422) ─────────────────────────────────────
echo ""
echo "==> POST /run  (invalid operation — expect 422)"
curl -v \
  --cacert /tmp/vuln-server-ca.crt \
  --resolve "vuln-server-service:443:$LB_IP" \
  -X POST https://vuln-server-service/run \
  -H "Content-Type: application/json" \
  -d '{"operation":"hack","a":1,"b":2}'