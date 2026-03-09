#!/usr/bin/env bash
# test.sh — end-to-end tests for vuln-server (TLS + JWT)
#
# Covers:
#   • TLS verification with internal CA
#   • Health endpoint (no auth)
#   • Valid JWT — successful compute request
#   • No token          → 401
#   • Tampered token    → 401
#   • Invalid operation → 422
#   • Division by zero  → 400
set -euo pipefail

NAMESPACE="testns"
PASS=0
FAIL=0

# ── Helpers ────────────────────────────────────────────────────────────────

green() { printf '\033[32m%s\033[0m\n' "$*"; }
red()   { printf '\033[31m%s\033[0m\n' "$*"; }

check() {
  local label="$1" expected="$2" actual="$3"
  if [ "$actual" = "$expected" ]; then
    green "  PASS  $label (HTTP $actual)"
    PASS=$((PASS + 1))
  else
    red   "  FAIL  $label — expected HTTP $expected, got HTTP $actual"
    FAIL=$((FAIL + 1))
  fi
}

# ── 1. Get LoadBalancer IP ─────────────────────────────────────────────────
echo "==> Resolving LoadBalancer IP..."
LB_IP=$(kubectl get svc vuln-server-service -n "$NAMESPACE" \
  -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
[ -z "$LB_IP" ] && { red "ERROR: No LoadBalancer IP assigned. Is MetalLB configured?"; exit 1; }
echo "    LoadBalancer IP: $LB_IP"

# ── 2. Pull CA cert ────────────────────────────────────────────────────────
echo "==> Extracting CA cert from Secret..."
kubectl get secret vuln-server-tls -n "$NAMESPACE" \
  -o jsonpath='{.data.ca\.crt}' | base64 -d > /tmp/vuln-server-ca.crt
echo "    CA cert written to /tmp/vuln-server-ca.crt"

# Shared curl options — TLS-verified, hostname pinned to LB IP
CURL_OPTS=(
  --cacert /tmp/vuln-server-ca.crt
  --resolve "vuln-server-service:443:$LB_IP"
  --silent
)

# ── 3. Pull JWT secret and mint a valid token ─────────────────────────────
echo "==> Minting JWT..."
JWT_SECRET=$(kubectl get secret vuln-jwt-secret -n "$NAMESPACE" \
  -o jsonpath='{.data.jwt\.secret}' | base64 -d)

TOKEN=$(python3 - <<PYEOF
import jwt, uuid
from datetime import datetime, timezone, timedelta
now = datetime.now(tz=timezone.utc)
print(jwt.encode({
    "iss": "exploit-client",
    "aud": "vuln-server",
    "sub": "curl-test",
    "iat": now,
    "exp": now + timedelta(seconds=30),
    "jti": str(uuid.uuid4()),
}, "$JWT_SECRET", algorithm="HS256"))
PYEOF
)
echo "    Token (first 40 chars): ${TOKEN:0:40}..."

# ── 4. Health check — no auth required ────────────────────────────────────
echo ""
echo "==> GET /health  (no auth — verbose)"
curl -v "${CURL_OPTS[@]}" https://vuln-server-service/health
STATUS=$(curl -o /dev/null -w "%{http_code}" "${CURL_OPTS[@]}" \
  https://vuln-server-service/health)
check "GET /health unauthenticated" "200" "$STATUS"

# ── 5. Valid compute request with JWT ─────────────────────────────────────
echo ""
echo "==> POST /run  add 1+2 with valid JWT (verbose)"
curl -v "${CURL_OPTS[@]}" \
  -X POST https://vuln-server-service/run \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"operation":"add","a":1,"b":2}'
STATUS=$(curl -o /dev/null -w "%{http_code}" "${CURL_OPTS[@]}" \
  -X POST https://vuln-server-service/run \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"operation":"add","a":1,"b":2}')
check "POST /run valid JWT" "200" "$STATUS"

# ── 6. No token → 401 ─────────────────────────────────────────────────────
echo ""
echo "==> POST /run  no token (expect 401)"
STATUS=$(curl -o /dev/null -w "%{http_code}" "${CURL_OPTS[@]}" \
  -X POST https://vuln-server-service/run \
  -H "Content-Type: application/json" \
  -d '{"operation":"add","a":1,"b":2}')
check "POST /run no token" "401" "$STATUS"

# ── 7. Tampered token → 401 ───────────────────────────────────────────────
echo ""
echo "==> POST /run  tampered token (expect 401)"
STATUS=$(curl -o /dev/null -w "%{http_code}" "${CURL_OPTS[@]}" \
  -X POST https://vuln-server-service/run \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${TOKEN}x" \
  -d '{"operation":"add","a":1,"b":2}')
check "POST /run tampered token" "401" "$STATUS"

# ── 8. Invalid operation → 422 ────────────────────────────────────────────
echo ""
echo "==> POST /run  invalid operation (expect 422)"
STATUS=$(curl -o /dev/null -w "%{http_code}" "${CURL_OPTS[@]}" \
  -X POST https://vuln-server-service/run \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"operation":"hack","a":1,"b":2}')
check "POST /run invalid operation" "422" "$STATUS"

# ── 9. Division by zero → 400 ─────────────────────────────────────────────
echo ""
echo "==> POST /run  division by zero (expect 400)"
STATUS=$(curl -o /dev/null -w "%{http_code}" "${CURL_OPTS[@]}" \
  -X POST https://vuln-server-service/run \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"operation":"div","a":1,"b":0}')
check "POST /run division by zero" "400" "$STATUS"

# ── Summary ────────────────────────────────────────────────────────────────
echo ""
echo "──────────────────────────────────"
TOTAL=$((PASS + FAIL))
echo "Results: $PASS/$TOTAL passed"
[ "$FAIL" -eq 0 ] && green "All tests passed ✓" || red "$FAIL test(s) failed ✗"
[ "$FAIL" -eq 0 ]   # exit 1 if any failures, for CI use