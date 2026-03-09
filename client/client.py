import os
import time
import signal
import logging
import uuid
from datetime import datetime, timezone, timedelta

import jwt
import requests

# -------------------------
# Configuration
# -------------------------

# Server URL must use https now that TLS is enabled
SERVER_URL = os.getenv("SERVER_URL", "https://vuln-server-service/run")
INTERVAL   = int(os.getenv("REQUEST_INTERVAL", "15"))
CA_CERT    = os.getenv("CA_CERT_PATH", "/tls/ca.crt")

# JWT settings — must match server exactly
_JWT_SECRET_PATH = os.getenv("JWT_SECRET_PATH", "/jwt/jwt.secret")
_JWT_ALGORITHM   = "HS256"
JWT_ISSUER       = "exploit-client"
JWT_AUDIENCE     = "vuln-server"
JWT_TTL_SEC      = 30   # token valid for 30 s — short-lived by design

TIMEOUT = (3, 5)  # connect, read timeout

# -------------------------
# Logging
# -------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

logger = logging.getLogger(__name__)

# -------------------------
# Load JWT secret
# -------------------------

def _load_jwt_secret() -> str:
    try:
        return open(_JWT_SECRET_PATH).read().strip()
    except OSError as exc:
        raise RuntimeError(
            f"Cannot read JWT secret from {_JWT_SECRET_PATH}: {exc}"
        ) from exc

JWT_SECRET: str = _load_jwt_secret()

# -------------------------
# Token factory
# A fresh token is minted for every request so each one has its own
# jti (JWT ID) and a tight exp window. Reusing tokens is avoided because
# a captured token would be replayable until it expires.
# -------------------------

def mint_token() -> str:
    now = datetime.now(tz=timezone.utc)
    payload = {
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "sub": "exploit-client",
        "iat": now,
        "exp": now + timedelta(seconds=JWT_TTL_SEC),
        "jti": str(uuid.uuid4()),   # unique per request — prevents replay
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=_JWT_ALGORITHM)

# -------------------------
# Graceful shutdown
# -------------------------

running = True

def shutdown_handler(signum, frame):
    global running
    logger.info("Shutdown signal received")
    running = False

signal.signal(signal.SIGTERM, shutdown_handler)
signal.signal(signal.SIGINT, shutdown_handler)

# -------------------------
# HTTP Session — TLS-verified
# -------------------------

session = requests.Session()
session.verify = CA_CERT  # never set to False in production

payload = {
    "operation": "add",
    "a": 1,
    "b": 2
}

# -------------------------
# Main loop
# -------------------------

while running:
    try:
        token = mint_token()

        headers = {
            "Content-Type": "application/json",
            "User-Agent": "secure-client/1.0",
            "Authorization": f"Bearer {token}",
        }

        response = session.post(
            SERVER_URL,
            json=payload,
            headers=headers,
            timeout=TIMEOUT,
        )

        if response.status_code == 200:
            logger.info("Server response: %s", response.json())
        elif response.status_code == 401:
            logger.error("Authentication failed (401): %s", response.text)
        elif response.status_code == 403:
            logger.error("Authorization failed (403): %s", response.text)
        else:
            logger.warning("Server returned status %s", response.status_code)

    except requests.exceptions.SSLError:
        logger.error("TLS verification failed — check CA cert or server certificate")

    except requests.exceptions.Timeout:
        logger.warning("Request timed out")

    except requests.exceptions.ConnectionError:
        logger.warning("Connection error")

    except Exception:
        logger.exception("Unexpected error")

    time.sleep(INTERVAL)

logger.info("Client shutting down")
