import os
import time
import signal
import logging
import requests

# -------------------------
# Configuration
# -------------------------

# Server URL must use https now that TLS is enabled
SERVER_URL = os.getenv("SERVER_URL", "https://vuln-server-service/run")
INTERVAL   = int(os.getenv("REQUEST_INTERVAL", "15"))

# Path to the CA certificate mounted from the shared Kubernetes Secret.
# Used to verify the server's TLS certificate.
CA_CERT = os.getenv("CA_CERT_PATH", "/tls/ca.crt")

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

# Verify server certificate against our internal CA.
# Never set verify=False in production.
session.verify = CA_CERT

headers = {
    "Content-Type": "application/json",
    "User-Agent": "secure-client/1.0"
}

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
        response = session.post(
            SERVER_URL,
            json=payload,
            headers=headers,
            timeout=TIMEOUT
        )

        if response.status_code == 200:
            logger.info("Server response: %s", response.json())
        else:
            logger.warning(
                "Server returned status %s",
                response.status_code
            )

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
