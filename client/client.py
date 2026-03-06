import os
import time
import signal
import logging
import requests

# -------------------------
# Configuration
# -------------------------

SERVER_URL = os.getenv("SERVER_URL", "http://vuln-server-service/run")
INTERVAL = int(os.getenv("REQUEST_INTERVAL", "15"))

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
# HTTP Session
# -------------------------

session = requests.Session()

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

    except requests.exceptions.Timeout:
        logger.warning("Request timed out")

    except requests.exceptions.ConnectionError:
        logger.warning("Connection error")

    except Exception:
        logger.exception("Unexpected error")

    time.sleep(INTERVAL)

logger.info("Client shutting down")