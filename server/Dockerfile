# syntax=docker/dockerfile:1

# =============================================================================
# Stage 1 — builder
# Must use the SAME Python minor version as the distroless runtime (3.11),
# otherwise site-packages land under python3.12/ and the interpreter won't
# find them. gcr.io/distroless/python3-debian12 ships CPython 3.11.
# =============================================================================
FROM python:3.11-slim AS builder

WORKDIR /build

COPY requirements.txt .

# Install into /build/install so the exact tree is easy to COPY out.
# --no-compile skips .pyc generation; distroless has no use for them.
RUN pip install --no-cache-dir --no-compile \
        --prefix=/build/install \
        -r requirements.txt

# =============================================================================
# Stage 2 — final (distroless)
# gcr.io/distroless/python3-debian12:nonroot ships:
#   • CPython 3.11 interpreter  (no shell, no apt, no pip, no curl)
#   • UID 65532 "nonroot" user  (matches our K8s securityContext)
# =============================================================================
FROM gcr.io/distroless/python3-debian12:nonroot

WORKDIR /app

# Copy installed packages — paths must match the 3.11 interpreter's search path.
COPY --from=builder /build/install/lib/python3.11/site-packages \
                    /usr/local/lib/python3.11/dist-packages

# Copy uvicorn and other console-script entry points.
COPY --from=builder /build/install/bin /usr/local/bin

# Application code
COPY app.py .

# UID 65532 is the built-in "nonroot" user in distroless — no USER instruction
# needed, but stating it explicitly documents intent and satisfies scanners.
USER nonroot

EXPOSE 8443

# Distroless has no shell, so ENTRYPOINT must be exec-form (JSON array).
# TLS flags (--ssl-keyfile / --ssl-certfile) are supplied by server.yaml
# command: to keep the image cert-path-agnostic.
ENTRYPOINT ["python3", "-m", "uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8443"]
