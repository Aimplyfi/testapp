# ---------- Stage 1: Build ----------
FROM python:3.12-slim AS builder

WORKDIR /app

COPY client.py .
RUN pip install --no-cache-dir requests --target /app/site-packages


# ---------- Stage 2: Runtime ----------
FROM gcr.io/distroless/python3

WORKDIR /app

# Copy app + dependencies
COPY --from=builder /app /app

# Run as non-root (distroless already has nonroot user)
USER nonroot

CMD ["client.py"]
