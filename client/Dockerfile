# ---------- Stage 1: Build ----------
FROM python:3.11-slim AS builder

WORKDIR /app

COPY client.py .

# Install all client dependencies into a local target directory.
# python:3.11 matches the distroless python3 runtime (also 3.11).
RUN pip install --no-cache-dir \
      requests==2.32.3 \
      PyJWT==2.9.0 \
    --target /app/site-packages

# ---------- Stage 2: Runtime ----------
FROM gcr.io/distroless/python3

WORKDIR /app

# Copy app + dependencies from builder
COPY --from=builder /app /app

# Add site-packages to Python path
ENV PYTHONPATH=/app/site-packages

# Run as non-root (distroless nonroot = UID 65532)
USER nonroot

CMD ["client.py"]