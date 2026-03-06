# ---------- Stage 1: Build ----------
FROM python:3.12-slim AS builder

WORKDIR /app

COPY app.py .

RUN pip install --no-cache-dir flask flask-limiter --target /app/site-packages


# ---------- Stage 2: Runtime ----------
FROM gcr.io/distroless/python3

WORKDIR /app

# Copy application + dependencies
COPY --from=builder /app /app

# Add site-packages to Python path
ENV PYTHONPATH=/app/site-packages

USER nonroot

EXPOSE 5000

CMD ["app.py"]