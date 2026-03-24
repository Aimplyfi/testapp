FROM python:3.12-slim
WORKDIR /app
# Create a non‑root user
RUN adduser --disabled-password --gecos "" appuser
# Install dependencies
RUN pip install requests
# Copy application code and set ownership
COPY client.py .
RUN chown -R appuser:appuser /app
# Switch to non‑root user
USER appuser
CMD ["python", "client.py"]