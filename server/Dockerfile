FROM python:3.12-slim
WORKDIR /app
# Create a non‑root user
RUN adduser --disabled-password --gecos "" appuser
# Copy application code and set ownership
COPY app.py .
RUN chown -R appuser:appuser /app
# Install dependencies as root (required for apt)
RUN pip install flask
# Switch to non‑root user
USER appuser
EXPOSE 5000
CMD ["python", "app.py"]