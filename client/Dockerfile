FROM python:3.12-slim
WORKDIR /app
RUN pip install requests
COPY client.py .
RUN useradd -m appuser && chown -R appuser:appuser /app
USER appuser
CMD ["python", "client.py"]