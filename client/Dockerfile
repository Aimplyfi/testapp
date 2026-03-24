FROM python:3.12-slim
WORKDIR /app
RUN pip install requests
COPY client.py .
RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser
USER appuser
CMD ["python", "client.py"]