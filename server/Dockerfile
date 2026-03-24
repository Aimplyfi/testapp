FROM python:3.12-slim
WORKDIR /app
RUN pip install flask
COPY app.py .
# Generate self-signed certificate for TLS
RUN apt-get update && apt-get install -y openssl && \
    openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out cert.pem -subj "/CN=localhost"

EXPOSE 443
CMD ["python", "app.py"]