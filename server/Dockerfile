FROM python:3.12-slim
WORKDIR /app
RUN pip install flask
COPY app.py .
EXPOSE 443
CMD ["python", "app.py"]