FROM python:3.12-slim
WORKDIR /app
RUN pip install flask
RUN useradd -m appuser && chown -R appuser:appuser /app
USER appuser  
COPY app.py .
EXPOSE 5000
CMD ["python", "app.py"]