FROM python:3.12-slim
WORKDIR /app
RUN pip install flask
COPY app.py .
EXPOSE 5000
RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser
USER appuser
CMD ["python", "app.py"]