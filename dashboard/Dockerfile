FROM python:3.11-slim
WORKDIR /app
RUN pip install flask kubernetes confluent-kafka --no-cache-dir
COPY app.py .
COPY dashboard.html .
EXPOSE 5000
CMD ["python", "app.py"]