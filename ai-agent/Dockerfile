FROM python:3.10-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd -m -u 1000 agent && chown -R agent:agent /app
USER agent
CMD ["python", "consumer.py"]