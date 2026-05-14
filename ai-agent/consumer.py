import json
from confluent_kafka import Consumer
from analyzer import analyze_alert
from policy import decide_action

consumer = Consumer({
    "bootstrap.servers": "192.168.28.146:9092",
    "group.id": "ai-detection-agent",
    "auto.offset.reset": "earliest"
})

consumer.subscribe(["falco-alerts"])

print("AI Detection Agent started. Waiting for Falco alerts...")

while True:
    msg = consumer.poll(1.0)
    if msg is None:
        continue
    if msg.error():
        print("Kafka error:", msg.error())
        continue
    try:
        alert = json.loads(msg.value().decode("utf-8"))
        analysis = analyze_alert(alert)
        decision = decide_action(analysis)
        print("ALERT:", analysis)
        print("DECISION:", decision)
    except Exception as e:
        print("Error processing alert:", e)
