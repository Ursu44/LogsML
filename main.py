from kafka import KafkaConsumer

consumer = KafkaConsumer(
    "logs_normalized",
    bootstrap_servers="kafka:9092",
    auto_offset_reset="earliest",
    group_id=None,
)

print("Connected to Kafka")

for msg in consumer:
    print("Connected to Kafka")
    print(msg.value)
    # raw_msg = msg.value.decode(errors="ignore")
    # try:
    #     payload = json.loads(raw_msg)
    #     log = payload.get("log", raw_msg)
    # except json.JSONDecodeError:
    #     log = raw_msg
