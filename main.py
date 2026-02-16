from kafka import KafkaConsumer

consumer = KafkaConsumer(
    "logs_normalized",
    bootstrap_servers="kafka:9092",
    auto_offset_reset="earliest",
    group_id=None,
)

for msg in consumer:
    print(msg.value)
    # raw_msg = msg.value.decode(errors="ignore")
    # try:
    #     payload = json.loads(raw_msg)
    #     log = payload.get("log", raw_msg)
    # except json.JSONDecodeError:
    #     log = raw_msg
