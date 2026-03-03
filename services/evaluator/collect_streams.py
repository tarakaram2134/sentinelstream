import json
import os
import time
from datetime import datetime, timezone

from confluent_kafka import Consumer


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _make_consumer(broker: str, group_id: str, topic: str) -> Consumer:
    c = Consumer(
        {
            "bootstrap.servers": broker,
            "group.id": group_id,
            "auto.offset.reset": "latest",
            "enable.auto.commit": True,
        }
    )
    c.subscribe([topic])
    return c


def _append_jsonl(path: str, record: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


def main() -> None:
    broker = "localhost:9092"
    telemetry_topic = "telemetry"
    anomalies_topic = "anomalies"

    duration_seconds = 300  # 5 minutes
    out_dir = "data"
    telemetry_path = os.path.join(out_dir, "telemetry.jsonl")
    anomalies_path = os.path.join(out_dir, "anomalies.jsonl")

    # Starting fresh files each run.
    for p in (telemetry_path, anomalies_path):
        if os.path.exists(p):
            os.remove(p)

    telemetry_consumer = _make_consumer(broker, "collector-telemetry", telemetry_topic)
    anomalies_consumer = _make_consumer(broker, "collector-anomalies", anomalies_topic)

    print(f"Collecting for {duration_seconds}s")
    print(f"  telemetry -> {telemetry_path}")
    print(f"  anomalies -> {anomalies_path}")
    print("Press Ctrl+C to stop early.")

    start = time.time()
    telemetry_count = 0
    anomalies_count = 0

    try:
        while time.time() - start < duration_seconds:
            tmsg = telemetry_consumer.poll(0.2)
            if tmsg is not None and not tmsg.error():
                try:
                    event = json.loads(tmsg.value().decode("utf-8"))
                    # Adding a collector timestamp so we can debug timing if needed.
                    event["_collected_at"] = _utc_now()
                    _append_jsonl(telemetry_path, event)
                    telemetry_count += 1
                except Exception:
                    pass

            amsg = anomalies_consumer.poll(0.2)
            if amsg is not None and not amsg.error():
                try:
                    event = json.loads(amsg.value().decode("utf-8"))
                    event["_collected_at"] = _utc_now()
                    _append_jsonl(anomalies_path, event)
                    anomalies_count += 1
                except Exception:
                    pass

        print(f"Done. telemetry={telemetry_count}, anomalies={anomalies_count}")
    except KeyboardInterrupt:
        print("\nStopped early by user.")
        print(f"Partial counts: telemetry={telemetry_count}, anomalies={anomalies_count}")
    finally:
        telemetry_consumer.close()
        anomalies_consumer.close()


if __name__ == "__main__":
    main()
