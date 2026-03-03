import json
import time
from collections import defaultdict, deque

import numpy as np
from confluent_kafka import Consumer, Producer
from joblib import dump, load
from prometheus_client import Counter, Gauge, start_http_server
from sklearn.ensemble import IsolationForest
import os


TELEMETRY_CONSUMED = Counter(
    "telemetry_events_consumed_total",
    "Telemetry events consumed by the scorer",
)
ANOMALIES_PRODUCED = Counter(
    "anomaly_events_produced_total",
    "Anomaly events produced by the scorer",
)
ANOMALY_FLAGS = Counter(
    "anomaly_flags_total",
    "Anomaly flags emitted",
    ["flag", "service"],
)
LAST_EVENT_UNIX_TS = Gauge(
    "last_event_unix_ts",
    "Unix timestamp of last telemetry event processed",
)

MODEL_READY = Gauge(
    "ml_model_ready",
    "Whether the ML model is trained and ready (1=yes, 0=no)",
    ["service"],
)
ANOMALY_SCORE = Gauge(
    "ml_anomaly_score",
    "IsolationForest anomaly score (higher means more anomalous after normalization)",
    ["service"],
)


def _to_features(event: dict) -> np.ndarray:
    # Keeping it small and stable.
    # We are using the same fields we already track.
    rps = float(event.get("rps", 0.0))
    p95 = float(event.get("p95_latency_ms", 0.0))
    err = float(event.get("error_rate", 0.0))
    cpu = float(event.get("cpu_pct", 0.0))
    mem = float(event.get("mem_pct", 0.0))
    return np.array([rps, p95, err, cpu, mem], dtype=np.float32)


def _model_path(service: str) -> str:
    safe = service.replace("/", "_")
    return f"models/iforest_{safe}.joblib"


def _train_iforest(x: np.ndarray) -> IsolationForest:
    # contamination is the expected outlier fraction.
    # We keep it conservative so it doesn't scream all day.
    model = IsolationForest(
    n_estimators=300,
    contamination=0.06,
    random_state=42,
    )
    model.fit(x)
    return model


def main() -> None:
    broker = os.getenv("KAFKA_BROKER", "localhost:9092")
    in_topic = "telemetry"
    out_topic = "anomalies"

    consumer = Consumer(
        {
            "bootstrap.servers": broker,
            "group.id": "sentinelstream-ml-scorer",
            "auto.offset.reset": "latest",
        }
    )
    consumer.subscribe([in_topic])

    producer = Producer({"bootstrap.servers": broker})

    # Training setup
    warmup_events = 200
    retrain_every = 300
    max_buffer = 1500            # per service

    feature_buffers = defaultdict(lambda: deque(maxlen=max_buffer))
    event_counts = defaultdict(int)

    models = {}
    score_threshold = 0.52 # 0..1 after we normalize; tune later

    # Metrics server
    start_http_server(8000, addr="0.0.0.0")
    print(f"Consuming {in_topic}, producing {out_topic} via {broker}")
    print("Press Ctrl+C to stop.")
    print("Metrics exposed at http://localhost:8000/metrics")

    # Ensure models dir exists

    os.makedirs("models", exist_ok=True)

    try:
        while True:
            msg = consumer.poll(1.0)
            if msg is None:
                continue
            if msg.error():
                print("Consumer error:", msg.error())
                continue

            try:
                event = json.loads(msg.value().decode("utf-8"))
            except Exception:
                continue

            TELEMETRY_CONSUMED.inc()
            LAST_EVENT_UNIX_TS.set(time.time())

            service = event.get("service", "unknown")
            x = _to_features(event)

            # We are buffering features for training/retraining.
            feature_buffers[service].append(x)
            event_counts[service] += 1

            # Train or retrain
            if service not in models:
                MODEL_READY.labels(service=service).set(0)

                if len(feature_buffers[service]) >= warmup_events:
                    train_x = np.stack(feature_buffers[service], axis=0)
                    model = _train_iforest(train_x)
                    models[service] = model
                    dump(model, _model_path(service))
                    MODEL_READY.labels(service=service).set(1)

            else:
                # periodic retrain to adapt to shifts
                if event_counts[service] % retrain_every == 0 and len(feature_buffers[service]) >= warmup_events:
                    train_x = np.stack(feature_buffers[service], axis=0)
                    model = _train_iforest(train_x)
                    models[service] = model
                    dump(model, _model_path(service))
                    MODEL_READY.labels(service=service).set(1)

            # If model isn't ready, we don't emit ML anomalies yet.
            if service not in models:
                continue

            model = models[service]

            # IsolationForest returns higher = more normal. We flip and normalize.
            # decision_function is roughly centered; we only need a consistent monotonic score.
            raw = float(model.decision_function(x.reshape(1, -1))[0])
            # Normalize to 0..1-ish using a squashing function.
            score = 1.0 / (1.0 + np.exp(raw))  # higher => more anomalous
            ANOMALY_SCORE.labels(service=service).set(float(score))

            flags = []
            if score >= score_threshold:
                flags.append("ml_iforest_anomaly")

            if not flags:
                continue

            anomaly = {
                "ts": event.get("ts"),
                "service": service,
                "region": event.get("region"),
                "flags": flags,
                "metrics": {
                    "rps": float(event.get("rps", 0.0)),
                    "p95_latency_ms": float(event.get("p95_latency_ms", 0.0)),
                    "error_rate": float(event.get("error_rate", 0.0)),
                    "cpu_pct": float(event.get("cpu_pct", 0.0)),
                    "mem_pct": float(event.get("mem_pct", 0.0)),
                },
                "ml": {
                    "model": "IsolationForest",
                    "score": round(float(score), 4),
                    "threshold": score_threshold,
                    "warmup_events": warmup_events,
                    "retrain_every": retrain_every,
                },
                "incident_label": event.get("incident_label", "none"),
            }

            ANOMALIES_PRODUCED.inc()
            for flg in flags:
                ANOMALY_FLAGS.labels(flag=flg, service=service).inc()

            producer.produce(out_topic, json.dumps(anomaly).encode("utf-8"))
            producer.flush(0)

    except KeyboardInterrupt:
        print("\nStopping ML scorer...")
    finally:
        consumer.close()
        producer.flush(3)


if __name__ == "__main__":
    main()
