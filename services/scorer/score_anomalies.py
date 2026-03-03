import json
import time
from collections import defaultdict, deque
from dataclasses import dataclass

from confluent_kafka import Consumer, Producer
from prometheus_client import Counter, Gauge, start_http_server
import os


# ----------------------------
# Prometheus metrics
# ----------------------------
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


# ----------------------------
# Rolling statistics helpers
# ----------------------------
@dataclass
class RollingStats:
    window: deque

    def __init__(self, maxlen: int) -> None:
        self.window = deque(maxlen=maxlen)

    def add(self, x: float) -> None:
        self.window.append(float(x))

    def mean(self) -> float:
        if not self.window:
            return 0.0
        return sum(self.window) / len(self.window)

    def std(self) -> float:
        n = len(self.window)
        if n < 2:
            return 0.0
        m = self.mean()
        var = sum((v - m) ** 2 for v in self.window) / (n - 1)
        return var ** 0.5


def _zscore(x: float, mean: float, std: float) -> float:
    if std <= 1e-9:
        return 0.0
    return (x - mean) / std


def main() -> None:
    broker = os.getenv("KAFKA_BROKER", "localhost:9092")
    in_topic = "telemetry"
    out_topic = "anomalies"

    consumer = Consumer(
        {
            "bootstrap.servers": broker,
            "group.id": "sentinelstream-scorer",
            "auto.offset.reset": "latest",
        }
    )
    consumer.subscribe([in_topic])

    producer = Producer({"bootstrap.servers": broker})

    # Per-service rolling windows
    window_size = 60  # last 60 seconds
    stats = defaultdict(
        lambda: {
            "p95": RollingStats(window_size),
            "err": RollingStats(window_size),
            "cpu": RollingStats(window_size),
            "mem": RollingStats(window_size),
            "rps": RollingStats(window_size),
        }
    )

    # Thresholds
    z_threshold = 3.0
    err_abs_threshold = 0.08
    mem_abs_threshold = 85.0

    print(f"Consuming {in_topic}, producing {out_topic} via {broker}")
    print("Press Ctrl+C to stop.")

    # Expose Prometheus metrics
    start_http_server(8000)
    print("Metrics exposed at http://localhost:8000/metrics")

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

            # Metrics: we processed one telemetry event
            TELEMETRY_CONSUMED.inc()
            LAST_EVENT_UNIX_TS.set(time.time())

            service = event.get("service", "unknown")
            p95 = float(event.get("p95_latency_ms", 0.0))
            err = float(event.get("error_rate", 0.0))
            cpu = float(event.get("cpu_pct", 0.0))
            mem = float(event.get("mem_pct", 0.0))
            rps = float(event.get("rps", 0.0))

            s = stats[service]

            # Scoring against history first
            p95_mean, p95_std = s["p95"].mean(), s["p95"].std()
            err_mean, err_std = s["err"].mean(), s["err"].std()
            cpu_mean, cpu_std = s["cpu"].mean(), s["cpu"].std()
            mem_mean, mem_std = s["mem"].mean(), s["mem"].std()
            rps_mean, rps_std = s["rps"].mean(), s["rps"].std()

            flags = []

            # Z-score checks once we have enough history
            if len(s["p95"].window) >= 20:
                if _zscore(p95, p95_mean, p95_std) >= z_threshold:
                    flags.append("p95_latency_zspike")
                if _zscore(err, err_mean, err_std) >= z_threshold:
                    flags.append("error_rate_zspike")
                if _zscore(cpu, cpu_mean, cpu_std) >= z_threshold:
                    flags.append("cpu_zspike")
                if _zscore(mem, mem_mean, mem_std) >= z_threshold:
                    flags.append("mem_zspike")
                if _zscore(rps, rps_mean, rps_std) >= z_threshold:
                    flags.append("rps_zspike")

            # Absolute checks
            if err >= err_abs_threshold:
                flags.append("error_rate_high")
            if mem >= mem_abs_threshold:
                flags.append("mem_high")

            if flags:
                anomaly = {
                    "ts": event.get("ts"),
                    "service": service,
                    "region": event.get("region"),
                    "flags": flags,
                    "metrics": {
                        "rps": rps,
                        "p95_latency_ms": p95,
                        "error_rate": err,
                        "cpu_pct": cpu,
                        "mem_pct": mem,
                    },
                    "baselines": {
                        "p95_mean": round(p95_mean, 3),
                        "p95_std": round(p95_std, 3),
                        "err_mean": round(err_mean, 5),
                        "err_std": round(err_std, 5),
                        "rps_mean": round(rps_mean, 3),
                        "rps_std": round(rps_std, 3),
                    },
                    "incident_label": event.get("incident_label", "none"),
                }

                # Prometheus anomaly metrics
                ANOMALIES_PRODUCED.inc()
                for flg in flags:
                    ANOMALY_FLAGS.labels(flag=flg, service=service).inc()

                producer.produce(out_topic, json.dumps(anomaly).encode("utf-8"))

            producer.flush(0)

            # Update rolling windows after scoring
            s["p95"].add(p95)
            s["err"].add(err)
            s["cpu"].add(cpu)
            s["mem"].add(mem)
            s["rps"].add(rps)

    except KeyboardInterrupt:
        print("\nStopping scorer...")
    finally:
        consumer.close()
        producer.flush(3)


if __name__ == "__main__":
    main()

