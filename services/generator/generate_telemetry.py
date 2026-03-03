import json
import math
import random
import time
from dataclasses import dataclass
from datetime import datetime, timezone

from confluent_kafka import Producer
import os


@dataclass
class ServiceProfile:
    name: str
    base_rps: float
    base_p95_ms: float


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _daily_seasonality(t: float) -> float:
    # Simulating a daily traffic rhythm (peaks mid-day, dips at night).
    # t is seconds since epoch.
    day = 24 * 60 * 60
    phase = (t % day) / day
    return 0.65 + 0.7 * math.sin(2 * math.pi * (phase - 0.25))


def _clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))


def _make_event(profile: ServiceProfile, t: float, incident: str | None) -> dict:
    season = _daily_seasonality(t)

    rps = profile.base_rps * season * random.uniform(0.9, 1.1)
    cpu = _clamp((rps / (profile.base_rps * 1.2)) * 55 + random.uniform(-5, 5), 1, 98)
    mem = _clamp(35 + (cpu * 0.35) + random.uniform(-3, 3), 5, 98)

    # Latency correlates with load, but with noise.
    p95 = profile.base_p95_ms * (1.0 + (rps / (profile.base_rps * 2.0))) * random.uniform(0.9, 1.2)
    p50 = p95 * random.uniform(0.45, 0.7)

    # Error rate stays low normally, bumps with load.
    err = _clamp(0.002 + (cpu / 1000.0) + random.uniform(-0.001, 0.001), 0.0, 0.25)

    # Injecting incidents (ground truth labels).
    if incident == "latency_spike":
        p95 *= random.uniform(2.5, 5.0)
        p50 *= random.uniform(2.0, 3.0)
    elif incident == "error_storm":
        err = _clamp(err + random.uniform(0.05, 0.18), 0.0, 0.9)
    elif incident == "traffic_flood":
        rps *= random.uniform(2.0, 4.0)
        cpu = _clamp(cpu + random.uniform(10, 30), 1, 99)
        p95 *= random.uniform(1.2, 1.8)
    elif incident == "memory_leak":
        mem = _clamp(mem + random.uniform(20, 45), 1, 99)
        p95 *= random.uniform(1.1, 1.4)

    return {
        "ts": _iso_now(),
        "service": profile.name,
        "region": random.choice(["us-east", "us-west"]),
        "rps": round(rps, 2),
        "p50_latency_ms": round(p50, 2),
        "p95_latency_ms": round(p95, 2),
        "error_rate": round(err, 4),
        "cpu_pct": round(cpu, 2),
        "mem_pct": round(mem, 2),
        "incident_label": incident or "none",
    }


def main() -> None:
    broker = os.getenv("KAFKA_BROKER", "localhost:9092")
    topic = "telemetry"

    producer = Producer({"bootstrap.servers": broker})

    services = [
        ServiceProfile("auth", 120, 110),
        ServiceProfile("payments", 65, 180),
        ServiceProfile("search", 220, 95),
        ServiceProfile("checkout", 45, 210),
    ]

    print("Publishing telemetry to", topic, "via", broker)
    print("Press Ctrl+C to stop.")

    incident_mode = True
    incident_every_n_seconds = 45
    incident_duration_seconds = 12

    next_incident_at = time.time() + incident_every_n_seconds
    incident_end_at = 0.0
    active_incident_type: str | None = None
    active_service: str | None = None

    try:
        while True:
            now = time.time()

            if incident_mode and now >= next_incident_at and active_incident_type is None:
                active_incident_type = random.choice(["latency_spike", "error_storm", "traffic_flood", "memory_leak"])
                active_service = random.choice([s.name for s in services])
                incident_end_at = now + incident_duration_seconds
                print(f"[INCIDENT] {active_incident_type} on {active_service} for {incident_duration_seconds}s")

            if active_incident_type is not None and now >= incident_end_at:
                active_incident_type = None
                active_service = None
                next_incident_at = now + incident_every_n_seconds

            for s in services:
                incident = active_incident_type if (s.name == active_service) else None
                event = _make_event(s, now, incident)

                producer.produce(topic, json.dumps(event).encode("utf-8"))
            producer.flush(0)

            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\nStopping generator...")
    finally:
        producer.flush(5)


if __name__ == "__main__":
    main()
