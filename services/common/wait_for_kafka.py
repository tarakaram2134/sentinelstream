import os
import socket
import time

host = os.getenv("KAFKA_HOST", "redpanda")
port = int(os.getenv("KAFKA_PORT", "9092"))
timeout_s = int(os.getenv("KAFKA_WAIT_TIMEOUT_S", "60"))

deadline = time.time() + timeout_s
last_err = None

while time.time() < deadline:
    try:
        with socket.create_connection((host, port), timeout=2):
            print(f"Kafka reachable at {host}:{port}")
            raise SystemExit(0)
    except Exception as e:
        last_err = e
        time.sleep(1)

print(f"Kafka NOT reachable at {host}:{port} after {timeout_s}s. Last error: {last_err}")
raise SystemExit(1)
