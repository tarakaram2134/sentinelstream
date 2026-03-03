SentinelStream

SentinelStream is a lightweight, production-style streaming anomaly detection system built around a Kafka-compatible event pipeline. It simulates real-time service telemetry, detects anomalies using both machine learning and adaptive baselines, and exposes operational metrics through Prometheus and Grafana.

The goal of this project is to demonstrate end-to-end system design — from streaming ingestion to model-based scoring and measurable evaluation — rather than isolated model experimentation.

Overview

The system consists of:

A telemetry generator that produces synthetic service metrics

A Redpanda (Kafka API) broker for streaming transport

An anomaly scoring service (IsolationForest + rule baselines)

Prometheus metrics exported from the scorer

Grafana dashboards for observability

An offline evaluation harness for quantitative comparison

Architecture

Telemetry Generator
→ telemetry topic (Redpanda / Kafka API)
→ Scorer Service
→ anomalies topic
→ Prometheus metrics endpoint
→ Grafana dashboards

Evaluation scripts operate on captured stream dumps to compute precision, recall, F1, and detection latency.

Core Features

Real-time telemetry simulation across multiple services

Kafka-compatible streaming using Redpanda

IsolationForest-based anomaly detection

Static threshold rules

Dynamic (k-sigma) adaptive baseline

Quantile-based baseline

Prometheus metrics integration

Alert rule definitions

Grafana dashboards

Reproducible evaluation framework

Running the System
Requirements

Docker

Docker Compose (v2)

Ports available:

9092 (Redpanda)

8000 (Scorer metrics)

9090 (Prometheus)

3000 (Grafana)

Start all services
docker compose up -d --build

Verify containers:

docker compose ps
Inspect streaming data

List topics:

docker exec -it redpanda rpk topic list

Consume telemetry:

docker exec -it redpanda rpk topic consume telemetry -n 5

Consume anomalies:

docker exec -it redpanda rpk topic consume anomalies -n 5 -f json
Access observability tools

Prometheus:
http://localhost:9090

Grafana:
http://localhost:3000

(Default login: admin / admin)

Metrics endpoint

The scorer exposes Prometheus metrics on:

curl http://localhost:8000/metrics

Example exported metrics:

telemetry_events_consumed_total

anomaly_events_produced_total

anomaly_flags_total{flag,service}

ml_anomaly_score{service}

ml_model_ready

Offline Evaluation

The evaluation harness reads a captured telemetry stream and compares anomaly detection methods.

Activate virtual environment:

source .venv/bin/activate

Run evaluation:

python services/evaluator/evaluate_ml.py
python services/evaluator/evaluate_rules.py
python services/evaluator/evaluate_rules_dynamic.py
python services/evaluator/evaluate_rules_quantile.py
python services/evaluator/compare_reports.py

Generated outputs:

results/ml_report.json

results/rule_report.json

results/rule_dynamic_report.json

results/rule_quantile_report.json

results/comparison.md

Example Evaluation (9,000 Telemetry Events)
Method	Precision	Recall	F1
ML (IsolationForest)	0.86	0.63	0.72
Static Rules	0.05	1.00	0.10
Dynamic Baseline	0.998	1.00	0.999
Quantile Baseline	0.75	1.00	0.86

Observations:

Static rules achieve perfect recall but generate excessive false positives.

ML improves precision but may miss certain incident windows.

Adaptive baselines significantly reduce false positives while maintaining recall, depending on baseline construction.

Full comparison details are available in results/comparison.md.

Repository Structure
services/
  generator/       Telemetry generation
  scorer/          ML + rule scoring logic
  evaluator/       Offline evaluation scripts
  common/          Shared utilities

observability/
  prometheus/      Prometheus configuration and alert rules

results/
  Evaluation outputs

docker-compose.yml
Design Notes

All components run as independent services via Docker Compose.

The system is intentionally framework-light to keep behavior transparent.

Evaluation metrics include both event-level and incident-level detection.

Alert rules are defined explicitly in Prometheus configuration.

The project emphasizes reproducibility and measurable outcomes.
