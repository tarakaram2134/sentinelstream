---

# SentinelStream

SentinelStream is a lightweight, production‑oriented streaming anomaly detection system built around a Kafka‑compatible event pipeline. It simulates real‑time service telemetry, applies multiple anomaly‑detection strategies, and exposes operational metrics through Prometheus and Grafana. The project is designed to demonstrate end‑to‑end system behavior from ingestion to scoring to evaluation rather than isolated model experimentation.

---

## Overview

The system includes the following components:

- A telemetry generator that produces synthetic service metrics  
- A Redpanda broker (Kafka API) for streaming transport  
- An anomaly‑scoring service combining IsolationForest with rule‑based baselines  
- Prometheus metrics exported from the scoring service  
- Grafana dashboards for visualization  
- An offline evaluation harness for quantitative comparison of detection methods  

---

## Architecture

```
Telemetry Generator
    → telemetry topic (Redpanda / Kafka API)
    → Scorer Service
    → anomalies topic
    → Prometheus metrics endpoint
    → Grafana dashboards
```

Evaluation scripts operate on captured stream dumps to compute precision, recall, F1, and detection latency.

---

## Core Features

- Real‑time telemetry simulation across multiple synthetic services  
- Kafka‑compatible streaming using Redpanda  
- IsolationForest‑based anomaly detection  
- Static threshold rules  
- Dynamic k‑sigma adaptive baseline  
- Quantile‑based baseline  
- Prometheus metrics integration  
- Alert rule definitions  
- Grafana dashboards  
- Reproducible offline evaluation framework  

---

## Running the System

### Requirements

- Docker  
- Docker Compose (v2)  
- Available ports:
  - 9092 (Redpanda)
  - 8000 (Scorer metrics)
  - 9090 (Prometheus)
  - 3000 (Grafana)

### Start all services

```bash
docker compose up -d --build
```

Check container status:

```bash
docker compose ps
```

---

## Inspecting Streaming Data

### List topics

```bash
docker exec -it redpanda rpk topic list
```

### Consume telemetry

```bash
docker exec -it redpanda rpk topic consume telemetry -n 5
```

### Consume anomalies

```bash
docker exec -it redpanda rpk topic consume anomalies -n 5 -f json
```

---

## Observability

### Prometheus  
http://localhost:9090

### Grafana  
http://localhost:3000  
Default login: `admin / admin`

### Metrics endpoint

```bash
curl http://localhost:8000/metrics
```

Example exported metrics:

- `telemetry_events_consumed_total`  
- `anomaly_events_produced_total`  
- `anomaly_flags_total{flag,service}`  
- `ml_anomaly_score{service}`  
- `ml_model_ready`  

---

## Offline Evaluation

The evaluation harness processes captured telemetry streams and compares anomaly‑detection methods.

Activate the virtual environment:

```bash
source .venv/bin/activate
```

Run evaluation scripts:

```bash
python services/evaluator/evaluate_ml.py
python services/evaluator/evaluate_rules.py
python services/evaluator/evaluate_rules_dynamic.py
python services/evaluator/evaluate_rules_quantile.py
python services/evaluator/compare_reports.py
```

Generated outputs:

```
results/ml_report.json
results/rule_report.json
results/rule_dynamic_report.json
results/rule_quantile_report.json
results/comparison.md
```

---

## Example Evaluation (9,000 Telemetry Events)

| Method            | Precision | Recall | F1    |
|-------------------|-----------|--------|-------|
| IsolationForest   | 0.86      | 0.63   | 0.72  |
| Static Rules      | 0.05      | 1.00   | 0.10  |
| Dynamic Baseline  | 0.998     | 1.00   | 0.999 |
| Quantile Baseline | 0.75      | 1.00   | 0.86  |

**Notes**

- Static rules achieve perfect recall but generate many false positives.  
- ML improves precision but may miss short incident windows.  
- Adaptive baselines significantly reduce false positives while maintaining recall.  

Full comparison details are available in `results/comparison.md`.

---

## Repository Structure

```
services/
  generator/        Telemetry generation
  scorer/           ML + rule-based scoring logic
  evaluator/        Offline evaluation scripts
  common/           Shared utilities

observability/
  prometheus/       Prometheus configuration and alert rules

results/            Evaluation outputs

docker-compose.yml
```

---

## Design Notes

- All components run as independent services via Docker Compose.  
- The system is intentionally framework‑light to keep behavior transparent.  
- Evaluation includes both event‑level and incident‑level metrics.  
- Prometheus alert rules are defined explicitly.  
- The project emphasizes reproducibility and measurable outcomes.  

---


