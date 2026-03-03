import json
import os
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Optional


TELEMETRY_PATH = "data/telemetry_dump.jsonl"

OUT_JSON = "results/rule_report.json"
OUT_MD = "results/rule_report.md"

INCIDENT_NONE = "none"
RULE_FLAG = "rule_baseline"

# Conservative but fair thresholds (tune later if needed)
THRESH = {
    "p95_latency_ms": 300.0,
    "error_rate": 0.02,
    "mem_pct": 85.0,
    "rps": 30.0,
}

def _parse_ts(ts_str: str) -> datetime:
    return datetime.fromisoformat(ts_str).astimezone(timezone.utc)

def _load_rpk_dump(path: str) -> List[dict]:
    """
    Parses rpk output that may be multi-line JSON objects and/or JSON-per-line.
    Handles wrapped format: {"topic": "...", "value": "{...json...}"}.
    """
    with open(path, "rb") as f:
        text = f.read().decode("utf-8", errors="ignore")

    decoder = json.JSONDecoder()
    idx = 0
    n = len(text)

    events: List[dict] = []

    def _push_event(obj: dict) -> None:
        if "value" in obj:
            val = obj.get("value")
            if isinstance(val, str):
                try:
                    events.append(json.loads(val))
                except Exception:
                    return
            elif isinstance(val, dict):
                events.append(val)
            return
        if "ts" in obj:
            events.append(obj)

    while idx < n:
        while idx < n and text[idx] not in "{[":
            idx += 1
        if idx >= n:
            break
        try:
            obj, next_idx = decoder.raw_decode(text, idx)
            idx = next_idx
        except Exception:
            idx += 1
            continue
        if isinstance(obj, dict):
            _push_event(obj)

    return events

@dataclass
class IncidentWindow:
    service: str
    label: str
    start: datetime
    end: datetime

def _build_incident_windows(telemetry: List[dict], gap_s: int = 3) -> List[IncidentWindow]:
    by_service = defaultdict(list)
    for e in telemetry:
        if "ts" in e:
            by_service[e.get("service", "unknown")].append(e)

    windows: List[IncidentWindow] = []

    for service, rows in by_service.items():
        rows.sort(key=lambda r: r["ts"])

        cur_label: Optional[str] = None
        cur_start: Optional[datetime] = None
        cur_end: Optional[datetime] = None
        last_ts: Optional[datetime] = None

        for r in rows:
            label = r.get("incident_label", INCIDENT_NONE)
            ts = _parse_ts(r["ts"])

            if label == INCIDENT_NONE:
                if cur_label is not None:
                    windows.append(IncidentWindow(service, cur_label, cur_start, cur_end))
                    cur_label = None
                    cur_start = None
                    cur_end = None
                last_ts = ts
                continue

            if cur_label is None:
                cur_label = label
                cur_start = ts
                cur_end = ts
                last_ts = ts
                continue

            gap = (ts - last_ts).total_seconds() if last_ts else 0.0

            if label != cur_label or gap > gap_s:
                windows.append(IncidentWindow(service, cur_label, cur_start, cur_end))
                cur_label = label
                cur_start = ts
                cur_end = ts
            else:
                cur_end = ts

            last_ts = ts

        if cur_label is not None:
            windows.append(IncidentWindow(service, cur_label, cur_start, cur_end))

    return windows

def _rule_flags(metrics: dict) -> List[str]:
    if not isinstance(metrics, dict):
        return []
    flags = []
    if metrics.get("p95_latency_ms", 0.0) >= THRESH["p95_latency_ms"]:
        flags.append("latency_high")
    if metrics.get("error_rate", 0.0) >= THRESH["error_rate"]:
        flags.append("error_rate_high")
    if metrics.get("mem_pct", 0.0) >= THRESH["mem_pct"]:
        flags.append("mem_high")
    if metrics.get("rps", 0.0) >= THRESH["rps"]:
        flags.append("rps_high")
    return flags

def _first_rule_detection(telemetry: List[dict], window: IncidentWindow) -> Optional[datetime]:
    # Scan telemetry within window and find first point that triggers any rule
    for e in telemetry:
        if e.get("service") != window.service:
            continue
        ts = e.get("ts")
        if not ts:
            continue
        ets = _parse_ts(ts)
        if not (window.start <= ets <= window.end):
            continue

        metrics = {
            "rps": e.get("rps"),
            "p95_latency_ms": e.get("p95_latency_ms"),
            "error_rate": e.get("error_rate"),
            "mem_pct": e.get("mem_pct"),
        }
        flags = _rule_flags(metrics)
        if flags:
            return ets

    return None

def main() -> None:
    os.makedirs("results", exist_ok=True)

    telemetry = _load_rpk_dump(TELEMETRY_PATH)
    telemetry_events = len(telemetry)

    windows = _build_incident_windows(telemetry)

    incidents_total = len(windows)
    detected_incidents = 0
    fn_incidents = 0

    by_type = defaultdict(lambda: {"incidents": 0, "detected_incidents": 0, "delays_s": []})

    # Build per-service telemetry lists for faster scanning
    tel_by_service = defaultdict(list)
    for e in telemetry:
        if "ts" in e:
            tel_by_service[e.get("service", "unknown")].append(e)
    for s in tel_by_service:
        tel_by_service[s].sort(key=lambda r: r["ts"])

    # Incident-level detection + delay
    for w in windows:
        by_type[w.label]["incidents"] += 1

        det_ts = _first_rule_detection(tel_by_service.get(w.service, []), w)
        if det_ts is None:
            fn_incidents += 1
            continue

        detected_incidents += 1
        by_type[w.label]["detected_incidents"] += 1
        by_type[w.label]["delays_s"].append((det_ts - w.start).total_seconds())

    # Event-level TP/FP:
    # - Rule anomaly event if any rule triggers on that telemetry row
    # - TP if that telemetry timestamp is inside any incident window for that service
    win_by_service = defaultdict(list)
    for w in windows:
        win_by_service[w.service].append(w)
    for s in win_by_service:
        win_by_service[s].sort(key=lambda x: x.start)

    def _in_window(service: str, ts: datetime) -> bool:
        for w in win_by_service.get(service, []):
            if w.start <= ts <= w.end:
                return True
        return False

    tp = 0
    fp = 0
    rule_anom_events = 0

    for e in telemetry:
        ts = e.get("ts")
        if not ts:
            continue
        ets = _parse_ts(ts)
        service = e.get("service", "unknown")

        metrics = {
            "rps": e.get("rps"),
            "p95_latency_ms": e.get("p95_latency_ms"),
            "error_rate": e.get("error_rate"),
            "mem_pct": e.get("mem_pct"),
        }
        flags = _rule_flags(metrics)
        if not flags:
            continue

        rule_anom_events += 1
        if _in_window(service, ets):
            tp += 1
        else:
            fp += 1

    precision = (tp / (tp + fp)) if (tp + fp) else 0.0
    recall = (detected_incidents / incidents_total) if incidents_total else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    by_incident_type = {}
    for label, stats in by_type.items():
        delays = stats["delays_s"]
        by_incident_type[label] = {
            "incidents": stats["incidents"],
            "detected_incidents": stats["detected_incidents"],
            "avg_detection_delay_s": (sum(delays) / len(delays)) if delays else None,
            "min_detection_delay_s": min(delays) if delays else None,
            "max_detection_delay_s": max(delays) if delays else None,
        }

    report = {
        "telemetry_events": telemetry_events,
        "rule_anomaly_events": rule_anom_events,
        "incidents_total": incidents_total,
        "detected_incidents": detected_incidents,
        "fn_incidents": fn_incidents,
        "tp_anomalies": tp,
        "fp_anomalies": fp,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "by_incident_type": by_incident_type,
        "rule_flag": RULE_FLAG,
        "thresholds": THRESH,
        "inputs": {"telemetry": TELEMETRY_PATH},
    }

    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    lines = []
    lines.append("# SentinelStream – Rule-Based Baseline Evaluation\n\n")
    lines.append(f"- Input telemetry: `{TELEMETRY_PATH}`\n")
    lines.append(f"- Thresholds: `{THRESH}`\n\n")
    lines.append("## Overall\n")
    lines.append(f"- telemetry_events: **{telemetry_events}**\n")
    lines.append(f"- rule_anomaly_events: **{rule_anom_events}**\n")
    lines.append(f"- incidents_total: **{incidents_total}**\n")
    lines.append(f"- detected_incidents: **{detected_incidents}**\n")
    lines.append(f"- precision: **{precision:.4f}**\n")
    lines.append(f"- recall: **{recall:.4f}**\n")
    lines.append(f"- f1: **{f1:.4f}**\n\n")

    lines.append("## By incident type\n")
    lines.append("| incident_type | incidents | detected | incident_recall | avg_delay_s | min_delay_s | max_delay_s |\n")
    lines.append("|---|---:|---:|---:|---:|---:|---:|\n")
    for itype, s in by_incident_type.items():
        incidents = s["incidents"]
        detected = s["detected_incidents"]
        it_recall = (detected / incidents) if incidents else 0.0
        avgd = s["avg_detection_delay_s"]
        mind = s["min_detection_delay_s"]
        maxd = s["max_detection_delay_s"]
        lines.append(
            f"| {itype} | {incidents} | {detected} | {it_recall:.4f} | "
            f"{(avgd if avgd is not None else 'NA')} | {(mind if mind is not None else 'NA')} | {(maxd if maxd is not None else 'NA')} |\n"
        )

    with open(OUT_MD, "w", encoding="utf-8") as f:
        f.write("".join(lines))

    print("Saved:")
    print(f"  {OUT_JSON}")
    print(f"  {OUT_MD}")
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
