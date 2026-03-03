import json
import os
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple


TELEMETRY_PATH = "data/telemetry_dump.jsonl"
ANOMALIES_PATH = "data/anomalies_dump.jsonl"

OUT_JSON = "results/ml_report.json"
OUT_MD = "results/ml_report.md"

ML_FLAG = "ml_iforest_anomaly"
INCIDENT_NONE = "none"


def _parse_ts(ts_str: str) -> datetime:
    # Example: "2026-03-02T22:06:54.115648+00:00"
    return datetime.fromisoformat(ts_str).astimezone(timezone.utc)

def _load_rpk_dump(path: str) -> List[dict]:
    """
    Parses rpk output that may be:
    - pretty-printed multi-line JSON objects (concatenated)
    - and/or JSON-per-line
    - and may contain a UTF BOM / non-utf8 bytes at the start
    """
    import json

    with open(path, "rb") as f:
        text = f.read().decode("utf-8", errors="ignore")

    decoder = json.JSONDecoder()
    idx = 0
    n = len(text)

    events: List[dict] = []

    def _push_event(obj: dict) -> None:
        # Wrapped format: {"topic": "...", "value": "{...json...}"}
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

        # Raw format: {"ts": "...", ...}
        if "ts" in obj:
            events.append(obj)

    while idx < n:
        # Skip until a JSON object begins
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
    """
    We are grouping consecutive telemetry rows with the same non-'none' incident_label.
    If there is a gap bigger than gap_s seconds, we start a new window.
    """
    by_service = defaultdict(list)
    for e in telemetry:
        if "ts" not in e:
            continue
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
                # closing any active window
                if cur_label is not None:
                    windows.append(IncidentWindow(service, cur_label, cur_start, cur_end))
                    cur_label = None
                    cur_start = None
                    cur_end = None
                last_ts = ts
                continue

            # label != none
            if cur_label is None:
                cur_label = label
                cur_start = ts
                cur_end = ts
                last_ts = ts
                continue

            # we have an active window
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


def _find_first_detection(anomalies: List[dict], window: IncidentWindow) -> Optional[datetime]:
    for a in anomalies:
        if a.get("service") != window.service:
            continue
        flags = a.get("flags", [])
        if ML_FLAG not in flags:
            continue
        ts = a.get("ts")
        if not ts:
            continue
        ats = _parse_ts(ts)
        if window.start <= ats <= window.end:
            return ats
    return None


def main() -> None:
    os.makedirs("results", exist_ok=True)

    telemetry = _load_rpk_dump(TELEMETRY_PATH)
    anomalies = _load_rpk_dump(ANOMALIES_PATH)

    windows = _build_incident_windows(telemetry)

    # Incidents -> detection
    incidents_total = len(windows)
    detected_incidents = 0
    fn_incidents = 0

    by_type = defaultdict(lambda: {"incidents": 0, "detected_incidents": 0, "delays_s": []})

    for w in windows:
        by_type[w.label]["incidents"] += 1

        det_ts = _find_first_detection(anomalies, w)
        if det_ts is None:
            fn_incidents += 1
            continue

        detected_incidents += 1
        by_type[w.label]["detected_incidents"] += 1
        delay_s = (det_ts - w.start).total_seconds()
        by_type[w.label]["delays_s"].append(delay_s)

    # Anomalies -> TP/FP (event-level)
    tp = 0
    fp = 0
    ml_anoms = 0

    # Pre-index windows by service for faster matching
    win_by_service = defaultdict(list)
    for w in windows:
        win_by_service[w.service].append(w)

    for service, ws in win_by_service.items():
        ws.sort(key=lambda x: x.start)

    def _is_in_window(service: str, ts: datetime) -> bool:
        for w in win_by_service.get(service, []):
            if w.start <= ts <= w.end:
                return True
        return False

    for a in anomalies:
        flags = a.get("flags", [])
        if ML_FLAG not in flags:
            continue
        ml_anoms += 1

        ts = a.get("ts")
        if not ts:
            continue
        ats = _parse_ts(ts)
        service = a.get("service", "unknown")

        if _is_in_window(service, ats):
            tp += 1
        else:
            fp += 1

    precision = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    recall = (detected_incidents / incidents_total) if incidents_total > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    by_incident_type = {}
    for label, d in by_type.items():
        delays = d["delays_s"]
        if delays:
            by_incident_type[label] = {
                "incidents": d["incidents"],
                "detected_incidents": d["detected_incidents"],
                "avg_detection_delay_s": round(sum(delays) / len(delays), 3),
                "min_detection_delay_s": round(min(delays), 3),
                "max_detection_delay_s": round(max(delays), 3),
            }
        else:
            by_incident_type[label] = {
                "incidents": d["incidents"],
                "detected_incidents": d["detected_incidents"],
                "avg_detection_delay_s": None,
                "min_detection_delay_s": None,
                "max_detection_delay_s": None,
            }

    report = {
        "telemetry_events": len(telemetry),
        "ml_anomaly_events": ml_anoms,
        "incidents_total": incidents_total,
        "detected_incidents": detected_incidents,
        "fn_incidents": fn_incidents,
        "tp_anomalies": tp,
        "fp_anomalies": fp,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "by_incident_type": by_incident_type,
        "ml_flag": ML_FLAG,
        "inputs": {
            "telemetry": TELEMETRY_PATH,
            "anomalies": ANOMALIES_PATH,
        },
    }

    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    md_lines = []
    md_lines.append("# SentinelStream – ML Evaluator Report (IsolationForest)\n")
    md_lines.append(f"- Telemetry events: **{report['telemetry_events']}**\n")
    md_lines.append(f"- ML anomaly events: **{report['ml_anomaly_events']}** (flag: `{ML_FLAG}`)\n")
    md_lines.append(f"- Incidents total: **{report['incidents_total']}**\n")
    md_lines.append(f"- Detected incidents: **{report['detected_incidents']}**\n")
    md_lines.append(f"- Precision: **{report['precision']}**\n")
    md_lines.append(f"- Recall: **{report['recall']}**\n")
    md_lines.append(f"- F1: **{report['f1']}**\n\n")

    md_lines.append("## By incident type\n\n")
    md_lines.append("| Incident | Incidents | Detected | Avg delay (s) | Min | Max |\n")
    md_lines.append("|---|---:|---:|---:|---:|---:|\n")
    for label, d in by_incident_type.items():
        md_lines.append(
            f"| {label} | {d['incidents']} | {d['detected_incidents']} | "
            f"{d['avg_detection_delay_s'] if d['avg_detection_delay_s'] is not None else '-'} | "
            f"{d['min_detection_delay_s'] if d['min_detection_delay_s'] is not None else '-'} | "
            f"{d['max_detection_delay_s'] if d['max_detection_delay_s'] is not None else '-'} |\n"
        )

    with open(OUT_MD, "w", encoding="utf-8") as f:
        f.writelines(md_lines)

    print("Saved:")
    print(f"  {OUT_JSON}")
    print(f"  {OUT_MD}")
    print()
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
