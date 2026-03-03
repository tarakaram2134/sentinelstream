import json
import os
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class IncidentWindow:
    service: str
    incident_type: str
    start_ts: datetime
    end_ts: datetime


def _parse_ts(ts: str) -> Optional[datetime]:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None


def _read_jsonl(path: str) -> list[dict]:
    if not os.path.exists(path):
        return []
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                continue
    return rows


def _build_incident_windows(telemetry: list[dict]) -> list[IncidentWindow]:
    """
    Builds incident windows from telemetry by tracking incident_label transitions per service.
    """
    by_service = defaultdict(list)
    for e in telemetry:
        s = e.get("service")
        ts = _parse_ts(e.get("ts", ""))
        label = e.get("incident_label", "none")
        if not s or ts is None:
            continue
        by_service[s].append((ts, label))

    windows: list[IncidentWindow] = []

    for service, points in by_service.items():
        points.sort(key=lambda x: x[0])

        active_type = None
        active_start = None

        for ts, label in points:
            if active_type is None:
                if label != "none":
                    active_type = label
                    active_start = ts
                continue

            # We are in an incident
            if label == active_type:
                continue

            # Incident ended or changed
            if active_start is not None:
                windows.append(
                    IncidentWindow(
                        service=service,
                        incident_type=active_type,
                        start_ts=active_start,
                        end_ts=ts,
                    )
                )

            if label != "none":
                active_type = label
                active_start = ts
            else:
                active_type = None
                active_start = None

        # Close incident at last timestamp if still active
        if active_type is not None and active_start is not None:
            end_ts = points[-1][0]
            windows.append(
                IncidentWindow(
                    service=service,
                    incident_type=active_type,
                    start_ts=active_start,
                    end_ts=end_ts,
                )
            )

    return windows


def _anomaly_is_tp(anom: dict) -> bool:
    # Our scorer passes incident_label through.
    # So for v1 evaluation: TP if incident_label != none, else FP.
    return anom.get("incident_label", "none") != "none"


def _match_first_detection(anomalies: list[dict], window: IncidentWindow) -> Optional[datetime]:
    """
    Returns the timestamp of the first anomaly for the same service
    that occurs within the incident window.
    """
    for a in anomalies:
        if a.get("service") != window.service:
            continue
        ats = _parse_ts(a.get("ts", ""))
        if ats is None:
            continue
        if window.start_ts <= ats <= window.end_ts:
            # We also prefer matching incident types when possible.
            if a.get("incident_label") in (window.incident_type, "none"):
                return ats
    return None


def main() -> None:
    telemetry_path = "data/telemetry.jsonl"
    anomalies_path = "data/anomalies.jsonl"

    telemetry = _read_jsonl(telemetry_path)
    anomalies = _read_jsonl(anomalies_path)

    windows = _build_incident_windows(telemetry)

    tp = sum(1 for a in anomalies if _anomaly_is_tp(a))
    fp = sum(1 for a in anomalies if not _anomaly_is_tp(a))

    # Recall is incident-based: did we detect each incident at least once?
    detected = 0
    delays_by_type = defaultdict(list)
    windows_by_type = defaultdict(int)

    # Sort anomalies by time for stable matching
    anomalies_sorted = sorted(
        anomalies,
        key=lambda x: _parse_ts(x.get("ts", "")) or datetime.min,
    )

    for w in windows:
        windows_by_type[w.incident_type] += 1
        first = _match_first_detection(anomalies_sorted, w)
        if first is not None:
            detected += 1
            delay_sec = (first - w.start_ts).total_seconds()
            delays_by_type[w.incident_type].append(delay_sec)

    fn = max(len(windows) - detected, 0)

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = detected / len(windows) if windows else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    per_type = {}
    for t, count in windows_by_type.items():
        delays = delays_by_type.get(t, [])
        per_type[t] = {
            "incidents": count,
            "detected_incidents": len(delays),
            "avg_detection_delay_s": round(sum(delays) / len(delays), 3) if delays else None,
            "min_detection_delay_s": round(min(delays), 3) if delays else None,
            "max_detection_delay_s": round(max(delays), 3) if delays else None,
        }

    report = {
        "telemetry_events": len(telemetry),
        "anomaly_events": len(anomalies),
        "incidents_total": len(windows),
        "tp_anomalies": tp,
        "fp_anomalies": fp,
        "fn_incidents": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "by_incident_type": per_type,
    }

    os.makedirs("results", exist_ok=True)
    with open("results/report.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    # Also write a simple markdown report for GitHub.
    lines = []
    lines.append("# SentinelStream Evaluation Report")
    lines.append("")
    lines.append(f"- Telemetry events: **{len(telemetry)}**")
    lines.append(f"- Anomaly events: **{len(anomalies)}**")
    lines.append(f"- Incidents: **{len(windows)}**")
    lines.append("")
    lines.append("## Overall")
    lines.append(f"- Precision: **{report['precision']}**")
    lines.append(f"- Recall (incident-level): **{report['recall']}**")
    lines.append(f"- F1: **{report['f1']}**")
    lines.append("")
    lines.append("## By incident type")
    for t, stats in per_type.items():
        lines.append(f"### {t}")
        lines.append(f"- Incidents: {stats['incidents']}")
        lines.append(f"- Detected incidents: {stats['detected_incidents']}")
        lines.append(f"- Avg detection delay (s): {stats['avg_detection_delay_s']}")
        lines.append("")

    with open("results/report.md", "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print("Saved:")
    print("  results/report.json")
    print("  results/report.md")
    print("")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
