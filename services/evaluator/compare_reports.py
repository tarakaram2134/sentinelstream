import json
from pathlib import Path

REPORTS = [
    ("ML (IsolationForest)", "results/ml_report.json"),
    ("Rules (static)", "results/rule_report.json"),
    ("Rules (dynamic baseline)", "results/rule_dynamic_report.json"),
    ("Rules (quantile baseline)", "results/rule_quantile_report.json"),
]

OUT_MD = Path("results/comparison.md")


def _load(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Missing report: {path}")
    return json.loads(p.read_text())


def _f(x, nd=4):
    if x is None:
        return ""
    if isinstance(x, (int, float)):
        return f"{x:.{nd}f}"
    return str(x)


def main() -> None:
    rows = []
    for name, path in REPORTS:
        r = _load(path)
        rows.append(
            {
                "name": name,
                "telemetry_events": r.get("telemetry_events"),
                "anomaly_events": r.get("ml_anomaly_events") or r.get("rule_anomaly_events"),
                "incidents_total": r.get("incidents_total"),
                "detected_incidents": r.get("detected_incidents"),
                "fn_incidents": r.get("fn_incidents"),
                "tp_anomalies": r.get("tp_anomalies"),
                "fp_anomalies": r.get("fp_anomalies"),
                "precision": r.get("precision"),
                "recall": r.get("recall"),
                "f1": r.get("f1"),
            }
        )

    lines = []
    lines.append("# SentinelStream Evaluation Comparison\n")
    lines.append("## Summary\n")
    lines.append("| Method | Telemetry | Anomalies | Incidents | Detected | FN | TP | FP | Precision | Recall | F1 |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|")

    for row in rows:
        lines.append(
            "| {name} | {telemetry_events} | {anomaly_events} | {incidents_total} | {detected_incidents} | {fn_incidents} | {tp_anomalies} | {fp_anomalies} | {precision} | {recall} | {f1} |".format(
                name=row["name"],
                telemetry_events=row["telemetry_events"],
                anomaly_events=row["anomaly_events"],
                incidents_total=row["incidents_total"],
                detected_incidents=row["detected_incidents"],
                fn_incidents=row["fn_incidents"],
                tp_anomalies=row["tp_anomalies"],
                fp_anomalies=row["fp_anomalies"],
                precision=_f(row["precision"], 4),
                recall=_f(row["recall"], 4),
                f1=_f(row["f1"], 4),
            )
        )

    lines.append("\n## Notes\n")
    lines.append("- Static rules typically maximize recall but can generate many false positives.")
    lines.append("- ML can have better precision but may miss some incident windows depending on threshold/warmup.")
    lines.append("- Dynamic/quantile baselines depend heavily on how the baseline is built (watch for label leakage).\n")

    OUT_MD.write_text("\n".join(lines))
    print(f"Saved: {OUT_MD}")


if __name__ == '__main__':
    main()
