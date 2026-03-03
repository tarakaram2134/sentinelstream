import json
import math
import os
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class DriftResult:
    psi: float
    bins: list[dict]


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


def _safe_float(x) -> Optional[float]:
    try:
        if x is None:
            return None
        return float(x)
    except Exception:
        return None


def _quantile(sorted_vals: list[float], q: float) -> float:
    if not sorted_vals:
        return 0.0
    pos = q * (len(sorted_vals) - 1)
    lo = int(math.floor(pos))
    hi = int(math.ceil(pos))
    if lo == hi:
        return sorted_vals[lo]
    frac = pos - lo
    return sorted_vals[lo] * (1 - frac) + sorted_vals[hi] * frac


def _make_bins_from_baseline(baseline: list[float], num_bins: int = 10) -> list[float]:
    # Using baseline quantiles as bin edges (common PSI approach).
    b = sorted(baseline)
    edges = [_quantile(b, i / num_bins) for i in range(num_bins + 1)]
    # Ensuring edges are strictly increasing by nudging equal edges.
    fixed = [edges[0]]
    eps = 1e-9
    for e in edges[1:]:
        if e <= fixed[-1]:
            e = fixed[-1] + eps
        fixed.append(e)
    return fixed


def _histogram(values: list[float], edges: list[float]) -> list[int]:
    counts = [0] * (len(edges) - 1)
    for v in values:
        # Finding bin index
        idx = None
        for i in range(len(edges) - 1):
            if edges[i] <= v < edges[i + 1]:
                idx = i
                break
        if idx is None:
            # Putting max value into last bin
            idx = len(counts) - 1
        counts[idx] += 1
    return counts


def _psi(baseline_vals: list[float], current_vals: list[float], num_bins: int = 10) -> DriftResult:
    if len(baseline_vals) < 50 or len(current_vals) < 50:
        return DriftResult(psi=0.0, bins=[])

    edges = _make_bins_from_baseline(baseline_vals, num_bins=num_bins)
    b_counts = _histogram(baseline_vals, edges)
    c_counts = _histogram(current_vals, edges)

    b_total = sum(b_counts)
    c_total = sum(c_counts)

    psi_total = 0.0
    bin_details = []

    # Small value to avoid log(0)
    tiny = 1e-6

    for i in range(len(b_counts)):
        b_pct = max(b_counts[i] / b_total, tiny)
        c_pct = max(c_counts[i] / c_total, tiny)

        contrib = (c_pct - b_pct) * math.log(c_pct / b_pct)
        psi_total += contrib

        bin_details.append(
            {
                "bin": i,
                "range": [edges[i], edges[i + 1]],
                "baseline_pct": round(b_pct, 6),
                "current_pct": round(c_pct, 6),
                "contribution": round(contrib, 6),
            }
        )

    return DriftResult(psi=float(psi_total), bins=bin_details)


def _split_baseline_current(events: list[dict], ratio: float = 0.5) -> tuple[list[dict], list[dict]]:
    events_sorted = sorted(
        events,
        key=lambda e: e.get("ts", ""),
    )
    cut = int(len(events_sorted) * ratio)
    return events_sorted[:cut], events_sorted[cut:]


def _severity(psi_value: float) -> str:
    # Common PSI interpretation thresholds (rough guidelines).
    if psi_value < 0.1:
        return "low"
    if psi_value < 0.25:
        return "medium"
    return "high"


def main() -> None:
    telemetry_path = "data/telemetry.jsonl"
    telemetry = _read_jsonl(telemetry_path)

    features = ["rps", "p95_latency_ms", "error_rate", "mem_pct"]
    by_service = defaultdict(list)
    for e in telemetry:
        s = e.get("service")
        if not s:
            continue
        by_service[s].append(e)

    report = {
        "input": telemetry_path,
        "total_events": len(telemetry),
        "baseline_ratio": 0.5,
        "features": features,
        "services": {},
    }

    for service, events in by_service.items():
        baseline_events, current_events = _split_baseline_current(events, ratio=0.5)

        service_block = {"event_count": len(events), "drift": {}}

        for feat in features:
            b_vals = []
            c_vals = []
            for e in baseline_events:
                v = _safe_float(e.get(feat))
                if v is not None:
                    b_vals.append(v)
            for e in current_events:
                v = _safe_float(e.get(feat))
                if v is not None:
                    c_vals.append(v)

            result = _psi(b_vals, c_vals, num_bins=10)
            service_block["drift"][feat] = {
                "psi": round(result.psi, 6),
                "severity": _severity(result.psi),
            }

        report["services"][service] = service_block

    os.makedirs("results", exist_ok=True)
    with open("results/drift_report.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    # Markdown summary
    lines = []
    lines.append("# SentinelStream Drift Report (PSI)")
    lines.append("")
    lines.append(f"- Total events: **{report['total_events']}**")
    lines.append(f"- Baseline ratio: **{report['baseline_ratio']}**")
    lines.append("")
    lines.append("## PSI by service and feature")
    for service, block in report["services"].items():
        lines.append(f"### {service} (n={block['event_count']})")
        for feat in features:
            psi_val = block["drift"][feat]["psi"]
            sev = block["drift"][feat]["severity"]
            lines.append(f"- {feat}: **{psi_val}** ({sev})")
        lines.append("")

    with open("results/drift_report.md", "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print("Saved:")
    print("  results/drift_report.json")
    print("  results/drift_report.md")
    print("")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
