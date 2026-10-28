from __future__ import annotations

import math
from collections.abc import Iterator
from typing import Any


def _number(value: Any) -> float | None:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return None
    try:
        parsed = float(value)
    except OverflowError:
        return None
    return parsed if math.isfinite(parsed) and parsed >= 0 else None


def _count(value: Any) -> int | None:
    parsed = _number(value)
    return int(parsed) if parsed is not None and parsed.is_integer() else None


def _samples(
    measurement: str, metrics: dict[str, Any]
) -> Iterator[tuple[dict[str, Any], str, Any, str]]:
    if measurement == "tcp-throughput":
        for direction in ("forward", "reverse"):
            row = metrics.get(direction) or {}
            for streams, profile in (row.get("streams") or {}).items():
                runs = profile.get("runs")
                if not isinstance(runs, list) and str(streams) == "1":
                    runs = row.get("repeats")
                for sample in runs if isinstance(runs, list) else []:
                    if isinstance(sample, dict):
                        yield sample, direction, streams, "throughput"
        bidirectional = metrics.get("bidirectional") or {}
        for direction in ("forward", "reverse"):
            sample = bidirectional.get(f"{direction}_sample")
            if isinstance(sample, dict):
                yield sample, direction, 1, "bidirectional throughput"
    elif measurement == "latency":
        for direction in ("forward", "reverse"):
            loaded = (metrics.get("loaded") or {}).get(direction) or {}
            sample = loaded.get("load_sample")
            if isinstance(sample, dict):
                yield sample, direction, loaded.get("load_streams"), "latency load"
    elif measurement in {"concurrent-path-load", "fabric-scale"}:
        for level in metrics.get("levels") or []:
            for run_index, run in enumerate(level.get("runs") or [], 1):
                for sample in run.get("tcp_windows") or []:
                    if not isinstance(sample, dict):
                        continue
                    yield (
                        {
                            **sample,
                            "concurrent_run": run_index,
                            "concurrent_pairs": level.get(
                                "pairs_used", level.get("pairs")
                            ),
                        },
                        sample.get("direction", "not recorded"),
                        None,
                        sample.get("condition", "concurrent VM-pair load"),
                    )


def _description(window: dict[str, Any]) -> str:
    parts = [window["condition"], window["direction"]]
    if window["family"] in (4, 6):
        parts.append(f"IPv{window['family']}")
    streams = window["streams"]
    parts.append(
        f"{streams} concurrent TCP connection{'s' if streams != 1 else ''}"
        if streams is not None
        else "connection count not recorded"
    )
    elapsed = window["elapsed_s"]
    parts.append(f"{elapsed:.3f} s" if elapsed is not None else "duration not recorded")
    if window["mbps"] is not None:
        parts.append(f"{window['mbps']:.1f} Mbps")
    if window["pair_index"] is not None:
        parts.append(f"VM pair {window['pair_index']}")
    if window["concurrent_pairs"] is not None:
        parts.append(f"{window['concurrent_pairs']} simultaneous VM pairs")
    if window["concurrent_run"] is not None:
        parts.append(f"repeat {window['concurrent_run']}")
    if window["source"] and window["destination"]:
        parts.append(f"{window['source']} → {window['destination']}")
    if window["stage"]:
        parts.append(str(window["stage"]))
    return "; ".join(parts)


def tcp_retransmission_summary(performance: list[dict[str, Any]]) -> dict[str, Any]:
    """Select one recorded TCP window, never totals across repeats or directions."""
    peak: dict[str, Any] | None = None
    for result in performance:
        details = result.get("details") or {}
        path = details.get("path") or {}
        measurement = str(details.get("measurement") or "")
        for sample, direction, streams, condition in _samples(
            measurement, details.get("metrics") or {}
        ):
            count = _count(sample.get("retransmissions"))
            if count is None:
                continue
            stream_count = _count(sample.get("streams"))
            if "streams" in sample and not stream_count:
                continue
            if stream_count is None and str(streams).isdigit():
                stream_count = _count(int(streams))
            counters = sample.get("stream_retransmissions")
            if "stream_retransmissions" in sample and (
                not isinstance(counters, list)
                or not counters
                or any(_count(value) is None for value in counters)
                or (stream_count is not None and len(counters) != stream_count)
                or sum(_count(value) or 0 for value in counters) != count
            ):
                # A generated aggregate can contain only the known stream
                # counters. Partial TCP_INFO telemetry is not a complete count.
                continue
            if peak is not None and count <= peak["retransmissions"]:
                continue
            elapsed = _number(sample.get("elapsed_s"))
            throughput = _number(sample.get("mbps"))
            source = path.get("source_label") or result.get("source")
            destination = path.get("destination_label") or result.get("destination")
            if direction == "reverse":
                source, destination = destination, source
            source = sample.get("source_label") or source
            destination = sample.get("destination_label") or destination
            peak = {
                "retransmissions": count,
                "elapsed_s": elapsed if elapsed else None,
                "mbps": throughput,
                "streams": stream_count if stream_count else None,
                "direction": direction,
                "condition": condition,
                "result_id": result.get("test_id"),
                "path_id": path.get("path_id"),
                "family": sample.get(
                    "family", path.get("family", result.get("family"))
                ),
                "stage": path.get("stage"),
                "placement": sample.get("placement", path.get("placement")),
                "source": source,
                "destination": destination,
                "pair_index": sample.get("pair_index"),
                "concurrent_pairs": sample.get("concurrent_pairs"),
                "concurrent_run": sample.get("concurrent_run"),
            }
    return {
        "worst_tcp_retransmissions": peak["retransmissions"] if peak else None,
        "worst_tcp_retransmission_window": peak,
        "worst_tcp_retransmission_window_description": _description(peak)
        if peak
        else None,
        "tcp_retransmission_summary_scope": (
            "Largest recorded count in one measured TCP window, including parallel "
            "streams, bidirectional transfers, latency load and retained individual "
            "windows from concurrent VM-pair load. Repeats and directions "
            "are separate; warmups and aggregate-only legacy records are excluded. "
            "Counts depend on duration and traffic volume and are not a loss rate."
        ),
    }
