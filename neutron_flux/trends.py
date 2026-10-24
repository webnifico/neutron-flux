from __future__ import annotations

import html
import json
import math
import pathlib
from datetime import datetime, timezone
from typing import Any

from .results_io import atomic_write_text, load_results, output_directory, result_files


def _number(value: Any) -> float | None:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    return parsed if math.isfinite(parsed) else None


def _first(mapping: dict[str, Any], *keys: str) -> Any:
    """Return the first recorded value, including zero and ``False``."""

    for key in keys:
        if mapping.get(key) is not None:
            return mapping[key]
    return None


def _values(payload: dict[str, Any]) -> dict[str, Any]:
    summary = payload.get("summary") or {}
    performance = summary.get("performance") or summary.get("performance_summary") or {}
    counts = summary.get("counts") or {}
    cleanup = payload.get("cleanup") or {}
    return {
        "run_id": (payload.get("run") or {}).get("run_id"),
        "started_at": (payload.get("run") or {}).get("started_at"),
        "final_status": (payload.get("run") or {}).get("final_status"),
        "pass": int(counts.get("PASS") or 0),
        "fail": int(counts.get("FAIL") or 0),
        "error": int(counts.get("ERROR") or 0),
        "blocked_by_setup_error": int(counts.get("BLOCKED_BY_SETUP_ERROR") or 0),
        "blocked_by_prerequisite": int(counts.get("BLOCKED_BY_PREREQUISITE") or 0),
        "cancelled_checks": int(counts.get("NOT_RUN_CANCELLED") or 0),
        "unverified": int(counts.get("UNVERIFIED") or 0),
        "warnings": int(
            performance.get("warning_results") or performance.get("warnings") or 0
        ),
        "cleanup_complete": cleanup.get("complete"),
        "lowest_tcp_mbps": _number(
            performance.get("lowest_single_stream_mbps")
            if performance.get("lowest_single_stream_mbps") is not None
            else performance.get("lowest_single_stream_tcp_mbps")
        ),
        "highest_idle_p95_ms": _number(
            performance.get("highest_idle_p95_ms")
            if performance.get("highest_idle_p95_ms") is not None
            else performance.get("highest_idle_p95_latency_ms")
        ),
        "highest_loaded_ratio": _number(
            performance.get("worst_loaded_latency_ratio")
            if performance.get("worst_loaded_latency_ratio") is not None
            else performance.get("highest_loaded_latency_ratio")
        ),
        "worst_udp_loss_pct": _number(performance.get("worst_udp_loss_pct")),
        "worst_udp_jitter_ms": _number(performance.get("worst_udp_jitter_ms")),
        "worst_asymmetry_pct": _number(
            performance.get("worst_directional_asymmetry_pct")
        ),
        "worst_variation_pct": _number(
            performance.get("worst_repeatability_variation_pct")
        ),
        "mtu_mismatches": int(
            performance.get("mtu_mismatch_paths")
            if performance.get("mtu_mismatch_paths") is not None
            else performance.get("mtu_mismatches") or 0
        ),
        "performance_paths": int(
            performance.get("paths")
            if performance.get("paths") is not None
            else performance.get("paths_measured") or 0
        ),
        # Canonical names describe the VM-visible measurement. Legacy keys remain
        # read aliases so historical result directories still trend correctly.
        "concurrent_load_max_pairs": int(
            _first(
                performance,
                "concurrent_load_max_pairs",
                "fabric_max_pairs",
            )
            or 0
        ),
        "concurrent_load_highest_observed_aggregate_mbps": _number(
            _first(
                performance,
                "concurrent_load_highest_observed_aggregate_mbps",
                "fabric_best_aggregate_mbps",
            )
        ),
        "concurrent_load_lowest_pair_mbps": _number(
            _first(
                performance,
                "concurrent_load_lowest_pair_mbps",
                "fabric_lowest_pair_mbps",
            )
        ),
        "concurrent_load_worst_degradation_pct": _number(
            _first(
                performance,
                "concurrent_load_worst_degradation_pct",
                "fabric_worst_degradation_pct",
            )
        ),
        "concurrent_load_worst_loaded_latency_ratio": _number(
            _first(
                performance,
                "concurrent_load_worst_loaded_latency_ratio",
                "fabric_worst_loaded_latency_ratio",
            )
        ),
        "concurrent_load_worst_udp_jitter_ms": _number(
            _first(
                performance,
                "concurrent_load_worst_udp_jitter_ms",
                "fabric_worst_udp_jitter_ms",
            )
        ),
        "concurrent_load_highest_observed_loaded_tcp_aggregate_mbps": _number(
            _first(
                performance,
                "concurrent_load_highest_observed_loaded_tcp_aggregate_mbps",
                "fabric_best_loaded_tcp_aggregate_mbps",
            )
        ),
        "concurrent_load_worst_clean_retransmissions": _number(
            _first(
                performance,
                "concurrent_load_worst_clean_retransmissions",
                "fabric_worst_capacity_retransmissions",
            )
        ),
        "concurrent_load_worst_loaded_retransmissions": _number(
            _first(
                performance,
                "concurrent_load_worst_loaded_retransmissions",
                "fabric_worst_loaded_retransmissions",
            )
        ),
    }


def trend_payload(paths: list[pathlib.Path]) -> dict[str, Any]:
    runs = [_values(load_results(path)) for path in paths]

    seen_run_ids: set[str] = set()
    duplicates: set[str] = set()
    for item in runs:
        run_id = str(item.get("run_id") or "").strip()
        if not run_id:
            raise ValueError("Trend inputs contain a result with no run ID")
        if run_id in seen_run_ids:
            duplicates.add(run_id)
        seen_run_ids.add(run_id)
    if duplicates:
        rendered = ", ".join(sorted(duplicates))
        raise ValueError(
            f"Trend inputs contain duplicate run IDs and are not independent runs: {rendered}"
        )

    def sort_key(item: dict[str, Any]) -> tuple[int, float, str]:
        value = str(item.get("started_at") or "").strip()
        if value:
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                return (1, parsed.timestamp(), str(item.get("run_id") or ""))
            except ValueError:
                pass
        # Unknown timestamps stay visible, but sort before valid chronology so
        # they cannot become the headline latest run.
        return (0, 0.0, str(item.get("run_id") or ""))

    runs.sort(key=sort_key)
    return {
        "schema_version": 1,
        "kind": "neutron-flux-trend",
        "runs": runs,
        "summary": {
            "run_count": len(runs),
            "first_run": runs[0].get("run_id") if runs else None,
            "latest_run": runs[-1].get("run_id") if runs else None,
            "cleanup_failures": sum(
                1 for item in runs if item.get("cleanup_complete") is False
            ),
            "failed_runs": sum(
                1
                for item in runs
                if item.get("fail")
                or item.get("error")
                or str(item.get("final_status") or "").upper()
                not in {"PASS", "PASS WITH WARNINGS"}
            ),
        },
    }


def _trend_text(payload: dict[str, Any]) -> str:
    lines = [
        "NEUTRON FLUX HISTORICAL TREND",
        "=" * 100,
        f"Runs: {payload.get('summary', {}).get('run_count', 0)}",
        "",
        "RUNS",
        "-" * 100,
    ]
    for run in payload.get("runs") or []:
        lines.append(
            f"{run.get('started_at')} | {run.get('run_id')} | {run.get('final_status')} | "
            f"TCP min={run.get('lowest_tcp_mbps')} Mbit/s | p95={run.get('highest_idle_p95_ms')} ms | "
            f"UDP application-delivery loss={run.get('worst_udp_loss_pct')}% | warnings={run.get('warnings')} | "
            "concurrent-load="
            f"{run.get('concurrent_load_highest_observed_aggregate_mbps')} "
            f"Mbit/s/{run.get('concurrent_load_max_pairs')} pairs | "
            "concurrent-load-with-udp="
            f"{run.get('concurrent_load_highest_observed_loaded_tcp_aggregate_mbps')} "
            "Mbit/s | "
            f"failures={run.get('fail')} errors={run.get('error')}"
        )
    return "\n".join(lines) + "\n"


def _trend_html(payload: dict[str, Any]) -> str:
    data = json.dumps(payload, separators=(",", ":"), allow_nan=False).replace(
        "</", "<\\/"
    )
    title = html.escape("Neutron Flux historical trends")
    return f"""<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>{title}</title>
<style>:root{{--bg:#07111f;--panel:#101d2d;--line:#2c4664;--text:#ecf4ff;--muted:#aebed1;--accent:#67d8ff}}*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:16px/1.5 system-ui,sans-serif}}main{{max-width:1600px;margin:auto;padding:28px}}.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:20px 0}}.card,.panel{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px;margin-bottom:14px}}.card strong{{display:block;font-size:28px}}.muted{{color:var(--muted)}}.grid{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}}canvas{{width:100%;height:280px;background:#091625;border-radius:8px}}table{{width:100%;border-collapse:collapse}}th,td{{padding:9px;border-bottom:1px solid var(--line);text-align:left}}@media(max-width:900px){{.grid{{grid-template-columns:1fr}}}}</style></head><body><main><h1>Neutron Flux historical trends</h1><p class=\"muted\">VM-observed network-path quality, concurrent-load measurements, and validation results across saved runs.</p><div class=\"cards\" id=\"cards\"></div><div class=\"grid\"><div class=\"panel\"><h2>TCP throughput (Mbit/s)</h2><canvas id=\"tcp\"></canvas></div><div class=\"panel\"><h2>Idle p95 latency (ms)</h2><canvas id=\"lat\"></canvas></div><div class=\"panel\"><h2>Loaded latency increase (×)</h2><canvas id=\"latRatio\"></canvas></div><div class=\"panel\"><h2>UDP application-delivery loss (%)</h2><canvas id=\"udpLoss\"></canvas></div><div class=\"panel\"><h2>UDP jitter (ms)</h2><canvas id=\"udpJitter\"></canvas></div><div class=\"panel\"><h2>Concurrent-load aggregate throughput (Mbit/s)</h2><canvas id=\"fabric\"></canvas></div><div class=\"panel\"><h2>Concurrent-load per-pair change (%)</h2><canvas id=\"fabricDegradation\"></canvas></div><div class=\"panel\"><h2>Concurrent-load latency increase (×)</h2><canvas id=\"fabricLatency\"></canvas></div><div class=\"panel\"><h2>Validation findings</h2><canvas id=\"findings\"></canvas></div></div><div class=\"panel\"><h2>Run inventory</h2><table><thead><tr><th>Run</th><th>Started</th><th>Status</th><th>TCP min</th><th>Idle p95 max</th><th>UDP application loss</th><th>Concurrent-load aggregate</th><th>Warnings</th><th>Cleanup</th></tr></thead><tbody id=\"rows\"></tbody></table></div></main><script id=\"data\" type=\"application/json\">{data}</script><script>
const D=JSON.parse(document.getElementById('data').textContent),R=D.runs||[],esc=v=>String(v??'').replace(/[&<>\"']/g,c=>({{'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',"'":'&#39;'}}[c])),fmt=v=>v==null?'—':Number(v).toLocaleString(undefined,{{maximumFractionDigits:2}});document.getElementById('cards').innerHTML=[['Runs',D.summary.run_count],['Failed runs',D.summary.failed_runs],['Cleanup failures',D.summary.cleanup_failures],['Latest',D.summary.latest_run||'—']].map(x=>`<div class=\"card\"><span class=\"muted\">${{esc(x[0])}}</span><strong>${{esc(x[1])}}</strong></div>`).join('');
function chart(id,series){{const c=document.getElementById(id),x=c.getContext('2d'),d=devicePixelRatio||1,w=c.clientWidth,h=c.clientHeight;c.width=w*d;c.height=h*d;x.scale(d,d);x.clearRect(0,0,w,h);const vals=series.flatMap(s=>s.values).filter(Number.isFinite),max=Math.max(1,...vals)*1.12,p={{l:48,r:12,t:22,b:58}},cw=w-p.l-p.r,ch=h-p.t-p.b;x.strokeStyle='#2c4664';x.beginPath();x.moveTo(p.l,p.t);x.lineTo(p.l,h-p.b);x.lineTo(w-p.r,h-p.b);x.stroke();series.forEach((s,si)=>{{x.strokeStyle=s.color;x.lineWidth=2;x.beginPath();let started=false;s.values.forEach((v,i)=>{{if(!Number.isFinite(v))return;const px=p.l+(i*Math.max(cw/(Math.max(R.length-1,1)),1)),py=p.t+ch-(v/max*ch);if(!started){{x.moveTo(px,py);started=true}}else x.lineTo(px,py);x.fillStyle=s.color;x.fillRect(px-2,py-2,4,4)}});x.stroke();x.fillStyle=s.color;x.fillText(s.name,p.l+si*170,14)}});x.fillStyle='#aebed1';R.forEach((r,i)=>{{const px=p.l+(i*Math.max(cw/(Math.max(R.length-1,1)),1));x.save();x.translate(px,h-8);x.rotate(-.5);x.fillText(String(r.run_id||'').slice(0,24),0,0);x.restore()}})}}
chart('tcp',[{{name:'Lowest TCP Mbit/s',color:'#67d8ff',values:R.map(r=>r.lowest_tcp_mbps)}}]);chart('lat',[{{name:'Idle p95 ms',color:'#42d392',values:R.map(r=>r.highest_idle_p95_ms)}}]);chart('latRatio',[{{name:'Loaded increase ×',color:'#ffcb66',values:R.map(r=>r.highest_loaded_ratio)}}]);chart('udpLoss',[{{name:'Application loss %',color:'#ff6b7a',values:R.map(r=>r.worst_udp_loss_pct)}}]);chart('udpJitter',[{{name:'Jitter ms',color:'#b5a1ff',values:R.map(r=>r.worst_udp_jitter_ms)}}]);chart('fabric',[{{name:'Aggregate Mbit/s',color:'#67d8ff',values:R.map(r=>r.concurrent_load_highest_observed_aggregate_mbps)}},{{name:'Lowest pair Mbit/s',color:'#ffcb66',values:R.map(r=>r.concurrent_load_lowest_pair_mbps)}}]);chart('fabricDegradation',[{{name:'Decrease from reference %',color:'#ff6b7a',values:R.map(r=>r.concurrent_load_worst_degradation_pct)}}]);chart('fabricLatency',[{{name:'Loaded increase ×',color:'#b5a1ff',values:R.map(r=>r.concurrent_load_worst_loaded_latency_ratio)}}]);chart('findings',[{{name:'Failures',color:'#ff6b7a',values:R.map(r=>r.fail)}},{{name:'Execution errors',color:'#ffcb66',values:R.map(r=>r.error)}},{{name:'Warnings',color:'#b5a1ff',values:R.map(r=>r.warnings)}},{{name:'Unverified',color:'#78a9ff',values:R.map(r=>r.unverified)}}]);document.getElementById('rows').innerHTML=R.map(r=>`<tr><td>${{esc(r.run_id)}}</td><td>${{esc(r.started_at||'—')}}</td><td>${{esc(r.final_status||'—')}}</td><td>${{fmt(r.lowest_tcp_mbps)}} Mbit/s</td><td>${{fmt(r.highest_idle_p95_ms)}} ms</td><td>${{fmt(r.worst_udp_loss_pct)}}%</td><td>${{fmt(r.concurrent_load_highest_observed_aggregate_mbps)}} Mbit/s / ${{r.concurrent_load_max_pairs||0}} pairs</td><td>${{r.warnings||0}}</td><td>${{r.cleanup_complete===true?'complete':r.cleanup_complete===false?'incomplete':'not run'}}</td></tr>`).join('');
</script></body></html>"""


def trend_files(
    inputs: list[str | pathlib.Path],
    *,
    destination: str | pathlib.Path | None = None,
) -> dict[str, pathlib.Path]:
    paths = result_files(inputs)
    if len(paths) < 2:
        raise ValueError(
            "Trend reporting requires at least two discovered results.json files"
        )
    output = output_directory(
        destination, default=pathlib.Path.cwd() / "neutron-flux-trend"
    )
    payload = trend_payload(paths)
    json_path = output / "trend.json"
    text_path = output / "trend.txt"
    html_path = output / "trend.html"
    atomic_write_text(
        json_path,
        json.dumps(payload, indent=2, sort_keys=True, allow_nan=False) + "\n",
    )
    atomic_write_text(text_path, _trend_text(payload))
    atomic_write_text(html_path, _trend_html(payload))
    return {"json": json_path, "text": text_path, "html": html_path}


__all__ = ["trend_files", "trend_payload"]
