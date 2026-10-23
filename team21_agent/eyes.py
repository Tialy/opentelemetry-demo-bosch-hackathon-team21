#!/usr/bin/env python3
"""Read-only Eyes component for the Bosch incident-response agent.

Collects telemetry evidence across five distinct signals:
1. Jaeger: discovered services, recent traces, and active error spans.
2. Prometheus: metric availability, container resource usage, and low-uptime containers.
3. OpenSearch: recent application logs, error/exception logs, and service attribution.
4. Deploy History: recent git commits and container lifecycle/restart history.
5. Docker: container health and running status (with demo container filtering).

This module is strictly read-only: it does not alter configurations, feature flags,
or service state.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone, timedelta
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

HTTP_TIMEOUT_SECONDS = float(os.getenv("EYES_HTTP_TIMEOUT", "5"))
LOGS_INDEX = os.getenv("OPENSEARCH_LOGS_INDEX", "otel-logs-*")

DEMO_SERVICE_NAMES = (
    "frontend", "frontend-proxy", "cart", "checkout", "payment", "shipping",
    "email", "recommendation", "product-catalog", "ad", "currency", "quote",
    "accounting", "fraud-detection", "image-provider", "load-generator",
    "flagd", "kafka", "otel-collector", "jaeger", "prometheus",
    "opensearch", "grafana", "valkey-cart", "astronomy-db", "opamp-server",
    "telemetry-docs", "flagd-ui",
)


# ---------------------------------------------------------------------------
# Port discovery — compose exposes random host ports for most services
# ---------------------------------------------------------------------------

def _docker_host_port(container: str, internal_port: int) -> int | None:
    """Return the host port mapped to internal_port for container."""
    try:
        proc = subprocess.run(
            ["docker", "port", container, f"{internal_port}/tcp"],
            capture_output=True, text=True, timeout=5, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    for line in proc.stdout.splitlines():
        match = re.search(r"0\.0\.0\.0:(\d+)", line)
        if match:
            return int(match.group(1))
    return None


def _resolve_url(env_var: str, container: str, internal_port: int,
                 default_host_port: int) -> str:
    """Resolve localhost URL with precedence: ENV > docker port > fallback."""
    explicit = os.getenv(env_var)
    if explicit:
        return explicit.rstrip("/")
    discovered = _docker_host_port(container, internal_port)
    port = discovered if discovered is not None else default_host_port
    return f"http://localhost:{port}"


JAEGER_URL = _resolve_url("JAEGER_URL", "jaeger", 16686, 16686)
PROMETHEUS_URL = _resolve_url("PROMETHEUS_URL", "prometheus", 9090, 9090)
OPENSEARCH_URL = _resolve_url("OPENSEARCH_URL", "opensearch", 9200, 9200)


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def request_json(url: str, method: str = "GET", body: dict[str, Any] | None = None) -> Any:
    """Perform a JSON HTTP request and parse response safely."""
    data = None if body is None else json.dumps(body).encode("utf-8")
    headers = {"Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    request = Request(url, data=data, headers=headers, method=method)
    try:
        with urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            raw = response.read().decode("utf-8", errors="replace")
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:300]
        raise RuntimeError(f"HTTP {exc.code}: {detail or exc.reason}") from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise RuntimeError(str(exc)) from exc
    try:
        return json.loads(raw) if raw else {}
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Endpoint did not return valid JSON: {raw[:200]}") from exc


def prometheus_query(expression: str) -> dict[str, Any]:
    url = f"{PROMETHEUS_URL}/api/v1/query?{urlencode({'query': expression})}"
    response = request_json(url)
    if response.get("status") != "success":
        raise RuntimeError(f"Prometheus query failed for {expression!r}: {response}")
    return response.get("data", {})


# ---------------------------------------------------------------------------
# Signal: Jaeger Traces
# ---------------------------------------------------------------------------

def collect_jaeger() -> dict[str, Any]:
    """Collect services, recent frontend traces, and error traces from Jaeger."""
    base = f"{JAEGER_URL}/jaeger/ui/api/v3"

    services_response = request_json(f"{base}/services")
    services = services_response.get("services", [])
    if not isinstance(services, list):
        raise RuntimeError("Jaeger /api/v3/services response had an unexpected format")

    now = datetime.now(timezone.utc)
    start_dt = now - timedelta(hours=1)
    start_iso = start_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    end_iso = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    recent_traces: list[dict[str, Any]] = []
    try:
        params = urlencode({
            "query.service_name": "frontend",
            "query.num_traces": 5,
            "query.start_time_min": start_iso,
            "query.start_time_max": end_iso,
        })
        trace_response = request_json(f"{base}/traces?{params}")
        for rs in trace_response.get("result", {}).get("resourceSpans", []):
            svc_name = "unknown"
            for attr in rs.get("resource", {}).get("attributes", []):
                if attr.get("key") == "service.name":
                    svc_name = attr.get("value", {}).get("stringValue", "unknown")
                    break
            scope_spans = rs.get("scopeSpans", [])
            span_count = sum(len(ss.get("spans", [])) for ss in scope_spans)
            trace_ids = {span.get("traceId") for ss in scope_spans for span in ss.get("spans", []) if span.get("traceId")}
            for tid in trace_ids:
                recent_traces.append({
                    "trace_id": tid,
                    "service": svc_name,
                    "span_count": span_count,
                })
    except Exception:
        pass

    # Query for error traces
    error_traces: list[dict[str, Any]] = []
    affected_error_services = set()
    try:
        err_params = urlencode({
            "query.tags": json.dumps({"error": "true"}),
            "query.num_traces": 5,
            "query.start_time_min": start_iso,
            "query.start_time_max": end_iso,
        })
        err_response = request_json(f"{base}/traces?{err_params}")
        for rs in err_response.get("result", {}).get("resourceSpans", []):
            svc_name = "unknown"
            for attr in rs.get("resource", {}).get("attributes", []):
                if attr.get("key") == "service.name":
                    svc_name = attr.get("value", {}).get("stringValue", "unknown")
                    break
            for ss in rs.get("scopeSpans", []):
                for span in ss.get("spans", []):
                    span_attrs = {a.get("key"): a.get("value") for a in span.get("attributes", [])}
                    is_err = span_attrs.get("error") or span.get("status", {}).get("code")
                    if is_err:
                        affected_error_services.add(svc_name)
                        error_traces.append({
                            "service": svc_name,
                            "span_name": span.get("name"),
                            "trace_id": span.get("traceId"),
                            "status": span.get("status"),
                            "http_status": span_attrs.get("http.status_code"),
                            "rpc_status": span_attrs.get("rpc.grpc.status_code"),
                        })
    except Exception:
        pass

    return {
        "status": "ok",
        "endpoint": base,
        "service_count": len(services),
        "services": services[:50],
        "recent_frontend_trace_count": len(recent_traces),
        "recent_frontend_traces": recent_traces[:5],
        "error_trace_count": len(error_traces),
        "error_traces": error_traces[:5],
        "affected_error_services": sorted(list(affected_error_services)),
    }


# ---------------------------------------------------------------------------
# Signal: Prometheus Metrics
# ---------------------------------------------------------------------------

def collect_prometheus() -> dict[str, Any]:
    """Collect available metrics and query key operational indicators."""
    response = request_json(f"{PROMETHEUS_URL}/api/v1/label/__name__/values")
    if response.get("status") != "success":
        raise RuntimeError(f"Prometheus metric discovery failed: {response}")
    names = response.get("data", [])
    if not isinstance(names, list):
        raise RuntimeError("Prometheus metric-name response had an unexpected format")

    samples: dict[str, Any] = {}
    for name in (
        "container_uptime_seconds",
        "container_memory_usage_total_bytes",
        "container_cpu_usage_nanoseconds_total",
    ):
        if name not in names:
            samples[name] = {"available": False, "series_count": 0}
            continue
        try:
            data = prometheus_query(name)
            results = data.get("result", [])
            samples[name] = {
                "available": True,
                "series_count": len(results) if isinstance(results, list) else 0,
            }
        except RuntimeError as exc:
            samples[name] = {"available": True, "query_error": str(exc)}

    # Check for containers with low uptime (< 300s = recently restarted or crash-looping)
    low_uptime_containers: list[dict[str, Any]] = []
    if "container_uptime_seconds" in names:
        try:
            uptime_data = prometheus_query("container_uptime_seconds < 300")
            for item in uptime_data.get("result", []):
                metric = item.get("metric", {})
                cname = metric.get("container_name") or metric.get("name")
                val = item.get("value", [None, None])[1]
                if cname and any(cname.startswith(p) for p in DEMO_SERVICE_NAMES):
                    low_uptime_containers.append({
                        "container": cname,
                        "uptime_seconds": float(val) if val else 0.0,
                    })
        except Exception:
            pass

    return {
        "status": "ok",
        "endpoint": PROMETHEUS_URL,
        "metric_name_count": len(names),
        "sample_metric_names": names[:30],
        "sample_series": samples,
        "low_uptime_containers": low_uptime_containers,
    }


# ---------------------------------------------------------------------------
# Signal: OpenSearch Logs
# ---------------------------------------------------------------------------

def _extract_log_doc(hit: dict[str, Any]) -> dict[str, Any]:
    source = hit.get("_source", {}) or {}
    resource = source.get("resource", {}) or {}
    attributes = source.get("attributes", {}) or {}
    res_attrs = resource.get("attributes", {}) or {}

    service_name = (
        resource.get("service.name")
        or source.get("service.name")
        or res_attrs.get("service.name")
        or attributes.get("service.name")
        or "unknown"
    )

    sev = source.get("severity")
    if isinstance(sev, dict):
        sev_text = sev.get("text") or (f"LVL-{sev.get('number')}" if sev.get("number") else None)
    else:
        sev_text = source.get("severity_text") or source.get("severityText") or (str(sev) if sev else None)

    msg = source.get("body") or source.get("message") or source.get("log")
    if isinstance(msg, dict):
        msg = msg.get("stringValue") or msg.get("text") or json.dumps(msg)[:200]

    ts = source.get("@timestamp") or source.get("time") or source.get("timestamp")

    return {
        "timestamp": ts,
        "service": service_name,
        "severity": sev_text,
        "message": str(msg).strip()[:240] if msg is not None else None,
        "index": hit.get("_index"),
    }


def collect_opensearch_logs() -> dict[str, Any]:
    """Collect recent general logs and recent error/exception logs."""
    url = f"{OPENSEARCH_URL}/{LOGS_INDEX}/_search"

    # 1. Recent general logs
    body_recent = {
        "size": 5,
        "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
        "query": {"match_all": {}},
    }
    response_recent = request_json(url, method="POST", body=body_recent)
    hits_block = response_recent.get("hits", {}) or {}
    total_block = hits_block.get("total", 0)
    total = total_block.get("value", 0) if isinstance(total_block, dict) else total_block

    recent_logs = [_extract_log_doc(h) for h in hits_block.get("hits", []) or []]

    # 2. Recent error and exception logs
    body_errors = {
        "size": 10,
        "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
        "query": {
            "bool": {
                "should": [
                    {"match_phrase": {"body": "error"}},
                    {"match_phrase": {"body": "failed"}},
                    {"match_phrase": {"body": "exception"}},
                    {"range": {"severity.number": {"gte": 13}}},
                    {"term": {"severity.text": "error"}},
                    {"term": {"severity.text": "ERROR"}},
                ],
                "minimum_should_match": 1,
            }
        },
    }
    error_logs: list[dict[str, Any]] = []
    error_services = set()
    try:
        response_errors = request_json(url, method="POST", body=body_errors)
        for h in response_errors.get("hits", {}).get("hits", []) or []:
            doc = _extract_log_doc(h)
            error_logs.append(doc)
            if doc["service"] and doc["service"] != "unknown":
                error_services.add(doc["service"])
    except Exception:
        pass

    return {
        "status": "ok",
        "endpoint": OPENSEARCH_URL,
        "index_pattern": LOGS_INDEX,
        "matching_document_count": total,
        "recent_logs": recent_logs,
        "error_log_count": len(error_logs),
        "recent_error_logs": error_logs[:6],
        "affected_error_services": sorted(list(error_services)),
    }


# ---------------------------------------------------------------------------
# Signal: Deploy History
# ---------------------------------------------------------------------------

def collect_deploy_history() -> dict[str, Any]:
    """Collect git commit deploy history and container lifecycle restart history."""
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    # Git deploy history
    git_commits: list[str] = []
    current_commit = "unknown"
    current_branch = "unknown"
    try:
        proc_commits = subprocess.run(
            ["git", "log", "-n", "5", "--format=%h | %an | %cr | %s"],
            capture_output=True, text=True, timeout=5, check=False, cwd=repo_root,
        )
        if proc_commits.returncode == 0:
            git_commits = [l.strip() for l in proc_commits.stdout.splitlines() if l.strip()]

        proc_rev = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=5, check=False, cwd=repo_root,
        )
        if proc_rev.returncode == 0:
            current_commit = proc_rev.stdout.strip()

        proc_br = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True, text=True, timeout=5, check=False, cwd=repo_root,
        )
        if proc_br.returncode == 0:
            current_branch = proc_br.stdout.strip()
    except Exception:
        pass

    # Container lifecycle events from docker ps
    recent_deployments: list[dict[str, str]] = []
    try:
        proc_docker = subprocess.run(
            ["docker", "ps", "--all", "--format", "{{.Names}}\t{{.Status}}\t{{.CreatedAt}}"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        if proc_docker.returncode == 0:
            for line in proc_docker.stdout.splitlines():
                parts = line.strip().split("\t")
                if len(parts) >= 2:
                    name = parts[0]
                    status = parts[1]
                    created = parts[2] if len(parts) > 2 else ""
                    if any(name.startswith(p) for p in DEMO_SERVICE_NAMES):
                        recent_deployments.append({
                            "service": name,
                            "status": status,
                            "created_at": created,
                        })
    except Exception:
        pass

    return {
        "status": "ok",
        "current_commit": current_commit,
        "current_branch": current_branch,
        "recent_git_commits": git_commits,
        "demo_service_deployments": recent_deployments[:15],
    }


# ---------------------------------------------------------------------------
# Signal: Docker Containers
# ---------------------------------------------------------------------------

def collect_docker() -> dict[str, Any]:
    """Inspect local Docker containers, separating demo from host services."""
    try:
        proc = subprocess.run(
            ["docker", "ps", "--all", "--format", "{{json .}}"],
            capture_output=True, text=True, timeout=10, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"Could not run Docker CLI: {exc}") from exc
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout or "docker ps failed").strip())

    all_containers: list[dict[str, str]] = []
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        name = str(item.get("Names", "unknown"))
        status = str(item.get("Status", "unknown"))
        image = str(item.get("Image", "unknown"))
        all_containers.append({"name": name, "status": status, "image": image})

    # Filter to OpenTelemetry demo containers
    demo_containers = [c for c in all_containers if any(c["name"].startswith(p) for p in DEMO_SERVICE_NAMES)]
    unhealthy = [c for c in demo_containers if "unhealthy" in c["status"].lower()]
    stopped = [c for c in demo_containers if c["status"].lower().startswith(("exited", "dead", "created"))]
    running = [c for c in demo_containers if c["status"].lower().startswith("up ")]

    return {
        "status": "ok",
        "container_count": len(demo_containers),
        "running_count": len(running),
        "unhealthy_count": len(unhealthy),
        "stopped_count": len(stopped),
        "unhealthy_containers": unhealthy,
        "stopped_containers": stopped,
        "containers": demo_containers,
    }


# ---------------------------------------------------------------------------
# Orchestrator & Symptom Summary
# ---------------------------------------------------------------------------

def collect_signal(name: str, collector: Any) -> dict[str, Any]:
    """Collect a single signal safely, isolating failures."""
    try:
        return collector()
    except Exception as exc:
        return {"status": "error", "error": str(exc), "signal": name}


def collect_snapshot() -> dict[str, Any]:
    """Collect full telemetry snapshot across all 5 signals."""
    return {
        "schema_version": "1.2",
        "component": "eyes",
        "mode": "read_only",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "resolved_endpoints": {
            "jaeger": JAEGER_URL,
            "prometheus": PROMETHEUS_URL,
            "opensearch": OPENSEARCH_URL,
        },
        "signals": {
            "traces": collect_signal("traces", collect_jaeger),
            "metrics": collect_signal("metrics", collect_prometheus),
            "logs": collect_signal("logs", collect_opensearch_logs),
            "deploy_history": collect_signal("deploy_history", collect_deploy_history),
            "containers": collect_signal("containers", collect_docker),
        },
        "safety_note": "Evidence collection only: no demo configuration, feature flags, or services were changed.",
    }


def summarize_symptoms(snapshot: dict[str, Any]) -> str:
    """Generate a clean, ASCII-safe symptom summary for human review (Checkpoint 1)."""
    signals = snapshot.get("signals", {})
    containers = signals.get("containers", {})
    logs = signals.get("logs", {})
    traces = signals.get("traces", {})
    metrics = signals.get("metrics", {})
    deploy = signals.get("deploy_history", {})

    symptoms: list[str] = []

    # Container anomalies
    stopped = containers.get("stopped_containers", [])
    if stopped:
        names = [c["name"] for c in stopped]
        symptoms.append(f"[CONTAINERS] Stopped demo services: {', '.join(names)}")
    unhealthy = containers.get("unhealthy_containers", [])
    if unhealthy:
        names = [c["name"] for c in unhealthy]
        symptoms.append(f"[CONTAINERS] Unhealthy services: {', '.join(names)}")

    # Metric anomalies
    low_uptime = metrics.get("low_uptime_containers", [])
    if low_uptime:
        details = [f"{item['container']} ({item['uptime_seconds']:.0f}s)" for item in low_uptime]
        symptoms.append(f"[METRICS] Low uptime / recently restarted: {', '.join(details)}")

    # Log anomalies
    error_logs = logs.get("recent_error_logs", [])
    err_services = logs.get("affected_error_services", [])
    if error_logs:
        symptoms.append(f"[LOGS] {logs.get('error_log_count', len(error_logs))} error/warn logs detected across: {', '.join(err_services) or 'system'}")
        for l in error_logs[:3]:
            symptoms.append(f"       * [{l.get('service')}] {l.get('message')}")

    # Trace anomalies
    error_traces = traces.get("error_traces", [])
    err_trace_services = traces.get("affected_error_services", [])
    if error_traces:
        symptoms.append(f"[TRACES] {traces.get('error_trace_count', len(error_traces))} error spans in services: {', '.join(err_trace_services)}")
        for t in error_traces[:2]:
            symptoms.append(f"       * [{t.get('service')}] span: {t.get('span_name')} (http={t.get('http_status')}, rpc={t.get('rpc_status')})")

    lines = [
        "=" * 60,
        "  EYES TELEMETRY & SYMPTOM SUMMARY (CHECKPOINT 1)",
        f"  Captured: {snapshot.get('generated_at')}",
        "=" * 60,
        "",
        "  Signals evaluated:",
        f"  - Traces (Jaeger):       {traces.get('status')} ({traces.get('service_count', 0)} services, {traces.get('error_trace_count', 0)} error traces)",
        f"  - Metrics (Prometheus):  {metrics.get('status')} ({metrics.get('metric_name_count', 0)} metric names)",
        f"  - Logs (OpenSearch):     {logs.get('status')} ({logs.get('matching_document_count', 0)} docs, {logs.get('error_log_count', 0)} error logs)",
        f"  - Deploy History:        {deploy.get('status')} (commit {deploy.get('current_commit')}, branch {deploy.get('current_branch')})",
        f"  - Containers (Docker):   {containers.get('status')} ({containers.get('running_count', 0)} running, {len(stopped)} stopped, {len(unhealthy)} unhealthy)",
        "",
        "  Symptom Diagnosis:",
    ]

    if symptoms:
        lines.append(f"  [!] {len(symptoms)} incident symptom(s) observed:")
        for s in symptoms:
            lines.append(f"    - {s}")
    else:
        lines.append("  [OK] All signals nominal. No active incident symptoms detected.")

    lines.append("")
    lines.append("=" * 60)
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Eyes: telemetry collector for OpenTelemetry Demo")
    parser.add_argument("--summary", action="store_true", help="Print human-readable symptom summary (Checkpoint 1)")
    parser.add_argument("--save", metavar="FILE", help="Save JSON snapshot to file")
    args, _ = parser.parse_known_args(argv if argv is not None else sys.argv[1:])

    print(f"[eyes] Resolved endpoints:", file=sys.stderr)
    print(f"  Jaeger:     {JAEGER_URL}", file=sys.stderr)
    print(f"  Prometheus: {PROMETHEUS_URL}", file=sys.stderr)
    print(f"  OpenSearch: {OPENSEARCH_URL}", file=sys.stderr)

    snapshot = collect_snapshot()

    if args.save:
        with open(args.save, "w", encoding="utf-8") as f:
            json.dump(snapshot, f, indent=2, ensure_ascii=False)
        print(f"[eyes] Snapshot saved to {args.save}", file=sys.stderr)

    if args.summary:
        print(summarize_symptoms(snapshot))
    else:
        print(json.dumps(snapshot, indent=2, ensure_ascii=False))

    failed = [name for name, result in snapshot["signals"].items() if result.get("status") != "ok"]
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
