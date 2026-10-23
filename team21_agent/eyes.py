#!/usr/bin/env python3
"""Team 21 Eyes: read-only incident detection and evidence gathering.

Modes:
  - default / --snapshot: collect a detailed telemetry snapshot and evaluate thresholds
  - --once: evaluate thresholds once; investigate automatically if an incident is detected
  - --watch: poll continuously; when a threshold breach appears, investigate it once

The component does not modify the demo, inspect feature-flag configuration, or perform remediation.
It detects generic HTTP 5xx-rate and request-latency threshold breaches from Prometheus data,
then gathers targeted traces, logs, and container health for the implicated service.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

PROMETHEUS_URL = os.getenv("PROMETHEUS_URL", "http://localhost:9090").rstrip("/")
JAEGER_URL = os.getenv("JAEGER_URL", "http://localhost:8080/jaeger/ui").rstrip("/")
OPENSEARCH_URL = os.getenv("OPENSEARCH_URL", "http://localhost:55704").rstrip("/")
HTTP_TIMEOUT_SECONDS = float(os.getenv("EYES_HTTP_TIMEOUT", "5"))
LOGS_INDEX = os.getenv("OPENSEARCH_LOGS_INDEX", "otel-logs-*")
DEFAULT_ERROR_RATE_THRESHOLD = float(os.getenv("EYES_ERROR_RATE_THRESHOLD", "0.05"))
DEFAULT_P95_LATENCY_THRESHOLD_MS = float(os.getenv("EYES_P95_LATENCY_THRESHOLD_MS", "1000"))
DEFAULT_WINDOW_SECONDS = int(os.getenv("EYES_WINDOW_SECONDS", "300"))
DEFAULT_MIN_REQUESTS = float(os.getenv("EYES_MIN_REQUESTS", "20"))
DEFAULT_WATCH_INTERVAL = float(os.getenv("EYES_WATCH_INTERVAL", "15"))

HTTP_COUNT_CANDIDATES = (
    "http_server_duration_milliseconds_count",
    "http_server_request_duration_seconds_count",
    "http_server_duration_seconds_count",
    "http_server_request_duration_milliseconds_count",
    "http_requests_total",
    "http_server_requests_total",
    "http_requests_count",
)
HTTP_BUCKET_CANDIDATES = (
    "http_server_duration_milliseconds_bucket",
    "http_server_request_duration_seconds_bucket",
    "http_server_duration_seconds_bucket",
    "http_server_request_duration_milliseconds_bucket",
)
STATUS_LABEL_CANDIDATES = (
    "http_status_code",
    "http_response_status_code",
    "status_code",
    "http_status",
    "response_code",
)
SERVICE_LABEL_CANDIDATES = (
    "service_name",
    "exported_job",
    "service",
    "app",
    "exported_service",
    "job",
)
DEMO_CONTAINER_NAMES = {
    "accounting", "ad", "astronomy-db", "cart", "checkout", "currency",
    "email", "flagd", "flagd-ui", "fraud-detection", "frontend",
    "frontend-proxy", "grafana", "image-provider", "jaeger", "kafka",
    "load-generator", "opamp-server", "opensearch", "otel-collector",
    "payment", "product-catalog", "prometheus", "quote", "recommendation",
    "shipping", "telemetry-docs", "valkey-cart", "agent", "mcp", "chatbot",
}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_utc(value: datetime | None = None) -> str:
    return (value or utc_now()).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def request_json(url: str, method: str = "GET", body: dict[str, Any] | None = None) -> Any:
    """Make a small JSON HTTP request and parse its response."""
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


def request_json_stream(url: str) -> list[Any]:
    """Read one or more JSON objects from a streaming API response."""
    request = Request(url, headers={"Accept": "application/json"}, method="GET")
    try:
        with urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            raw = response.read().decode("utf-8", errors="replace")
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:300]
        raise RuntimeError(f"HTTP {exc.code}: {detail or exc.reason}") from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise RuntimeError(str(exc)) from exc

    decoder = json.JSONDecoder()
    values: list[Any] = []
    offset = 0
    while offset < len(raw):
        while offset < len(raw) and raw[offset].isspace():
            offset += 1
        if offset >= len(raw):
            break
        try:
            value, offset = decoder.raw_decode(raw, offset)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Endpoint did not return valid JSON stream near {raw[offset:offset + 200]!r}") from exc
        if isinstance(value, list):
            values.extend(value)
        else:
            values.append(value)
    return values


def prometheus_query(expression: str) -> dict[str, Any]:
    url = f"{PROMETHEUS_URL}/api/v1/query?{urlencode({'query': expression})}"
    response = request_json(url)
    if response.get("status") != "success":
        raise RuntimeError(f"Prometheus query failed for {expression!r}: {response}")
    data = response.get("data", {})
    if not isinstance(data, dict):
        raise RuntimeError(f"Prometheus returned an unexpected response for {expression!r}")
    return data


def prometheus_metric_names() -> list[str]:
    response = request_json(f"{PROMETHEUS_URL}/api/v1/label/__name__/values")
    if response.get("status") != "success" or not isinstance(response.get("data"), list):
        raise RuntimeError("Prometheus metric-name discovery failed")
    return [str(name) for name in response["data"]]


def _vector_value(item: dict[str, Any]) -> float | None:
    value = item.get("value")
    if not isinstance(value, list) or len(value) < 2:
        return None
    try:
        parsed = float(value[1])
    except (TypeError, ValueError):
        return None
    return parsed if math.isfinite(parsed) else None


def _query_sum(expression: str, empty_value: float = 0.0) -> float:
    result = prometheus_query(expression).get("result", [])
    if not isinstance(result, list) or not result:
        return empty_value
    values = [_vector_value(item) for item in result if isinstance(item, dict)]
    available = [value for value in values if value is not None]
    return sum(available) if available else empty_value


def _series_labels(metric_name: str) -> list[dict[str, str]]:
    data = prometheus_query(metric_name)
    result = data.get("result", [])
    if not isinstance(result, list):
        return []
    labels: list[dict[str, str]] = []
    for item in result:
        if not isinstance(item, dict):
            continue
        metric = item.get("metric", {})
        if isinstance(metric, dict):
            labels.append({str(k): str(v) for k, v in metric.items()})
    return labels


def _find_status_label(series_labels: list[dict[str, str]]) -> str | None:
    for key in STATUS_LABEL_CANDIDATES:
        values = [labels.get(key, "") for labels in series_labels]
        if any(re.fullmatch(r"[1-5]\d\d", value) for value in values):
            return key
    return None


def _find_service_label(series_labels: list[dict[str, str]]) -> str | None:
    for key in SERVICE_LABEL_CANDIDATES:
        values = {labels.get(key, "") for labels in series_labels if labels.get(key, "")}
        if values and (key != "job" or len(values) > 1):
            return key
    return None


def _service_error_counts(metric: str, status_label: str, service_label: str | None, window: str) -> list[dict[str, Any]]:
    if not service_label:
        return []
    expression = (
        f'sum by ({service_label}) '
        f'(increase({metric}{{{status_label}=~"5[0-9][0-9]"}}[{window}]))'
    )
    try:
        result = prometheus_query(expression).get("result", [])
    except RuntimeError:
        return []
    output = []
    for item in result if isinstance(result, list) else []:
        if not isinstance(item, dict):
            continue
        value = _vector_value(item)
        service = (item.get("metric") or {}).get(service_label)
        if value is not None and service:
            output.append({"service": str(service), "error_count": round(max(0.0, value), 3)})
    return sorted(output, key=lambda item: item["error_count"], reverse=True)


def _detect_http_error_rate(
    metric_names: list[str], window_seconds: int, threshold: float, min_requests: float
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    metric = next((name for name in HTTP_COUNT_CANDIDATES if name in metric_names), None)
    if metric is None:
        return (
            {
                "status": "unavailable",
                "reason": "No supported HTTP request-count metric was found in Prometheus.",
                "supported_candidates": list(HTTP_COUNT_CANDIDATES),
            },
            [],
            {},
        )

    try:
        labels = _series_labels(metric)
    except RuntimeError as exc:
        return ({"status": "error", "metric": metric, "error": str(exc)}, [], {})

    status_label = _find_status_label(labels)
    service_label = _find_service_label(labels)
    if status_label is None:
        return (
            {
                "status": "unavailable",
                "metric": metric,
                "reason": "The request-count metric does not expose a recognized HTTP status-code label.",
                "observed_label_names": sorted({key for row in labels for key in row}),
            },
            [],
            {"metric": metric, "service_label": service_label},
        )

    window = f"{max(30, int(window_seconds))}s"
    try:
        total = _query_sum(f"sum(increase({metric}[{window}]))")
        errors = _query_sum(f'sum(increase({metric}{{{status_label}=~"5[0-9][0-9]"}}[{window}]))')
    except RuntimeError as exc:
        return ({"status": "error", "metric": metric, "error": str(exc)}, [], {})

    total = max(0.0, total)
    errors = max(0.0, min(errors, total)) if total > 0 else 0.0
    ratio = errors / total if total > 0 else None
    service_errors = _service_error_counts(metric, status_label, service_label, window) if errors > 0 else []
    impacted_service = service_errors[0]["service"] if service_errors else None

    check: dict[str, Any] = {
        "status": "ok" if total >= min_requests else "insufficient_traffic",
        "metric": metric,
        "status_label": status_label,
        "service_label": service_label,
        "window_seconds": window_seconds,
        "request_count": round(total, 3),
        "http_5xx_count": round(errors, 3),
        "error_rate": round(ratio, 6) if ratio is not None else None,
        "threshold": threshold,
        "minimum_requests": min_requests,
    }
    incidents: list[dict[str, Any]] = []
    if total >= min_requests and ratio is not None and ratio >= threshold:
        incidents.append({
            "id": f"http_5xx_rate:{impacted_service or 'global'}",
            "kind": "http_5xx_error_rate_high",
            "title": "HTTP 5xx error rate exceeds the configured threshold",
            "severity": "critical" if ratio >= max(0.20, threshold * 3) else "warning",
            "service": impacted_service,
            "observed_value": round(ratio, 6),
            "unit": "ratio",
            "threshold": threshold,
            "window_seconds": window_seconds,
            "evidence": {
                "metric": metric,
                "status_label": status_label,
                "request_count": round(total, 3),
                "http_5xx_count": round(errors, 3),
                "service_error_counts": service_errors[:5],
            },
        })
    return check, incidents, {"metric": metric, "service_label": service_label, "status_label": status_label}


def _detect_p95_latency(
    metric_names: list[str], window_seconds: int, threshold_ms: float
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    bucket_metric = next((name for name in HTTP_BUCKET_CANDIDATES if name in metric_names), None)
    if bucket_metric is None:
        return (
            {
                "status": "unavailable",
                "reason": "No supported HTTP request-duration histogram was found in Prometheus.",
                "supported_candidates": list(HTTP_BUCKET_CANDIDATES),
            },
            [],
            {},
        )

    try:
        labels = _series_labels(bucket_metric)
    except RuntimeError as exc:
        return ({"status": "error", "metric": bucket_metric, "error": str(exc)}, [], {})
    service_label = _find_service_label(labels)
    group_labels = "le" + (f", {service_label}" if service_label else "")
    window = f"{max(30, int(window_seconds))}s"
    expression = f"histogram_quantile(0.95, sum by ({group_labels}) (rate({bucket_metric}[{window}])))"
    try:
        result = prometheus_query(expression).get("result", [])
    except RuntimeError as exc:
        return ({"status": "error", "metric": bucket_metric, "query": expression, "error": str(exc)}, [], {})

    unit_ms = 1.0 if "milliseconds" in bucket_metric else 1000.0
    measurements: list[dict[str, Any]] = []
    for item in result if isinstance(result, list) else []:
        if not isinstance(item, dict):
            continue
        value = _vector_value(item)
        if value is None or value < 0:
            continue
        metric_labels = item.get("metric", {}) or {}
        service = metric_labels.get(service_label) if service_label else None
        measurements.append({
            "service": str(service) if service else None,
            "p95_latency_ms": round(value * unit_ms, 3),
        })

    if not measurements:
        return (
            {
                "status": "insufficient_data",
                "metric": bucket_metric,
                "query": expression,
                "service_label": service_label,
                "reason": f"No usable p95 value was returned for the last {window_seconds} seconds.",
                "threshold_ms": threshold_ms,
            },
            [],
            {"metric": bucket_metric, "service_label": service_label},
        )

    measurements.sort(key=lambda item: item["p95_latency_ms"], reverse=True)
    check = {
        "status": "ok",
        "metric": bucket_metric,
        "query": expression,
        "service_label": service_label,
        "window_seconds": window_seconds,
        "threshold_ms": threshold_ms,
        "measurements": measurements[:10],
        "max_p95_latency_ms": measurements[0]["p95_latency_ms"],
    }
    incidents = []
    for measurement in measurements:
        observed = measurement["p95_latency_ms"]
        if observed < threshold_ms:
            continue
        service = measurement["service"]
        incidents.append({
            "id": f"http_p95_latency:{service or 'global'}",
            "kind": "http_p95_latency_high",
            "title": "HTTP p95 request latency exceeds the configured threshold",
            "severity": "critical" if observed >= threshold_ms * 2 else "warning",
            "service": service,
            "observed_value": observed,
            "unit": "milliseconds",
            "threshold": threshold_ms,
            "window_seconds": window_seconds,
            "evidence": {
                "metric": bucket_metric,
                "promql": expression,
                "p95_latency_ms": observed,
            },
        })
    return check, incidents, {"metric": bucket_metric, "service_label": service_label}


def _parse_metric_checks(
    error_check: dict[str, Any], latency_check: dict[str, Any]
) -> str:
    statuses = [error_check.get("status"), latency_check.get("status")]
    available_count = sum(status == "ok" for status in statuses)
    if available_count == 2:
        return "ok"
    if available_count == 1:
        return "partial"
    if "error" in statuses:
        return "error"
    return "unavailable"


def detect_metric_incidents(
    error_rate_threshold: float = DEFAULT_ERROR_RATE_THRESHOLD,
    p95_latency_threshold_ms: float = DEFAULT_P95_LATENCY_THRESHOLD_MS,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
    min_requests: float = DEFAULT_MIN_REQUESTS,
) -> dict[str, Any]:
    """Evaluate threshold-based incident rules using Prometheus only."""
    base = {
        "component": "eyes",
        "mode": "incident_detection",
        "evaluated_at": iso_utc(),
        "window_seconds": window_seconds,
        "thresholds": {
            "http_5xx_error_rate": error_rate_threshold,
            "http_p95_latency_ms": p95_latency_threshold_ms,
            "minimum_requests_for_error_rate": min_requests,
        },
    }
    try:
        names = prometheus_metric_names()
    except Exception as exc:
        return {
            **base,
            "status": "error",
            "error": f"Could not discover Prometheus metrics: {exc}",
            "checks": {},
            "incidents": [],
        }

    error_check, error_incidents, _ = _detect_http_error_rate(names, window_seconds, error_rate_threshold, min_requests)
    latency_check, latency_incidents, _ = _detect_p95_latency(names, window_seconds, p95_latency_threshold_ms)
    incidents = error_incidents + latency_incidents
    status = _parse_metric_checks(error_check, latency_check)
    if incidents:
        summary = f"Detected {len(incidents)} threshold breach(es); targeted investigation should start."
    elif status == "ok":
        summary = "No configured HTTP error-rate or p95-latency threshold is currently breached."
    elif status == "partial":
        summary = "Only some thresholds could be evaluated. Inspect per-check status; this is not a full green result."
    elif status == "unavailable":
        summary = "Threshold detection is unavailable: no compatible request metrics were found. Do not interpret this as a healthy result."
    else:
        summary = "Threshold checks encountered an error; see individual check details."
    return {
        **base,
        "status": status,
        "summary": summary,
        "discovered_metric_name_count": len(names),
        "checks": {"http_5xx_error_rate": error_check, "http_p95_latency": latency_check},
        "incidents": incidents,
    }


def collect_jaeger(service_name: str = "frontend", lookback_seconds: int = 3600, search_depth: int = 5) -> dict[str, Any]:
    """Collect service names and recent trace summaries from Jaeger API v3 via proxy."""
    services_url = f"{JAEGER_URL}/api/v3/services"
    services_response = request_json(services_url)
    services = services_response.get("services", [])
    if not isinstance(services, list):
        raise RuntimeError("Jaeger API v3 /services response had an unexpected format")

    now = utc_now()
    start = now.timestamp() - max(30, lookback_seconds)
    start_rfc3339 = datetime.fromtimestamp(start, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    end_rfc3339 = now.isoformat(timespec="seconds").replace("+00:00", "Z")
    traces_query = urlencode({
        "query.service_name": service_name,
        "query.start_time_min": start_rfc3339,
        "query.start_time_max": end_rfc3339,
        "query.search_depth": max(1, min(search_depth, 20)),
    })
    trace_summaries_url = f"{JAEGER_URL}/api/v3/trace-summaries?{traces_query}"
    trace_note = None
    recent_traces: list[dict[str, Any]] = []
    try:
        response_chunks = request_json_stream(trace_summaries_url)
        summaries: list[dict[str, Any]] = []
        for chunk in response_chunks:
            if not isinstance(chunk, dict):
                continue
            chunk_summaries = chunk.get("summaries")
            if chunk_summaries is None and isinstance(chunk.get("result"), dict):
                chunk_summaries = chunk["result"].get("summaries")
            if chunk_summaries is None and isinstance(chunk.get("data"), dict):
                chunk_summaries = chunk["data"].get("summaries")
            if isinstance(chunk_summaries, list):
                summaries.extend(item for item in chunk_summaries if isinstance(item, dict))

        for item in summaries:
            start_ns = item.get("minStartTimeUnixNano")
            end_ns = item.get("maxEndTimeUnixNano")
            try:
                duration_ms = max(0, (int(end_ns) - int(start_ns)) / 1_000_000) if start_ns is not None and end_ns is not None else None
            except (TypeError, ValueError):
                duration_ms = None
            service_summaries = item.get("services", []) or []
            service_names = sorted({
                str(service.get("name"))
                for service in service_summaries
                if isinstance(service, dict) and service.get("name")
            })
            root_service = item.get("rootServiceName")
            if root_service and root_service not in service_names:
                service_names.append(str(root_service))
            recent_traces.append({
                "trace_id": item.get("traceId"),
                "root_service": root_service,
                "root_operation": item.get("rootOperationName"),
                "span_count": item.get("spanCount"),
                "error_span_count": item.get("errorSpanCount", 0),
                "duration_ms": round(duration_ms, 3) if duration_ms is not None else None,
                "services": sorted(service_names),
            })
    except RuntimeError as exc:
        trace_note = f"Recent trace search unavailable: {exc}"

    return {
        "status": "ok",
        "endpoint": services_url,
        "service_count": len(services),
        "services": services[:50],
        "queried_service": service_name,
        "lookback_seconds": lookback_seconds,
        "recent_trace_query_endpoint": trace_summaries_url,
        "recent_trace_count": len(recent_traces),
        "recent_traces": recent_traces,
        "note": trace_note,
    }


def collect_prometheus() -> dict[str, Any]:
    response = request_json(f"{PROMETHEUS_URL}/api/v1/label/__name__/values")
    if response.get("status") != "success":
        raise RuntimeError("Prometheus metric discovery failed")
    names = response.get("data", [])
    if not isinstance(names, list):
        raise RuntimeError("Prometheus metric-name response had an unexpected format")
    samples: dict[str, Any] = {}
    for name in ("container_uptime_seconds", "container_memory_usage_total_bytes", "container_cpu_usage_nanoseconds_total"):
        if name not in names:
            samples[name] = {"available": False, "series_count": 0}
            continue
        try:
            data = prometheus_query(name)
            results = data.get("result", [])
            samples[name] = {"available": True, "series_count": len(results) if isinstance(results, list) else 0}
        except RuntimeError as exc:
            samples[name] = {"available": True, "query_error": str(exc)}
    return {
        "status": "ok",
        "endpoint": PROMETHEUS_URL,
        "metric_name_count": len(names),
        "sample_metric_names": names[:30],
        "sample_series": samples,
    }


def _first_value(source: dict[str, Any], keys: tuple[str, ...]) -> Any:
    for key in keys:
        value = source.get(key)
        if value not in (None, ""):
            return value
    return None


def _normalise_log(hit: dict[str, Any]) -> dict[str, Any]:
    source = hit.get("_source", {}) or {}
    resource = source.get("resource", {}) or {}
    source_attributes = source.get("attributes", {}) or {}
    resource_attributes = source.get("resourceAttributes", {}) or {}
    scope = source.get("instrumentationScope", {}) or {}
    service_name = (
        resource.get("service.name")
        or source.get("service.name")
        or resource_attributes.get("service.name")
        or source_attributes.get("service.name")
        or scope.get("name")
    )
    severity_obj = source.get("severity")
    if isinstance(severity_obj, dict):
        severity = severity_obj.get("text")
        severity_number = severity_obj.get("number")
    else:
        severity = severity_obj or source.get("severity_text") or source.get("severityText")
        severity_number = source.get("severity_number") or source.get("severityNumber")
    message = _first_value(source, ("body", "message", "log"))
    if isinstance(message, dict):
        message = message.get("stringValue") or message.get("text") or message.get("value") or json.dumps(message)
    return {
        "timestamp": source.get("@timestamp") or source.get("time") or source.get("timestamp"),
        "service": service_name,
        "severity": severity,
        "severity_number": severity_number,
        "message": str(message)[:400] if message is not None else None,
        "trace_id": source.get("traceId") or source.get("trace_id"),
        "span_id": source.get("spanId") or source.get("span_id"),
        "index": hit.get("_index"),
    }


def collect_opensearch_logs(service_name: str | None = None, size: int = 5) -> dict[str, Any]:
    """Collect recent logs; on incidents, focus on a service when OpenSearch mappings allow it."""
    url = f"{OPENSEARCH_URL}/{LOGS_INDEX}/_search"
    query: dict[str, Any] = {"match_all": {}}
    if service_name:
        query = {
            "bool": {
                "should": [
                    {"term": {"resource.service.name.keyword": service_name}},
                    {"term": {"resource.service.name": service_name}},
                    {"term": {"instrumentationScope.name.keyword": service_name}},
                    {"term": {"instrumentationScope.name": service_name}},
                ],
                "minimum_should_match": 1,
            }
        }
    body = {
        "size": max(1, min(size, 100)),
        "track_total_hits": True,
        "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
        "query": query,
    }
    response = request_json(url, method="POST", body=body)
    hits_block = response.get("hits", {}) or {}
    total_block = hits_block.get("total", 0)
    total = total_block.get("value", 0) if isinstance(total_block, dict) else total_block
    relation = total_block.get("relation", "eq") if isinstance(total_block, dict) else "eq"
    hits = hits_block.get("hits", []) or []
    filter_method = "opensearch_query"

    # Some OpenSearch mappings flatten resource attributes differently. If an exact
    # service filter finds nothing, inspect a bounded recent sample and filter locally.
    if service_name and not hits:
        fallback_body = {
            "size": 100,
            "track_total_hits": False,
            "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
            "query": {"match_all": {}},
        }
        fallback = request_json(url, method="POST", body=fallback_body)
        candidates = (fallback.get("hits", {}) or {}).get("hits", []) or []
        hits = []
        for hit in candidates:
            normalised = _normalise_log(hit)
            if normalised.get("service") == service_name:
                hits.append(hit)
            if len(hits) >= size:
                break
        total = None  # We have only filtered a bounded sample; don't claim an exact service count.
        relation = "sampled"
        filter_method = "bounded_recent_sample_local_filter"

    docs = [_normalise_log(hit) for hit in hits[:size]]
    return {
        "status": "ok",
        "endpoint": OPENSEARCH_URL,
        "index_pattern": LOGS_INDEX,
        "filter_service": service_name,
        "filter_method": filter_method,
        "matching_document_count": total,
        "count_relation": relation,
        "recent_logs": docs,
    }


def collect_docker() -> dict[str, Any]:
    try:
        proc = subprocess.run(
            ["docker", "ps", "--all", "--format", "{{json .}}"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"Could not run Docker CLI: {exc}") from exc
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout or "docker ps failed").strip())
    containers: list[dict[str, str]] = []
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        containers.append({
            "name": str(item.get("Names", "unknown")),
            "status": str(item.get("Status", "unknown")),
            "image": str(item.get("Image", "unknown")),
        })
    unhealthy = [c for c in containers if "unhealthy" in c["status"].lower()]
    stopped = [c for c in containers if c["status"].lower().startswith(("exited", "dead", "created"))]
    running = [c for c in containers if c["status"].lower().startswith("up ")]
    return {
        "status": "ok",
        "container_count": len(containers),
        "running_count": len(running),
        "unhealthy_count": len(unhealthy),
        "stopped_count": len(stopped),
        "unhealthy_containers": unhealthy,
        "stopped_containers": stopped,
        "containers": containers,
    }


def collect_signal(name: str, collector: Any) -> dict[str, Any]:
    try:
        return collector()
    except Exception as exc:
        return {"status": "error", "error": str(exc), "signal": name}


def _is_demo_container(container: dict[str, Any]) -> bool:
    name = str(container.get("name", "")).lower()
    image = str(container.get("image", "")).lower()
    return (
        name in DEMO_CONTAINER_NAMES
        or name.startswith("opentelemetry-demo-")
        or image.startswith("ghcr.io/open-telemetry/demo:")
        or image.startswith("ghcr.io/open-telemetry/opentelemetry-collector-releases/")
        or image.startswith("quay.io/jaegertracing/jaeger:")
        or image.startswith("quay.io/prometheus/prometheus:")
    )


def add_container_incidents(docker_result: dict[str, Any]) -> list[dict[str, Any]]:
    if docker_result.get("status") != "ok":
        return []
    incidents = []
    for container in docker_result.get("unhealthy_containers", []):
        if not _is_demo_container(container):
            continue
        name = container.get("name")
        incidents.append({
            "id": f"container_unhealthy:{name}",
            "kind": "container_unhealthy",
            "title": "Docker reports an unhealthy container",
            "severity": "critical",
            "service": name,
            "observed_value": container.get("status"),
            "unit": "container_status",
            "threshold": "healthy or no configured health check",
            "window_seconds": None,
            "evidence": {"container": container},
        })
    for container in docker_result.get("stopped_containers", []):
        if not _is_demo_container(container):
            continue
        name = container.get("name")
        incidents.append({
            "id": f"container_stopped:{name}",
            "kind": "container_stopped",
            "title": "Docker reports a stopped or created container",
            "severity": "warning",
            "service": name,
            "observed_value": container.get("status"),
            "unit": "container_status",
            "threshold": "running",
            "window_seconds": None,
            "evidence": {"container": container},
        })
    return incidents


def investigate_incident(incident: dict[str, Any], window_seconds: int) -> dict[str, Any]:
    """Gather focused telemetry only after a detector has produced an incident."""
    target = incident.get("service")
    traces_service = target or "frontend"
    traces = collect_signal(
        "traces",
        lambda: collect_jaeger(service_name=traces_service, lookback_seconds=window_seconds, search_depth=5),
    )
    logs = collect_signal("logs", lambda: collect_opensearch_logs(service_name=target, size=10))
    docker = collect_signal("containers", collect_docker)
    matching_container = None
    related_containers: list[dict[str, Any]] = []
    if docker.get("status") == "ok":
        for container in docker.get("containers", []):
            if target and (container.get("name", "").lower() == str(target).lower()):
                matching_container = container
            elif target and str(target).lower() in container.get("name", "").lower():
                related_containers.append(container)
    return {
        "incident_id": incident.get("id"),
        "trigger": incident,
        "investigation_status": "evidence_collected",
        "diagnosis": "not_attempted_by_eyes; passed to Brain for root-cause analysis",
        "evidence": {
            "traces": traces,
            "logs": logs,
            "container_status": {
                "status": docker.get("status"),
                "error": docker.get("error"),
                "container_count": docker.get("container_count"),
                "running_count": docker.get("running_count"),
                "unhealthy_count": docker.get("unhealthy_count"),
                "stopped_count": docker.get("stopped_count"),
                "target_container": matching_container,
                "related_containers": related_containers[:5],
            },
        },
        "safety_note": "Read-only investigation only; no remediation or configuration changes were made.",
    }


def run_detection_cycle(
    error_rate_threshold: float,
    latency_threshold_ms: float,
    window_seconds: int,
    min_requests: float,
    docker_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    detection = detect_metric_incidents(error_rate_threshold, latency_threshold_ms, window_seconds, min_requests)
    if docker_result is None:
        docker_result = collect_signal("containers", collect_docker)
    extra_incidents = add_container_incidents(docker_result)
    incidents = list(detection.get("incidents", [])) + extra_incidents
    return {
        "component": "eyes",
        "mode": "incident_detection",
        "generated_at": iso_utc(),
        "status": "incident_detected" if incidents else ("monitoring_degraded" if detection.get("status") != "ok" or docker_result.get("status") != "ok" else "no_incident_detected"),
        "detection": detection,
        "container_signal": {
            key: docker_result.get(key)
            for key in ("status", "container_count", "running_count", "unhealthy_count", "stopped_count", "error")
            if key in docker_result
        },
        "incidents": incidents,
        "investigations": [investigate_incident(item, window_seconds) for item in incidents],
        "safety_note": "Evidence collection only: no demo configuration, feature flags, or services were changed.",
    }


def run_snapshot(
    error_rate_threshold: float,
    latency_threshold_ms: float,
    window_seconds: int,
    min_requests: float,
) -> dict[str, Any]:
    detection = detect_metric_incidents(error_rate_threshold, latency_threshold_ms, window_seconds, min_requests)
    signals = {
        "traces": collect_signal("traces", collect_jaeger),
        "metrics": collect_signal("metrics", collect_prometheus),
        "logs": collect_signal("logs", collect_opensearch_logs),
        "containers": collect_signal("containers", collect_docker),
    }
    incidents = list(detection.get("incidents", [])) + add_container_incidents(signals["containers"])
    return {
        "schema_version": "1.1",
        "component": "eyes",
        "mode": "read_only_snapshot",
        "generated_at": iso_utc(),
        "detection": detection,
        "signals": signals,
        "incidents": incidents,
        "investigations": [investigate_incident(item, window_seconds) for item in incidents],
        "safety_note": "Evidence collection only: no demo configuration, feature flags, or services were changed.",
    }


def watch(
    error_rate_threshold: float,
    latency_threshold_ms: float,
    window_seconds: int,
    min_requests: float,
    interval_seconds: float,
) -> int:
    """Continuously poll thresholds and auto-investigate each newly active incident once."""
    active_incident_ids: set[str] = set()
    print(json.dumps({
        "component": "eyes",
        "mode": "watch",
        "status": "started",
        "started_at": iso_utc(),
        "poll_interval_seconds": interval_seconds,
        "note": "Press Ctrl+C to stop. New incidents trigger targeted evidence collection; no actions are executed.",
    }, indent=2))
    try:
        while True:
            detection = detect_metric_incidents(error_rate_threshold, latency_threshold_ms, window_seconds, min_requests)
            docker_result = collect_signal("containers", collect_docker)
            incidents = list(detection.get("incidents", [])) + add_container_incidents(docker_result)
            current_ids = {str(item.get("id")) for item in incidents}
            newly_detected = [item for item in incidents if str(item.get("id")) not in active_incident_ids]
            if newly_detected:
                event = {
                    "component": "eyes",
                    "mode": "watch",
                    "event": "incident_detected",
                    "generated_at": iso_utc(),
                    "detection": detection,
                    "incidents": newly_detected,
                    "investigations": [investigate_incident(item, window_seconds) for item in newly_detected],
                    "safety_note": "Read-only evidence gathering; human approval and the Action API are outside Eyes.",
                }
            else:
                event = {
                    "component": "eyes",
                    "mode": "watch",
                    "event": "poll",
                    "generated_at": iso_utc(),
                    "status": "incident_active" if incidents else ("monitoring_degraded" if detection.get("status") != "ok" or docker_result.get("status") != "ok" else "no_incident_detected"),
                    "threshold_status": detection.get("status"),
                    "checks": detection.get("checks", {}),
                    "active_incident_count": len(incidents),
                    "container_signal": {
                        key: docker_result.get(key)
                        for key in ("status", "container_count", "running_count", "unhealthy_count", "stopped_count", "error")
                        if key in docker_result
                    },
                }
            print(json.dumps(event, ensure_ascii=False), flush=True)
            active_incident_ids = current_ids
            time.sleep(max(2.0, interval_seconds))
    except KeyboardInterrupt:
        print(json.dumps({"component": "eyes", "mode": "watch", "event": "stopped", "stopped_at": iso_utc()}), flush=True)
        return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only incident detection and investigation for OpenTelemetry Demo")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--watch", action="store_true", help="continuously monitor metric thresholds and auto-investigate new incidents")
    modes.add_argument("--once", action="store_true", help="run one detection cycle and investigate automatically if an incident is found")
    modes.add_argument("--snapshot", action="store_true", help="collect a detailed telemetry snapshot (default)")
    parser.add_argument("--interval", type=float, default=DEFAULT_WATCH_INTERVAL, help=f"watch interval in seconds (default: {DEFAULT_WATCH_INTERVAL:g})")
    parser.add_argument("--window-seconds", type=int, default=DEFAULT_WINDOW_SECONDS, help=f"metric rate/latency window in seconds (default: {DEFAULT_WINDOW_SECONDS})")
    parser.add_argument("--error-rate-threshold", type=float, default=DEFAULT_ERROR_RATE_THRESHOLD, help=f"HTTP 5xx ratio threshold, 0-1 (default: {DEFAULT_ERROR_RATE_THRESHOLD})")
    parser.add_argument("--latency-threshold-ms", type=float, default=DEFAULT_P95_LATENCY_THRESHOLD_MS, help=f"p95 HTTP request latency threshold in milliseconds (default: {DEFAULT_P95_LATENCY_THRESHOLD_MS:g})")
    parser.add_argument("--min-requests", type=float, default=DEFAULT_MIN_REQUESTS, help=f"minimum requests before evaluating error rate (default: {DEFAULT_MIN_REQUESTS:g})")
    args = parser.parse_args(argv)

    if not 0 < args.error_rate_threshold <= 1:
        parser.error("--error-rate-threshold must be greater than 0 and at most 1")
    if args.latency_threshold_ms <= 0:
        parser.error("--latency-threshold-ms must be positive")
    if args.window_seconds < 30:
        parser.error("--window-seconds must be at least 30")
    if args.min_requests < 1:
        parser.error("--min-requests must be at least 1")

    if args.watch:
        return watch(args.error_rate_threshold, args.latency_threshold_ms, args.window_seconds, args.min_requests, args.interval)
    if args.once:
        result = run_detection_cycle(args.error_rate_threshold, args.latency_threshold_ms, args.window_seconds, args.min_requests)
    else:
        result = run_snapshot(args.error_rate_threshold, args.latency_threshold_ms, args.window_seconds, args.min_requests)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    if result.get("status") == "monitoring_degraded":
        return 1
    signals = result.get("signals", {})
    failed_signal = any(value.get("status") != "ok" for value in signals.values() if isinstance(value, dict))
    return 1 if failed_signal else 0


if __name__ == "__main__":
    sys.exit(main())
