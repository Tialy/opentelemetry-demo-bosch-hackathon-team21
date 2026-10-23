#!/usr/bin/env python3
"""Team 21 agent tools: the read-only "senses" the Brain can call.

Every tool wraps Eyes (eyes.py) or adds one focused, read-only query on top of it.
Each returns a small JSON-serialisable dict. Nothing here changes the demo.

Safety boundary (same as Eyes):
  * no feature-flag state: PromQL/URLs mentioning flags are refused, flagd services are
    dropped, and feature-flag span attributes/events never reach the LLM
  * Docker is only called with `ps` and `inspect`, and only for demo containers
"""
from __future__ import annotations

import json
import re
import subprocess
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Callable
from urllib.parse import quote, urlencode

import eyes

EXCLUDED_SERVICES = {"flagd", "flagd-ui"}
FORBIDDEN_MARKERS = ("flagd", "feature_flag", "/feature", "flagservice", "ofrep")
ENTRY_SERVICES = ("frontend-proxy", "frontend")


class ToolError(RuntimeError):
    """Raised for bad tool input; the message is shown to the LLM so it can correct itself."""


def _guard(text: str) -> None:
    lowered = text.lower()
    for marker in FORBIDDEN_MARKERS:
        if marker in lowered:
            raise ToolError(f"Refused: feature-flag state is off limits ({marker!r}). Diagnose from telemetry.")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _rfc3339(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _short(value: Any, limit: int = 240) -> str:
    text = " ".join(str(value or "").split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _num(value: Any) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if number == number and abs(number) != float("inf") else None


def _r(value: float | None, digits: int) -> float | None:
    return None if value is None else round(value, digits)


_VARIABLE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|\b[0-9a-f]{12,}\b|\d+(?:\.\d+)?", re.I)


def _normalize(message: str) -> str:
    return _VARIABLE.sub("#", _short(message, 400))[:160]


# ================================================================== alerts (Eyes)
def check_alerts() -> dict[str, Any]:
    """Current threshold breaches (Eyes detector) plus stopped/unhealthy demo containers."""
    detection = eyes.detect_metric_incidents()
    docker = eyes.collect_signal("containers", eyes.collect_docker)
    incidents = list(detection.get("incidents", [])) + eyes.add_container_incidents(docker)
    return {
        "detector_status": detection.get("status"),
        "summary": detection.get("summary"),
        "incidents": [
            {k: item.get(k) for k in ("id", "kind", "service", "observed_value", "unit", "threshold", "severity")}
            for item in incidents
        ],
        "containers": {k: docker.get(k) for k in ("running_count", "stopped_count", "unhealthy_count")},
    }


# ============================================================ metrics (span metrics)
_KIND = "SPAN_KIND_SERVER|SPAN_KIND_CONSUMER|SERVER|CONSUMER"
_ERROR = "STATUS_CODE_ERROR|ERROR|Error"


def _label(name: str) -> str:
    return name if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) else json.dumps(name)


def _sel(metric: str, matchers: list[tuple[str, str, str]]) -> str:
    return "{" + ", ".join([f'__name__="{metric}"'] + [f'{_label(k)}{op}"{v}"' for k, op, v in matchers]) + "}"


def _first(names: list[str], patterns: tuple[str, ...]) -> str | None:
    for pattern in patterns:
        for name in names:
            if re.search(pattern, name):
                return name
    return None


def _by_label(expr: str, label: str) -> dict[str, float | None]:
    result = eyes.prometheus_query(expr).get("result") or []
    return {str((r.get("metric") or {}).get(label, "unknown")): _num((r.get("value") or [None, None])[1]) for r in result}


def service_health(window_minutes: int = 5) -> dict[str, Any]:
    """Per-service request rate, error ratio and p95 latency from span metrics (covers HTTP and gRPC),
    compared with the 30 minutes before the window."""
    window = f"{max(1, int(window_minutes))}m"
    names = [n for n in eyes.prometheus_metric_names() if "flag" not in n.lower()]
    calls = _first(names, (r"^traces_span_metrics_calls_total$", r"span.?metrics.*calls", r"^calls(_total)?$"))
    bucket = _first(names, (r"^traces_span_metrics_duration_.*_bucket$", r"span.?metrics.*duration.*_bucket$"))
    if not calls:
        hints = [n for n in names if re.search(r"span|calls|duration", n)][:20]
        raise ToolError(f"No span-metrics calls metric found. Candidates: {hints}. Use query_promql instead.")
    labels = eyes.request_json(f"{eyes.PROMETHEUS_URL}/api/v1/labels?{urlencode({'match[]': _sel(calls, [])})}").get("data") or []
    svc = next((l for l in ("service_name", "service.name", "job") if l in labels), None)
    status = next((l for l in ("status_code", "status.code") if l in labels), None)
    kind = next((l for l in ("span_kind", "span.kind") if l in labels), None)
    if not svc:
        raise ToolError(f"Span metrics have no service label (labels: {labels}).")
    by = _label(svc)
    kind_m = [(kind, "=~", _KIND)] if kind else []
    queries = {
        "requests": f"sum by ({by}) (rate({_sel(calls, kind_m)}[{window}]))",
        "baseline_requests": f"sum by ({by}) (rate({_sel(calls, kind_m)}[30m] offset {window}))",
    }
    if status:
        err = _sel(calls, kind_m + [(status, "=~", _ERROR)])
        queries["errors"] = f"sum by ({by}) (rate({err}[{window}]))"
        queries["baseline_errors"] = f"sum by ({by}) (rate({err}[30m] offset {window}))"
    if bucket:
        b = _sel(bucket, kind_m)
        queries["p95"] = f"histogram_quantile(0.95, sum by ({by}, le) (rate({b}[{window}])))"
        queries["baseline_p95"] = f"histogram_quantile(0.95, sum by ({by}, le) (rate({b}[30m] offset {window})))"
    data = {key: _by_label(expr, svc) for key, expr in queries.items()}
    to_ms = 1000.0 if bucket and "second" in bucket and "milli" not in bucket else 1.0

    rows = {}
    for raw in sorted(set().union(*(set(v) for v in data.values()))):
        name = raw.split("/", 1)[-1] if svc == "job" else raw
        if name in EXCLUDED_SERVICES:
            continue
        get = lambda key: data.get(key, {}).get(raw)  # noqa: E731
        req, breq = get("requests"), get("baseline_requests")
        p95, bp95 = get("p95"), get("baseline_p95")
        rows[name] = {
            "req_per_s": _r(req, 3),
            "error_ratio": _r((get("errors") or 0) / req, 4) if req and status else None,
            "baseline_error_ratio": _r((get("baseline_errors") or 0) / breq, 4) if breq and status else None,
            "p95_ms": _r(p95 * to_ms, 1) if p95 is not None else None,
            "baseline_p95_ms": _r(bp95 * to_ms, 1) if bp95 is not None else None,
        }
    ordered = dict(sorted(rows.items(), key=lambda kv: (kv[1]["error_ratio"] or 0, kv[1]["p95_ms"] or 0), reverse=True))
    return {"window": window, "baseline": "30m before the window", "services": ordered,
            "error_query": queries.get("errors"), "p95_query": queries.get("p95")}


def query_promql(query: str) -> dict[str, Any]:
    """Run any read-only instant PromQL query (max 25 series returned)."""
    if not query or not query.strip():
        raise ToolError("query must be a non-empty PromQL expression")
    _guard(query)
    result = eyes.prometheus_query(query).get("result") or []
    series = []
    for item in result[:25]:
        labels = {k: v for k, v in (item.get("metric") or {}).items()
                  if k in ("__name__", "service_name", "job", "span_name", "status_code", "http_response_status_code",
                           "rpc_grpc_status_code", "span_kind", "container_name", "name", "le")}
        series.append({"labels": labels, "value": _r(_num((item.get("value") or [None, None])[1]), 4)})
    return {"query": query, "series_count": len(result), "series": series}


def list_metrics(contains: str = "") -> dict[str, Any]:
    """Metric names in Prometheus containing a substring (max 60)."""
    names = [n for n in eyes.prometheus_metric_names() if "flag" not in n.lower()]
    if contains:
        names = [n for n in names if contains.lower() in n.lower()]
    return {"match_count": len(names), "names": names[:60]}


# ===================================================================== traces
_ATTR_PREFIXES = ("http.", "url.", "rpc.", "db.", "server.", "peer.", "net.peer", "network.peer",
                  "messaging.", "error.", "exception.", "app.")


def _any(value: Any) -> Any:
    if not isinstance(value, dict):
        return value
    for key in ("stringValue", "boolValue", "doubleValue"):
        if key in value:
            return value[key]
    if "intValue" in value:
        return _num(value["intValue"])
    if "arrayValue" in value:
        return [_any(v) for v in (value["arrayValue"] or {}).get("values") or []]
    return None


def _attrs(items: Any) -> dict[str, Any]:
    return {str(i["key"]): _any(i.get("value")) for i in items or [] if isinstance(i, dict) and "key" in i}


def _parse_spans(payload: Any) -> list[dict[str, Any]]:
    """Jaeger api_v3 OTLP JSON -> flat span list (feature-flag data dropped)."""
    root = payload.get("result", payload) if isinstance(payload, dict) else {}
    spans = []
    for rs in (root or {}).get("resourceSpans") or []:
        service = str(_attrs((rs.get("resource") or {}).get("attributes")).get("service.name") or "unknown")
        if service in EXCLUDED_SERVICES:
            continue
        for scope in rs.get("scopeSpans") or []:
            for sp in scope.get("spans") or []:
                attrs = _attrs(sp.get("attributes"))
                start, end = int(sp.get("startTimeUnixNano") or 0), int(sp.get("endTimeUnixNano") or 0)
                exception = None
                for ev in sp.get("events") or []:
                    ev_attrs = _attrs(ev.get("attributes"))
                    if ev.get("name") == "exception" or "exception.message" in ev_attrs:
                        exception = ev_attrs.get("exception.message") or ev_attrs.get("exception.type")
                        break
                status = sp.get("status") or {}
                spans.append({
                    "trace_id": sp.get("traceId"),
                    "span_id": sp.get("spanId"),
                    "parent": sp.get("parentSpanId") or None,
                    "service": service,
                    "name": sp.get("name"),
                    "start": start,
                    "duration_ms": round((end - start) / 1e6, 2) if start and end >= start else None,
                    "error": status.get("code") in (2, "STATUS_CODE_ERROR", "ERROR"),
                    "message": _short(exception or status.get("message") or "", 300) or None,
                    "attributes": {k: (_short(v, 150) if isinstance(v, str) else v) for k, v in attrs.items()
                                   if k.startswith(_ATTR_PREFIXES) and "flag" not in k.lower()},
                })
    return spans


def _search_spans(service: str, lookback_minutes: int, limit: int) -> list[dict[str, Any]]:
    end = _now()
    params = {
        "query.service_name": service,
        "query.start_time_min": _rfc3339(end - timedelta(minutes=lookback_minutes)),
        "query.start_time_max": _rfc3339(end),
        "query.search_depth": limit,
    }
    try:
        payload = eyes.request_json(f"{eyes.JAEGER_URL}/api/v3/traces?{urlencode(params)}")
    except RuntimeError as exc:
        if "HTTP 404" in str(exc):  # api_v3: "No traces found"
            return []
        raise
    return _parse_spans(payload)


def find_error_origins(service: str = "", lookback_minutes: int = 15) -> dict[str, Any]:
    """Sample recent traces through `service` (default: the entry point) and report where errors START
    (failing spans with no failing children), errors per service, and the slowest operations by self time."""
    _guard(service or "")
    if not service:
        services = eyes.request_json(f"{eyes.JAEGER_URL}/api/v3/services").get("services") or []
        service = next((s for s in ENTRY_SERVICES if s in services), "frontend")
    spans = _search_spans(service, max(1, int(lookback_minutes)), 30)
    by_trace: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for span in spans:
        by_trace[span["trace_id"]].append(span)

    origins: dict[tuple, dict[str, Any]] = {}
    errors_by_service: Counter[str] = Counter()
    self_ms: dict[tuple, list[float]] = defaultdict(list)
    for trace_id, trace in by_trace.items():
        ids = {s["span_id"] for s in trace}
        children: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for s in trace:
            if s["parent"] in ids:
                children[s["parent"]].append(s)
        for s in trace:
            if s["error"]:
                errors_by_service[s["service"]] += 1
                if not any(c["error"] for c in children[s["span_id"]]):
                    key = (s["service"], s["name"], _normalize(s["message"] or ""))
                    o = origins.setdefault(key, {"service": s["service"], "operation": s["name"],
                                                 "message": s["message"], "error_spans": 0, "trace_ids": [],
                                                 "sample_attributes": s["attributes"]})
                    o["error_spans"] += 1
                    if trace_id not in o["trace_ids"]:
                        o["trace_ids"].append(trace_id)
            if s["duration_ms"] is not None:
                child = sum(c["duration_ms"] or 0 for c in children[s["span_id"]])
                self_ms[(s["service"], s["name"])].append(max(s["duration_ms"] - child, 0.0))

    origin_rows = sorted(origins.values(), key=lambda o: (len(o["trace_ids"]), o["error_spans"]), reverse=True)[:5]
    for o in origin_rows:
        o["trace_count"] = len(o["trace_ids"])
        o["sample_trace_ids"] = o.pop("trace_ids")[:3]
    slow = sorted(({"service": k[0], "operation": k[1], "spans": len(v), "avg_self_ms": round(sum(v) / len(v), 1),
                    "max_self_ms": round(max(v), 1)} for k, v in self_ms.items()),
                  key=lambda row: row["avg_self_ms"], reverse=True)[:5]
    return {
        "searched_service": service,
        "lookback_minutes": lookback_minutes,
        "traces_sampled": len(by_trace),
        "traces_with_errors": sum(1 for t in by_trace.values() if any(s["error"] for s in t)),
        "error_spans_by_service": dict(errors_by_service.most_common()),
        "error_origins": origin_rows,
        "slowest_operations_by_self_time": slow,
    }


def get_trace(trace_id: str) -> dict[str, Any]:
    """One trace as an indented span tree: who called whom, durations, which spans failed and why."""
    if not re.fullmatch(r"[0-9a-fA-F]{16,32}", trace_id or ""):
        raise ToolError("trace_id must be the 32-character hex id exactly as returned by another tool")
    try:
        payload = eyes.request_json(f"{eyes.JAEGER_URL}/api/v3/traces/{quote(trace_id)}")
    except RuntimeError as exc:
        if "HTTP 404" in str(exc):
            return {"trace_id": trace_id, "found": False}
        raise
    spans = _parse_spans(payload)
    ids = {s["span_id"] for s in spans}
    children: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for s in spans:
        if s["parent"] in ids:
            children[s["parent"]].append(s)
    rows: list[dict[str, Any]] = []

    def walk(span: dict[str, Any], depth: int) -> None:
        if len(rows) >= 60:
            return
        rows.append({"depth": depth, "service": span["service"], "operation": span["name"],
                     "duration_ms": span["duration_ms"], "error": span["error"], "message": span["message"],
                     **({"attributes": span["attributes"]} if span["error"] and span["attributes"] else {})})
        for child in sorted(children[span["span_id"]], key=lambda c: c["start"]):
            walk(child, depth + 1)

    for root in sorted((s for s in spans if s["parent"] not in ids), key=lambda s: s["start"]):
        walk(root, 0)
    return {"trace_id": trace_id, "found": bool(spans), "span_count": len(spans),
            "error_spans": sum(1 for s in spans if s["error"]), "spans": rows, "truncated": len(rows) < len(spans)}


# ======================================================================= logs
_ERROR_SEVERITIES = {"ERROR", "ERR", "FATAL", "CRITICAL", "CRIT", "PANIC", "ALERT", "EMERG"}
_ERROR_WORDS = re.compile(r"\b(error|exception|fail(?:ed|ure|ing)?|fatal|panic|timeout|timed out|refused|unavailable)\b", re.I)


def _is_error(log: dict[str, Any]) -> bool:
    severity = str(log.get("severity") or "").upper()
    try:
        number = int(log.get("severity_number") or 0)
    except (TypeError, ValueError):
        number = 0
    return severity in _ERROR_SEVERITIES or number >= 17 or bool(_ERROR_WORDS.search(log.get("message") or ""))


def search_logs(service: str = "", errors_only: bool = True, contains: str = "", limit: int = 15) -> dict[str, Any]:
    """Newest log records (optionally one service, errors only, containing text), grouped by message."""
    _guard(service or "")
    raw = eyes.collect_opensearch_logs(service_name=service or None, size=100)
    logs = [l for l in raw.get("recent_logs", []) if l.get("service") not in EXCLUDED_SERVICES]
    if service:
        logs = [l for l in logs if l.get("service") in (service, None)]
    if errors_only:
        logs = [l for l in logs if _is_error(l)]
    if contains:
        logs = [l for l in logs if contains.lower() in (l.get("message") or "").lower()]
    groups: dict[tuple, dict[str, Any]] = {}
    for log in logs:
        key = (log.get("service"), _normalize(log.get("message") or ""))
        g = groups.setdefault(key, {"service": log.get("service"), "message": _short(log.get("message"), 300),
                                    "count": 0, "latest": log.get("timestamp"), "sample_trace_id": log.get("trace_id")})
        g["count"] += 1
    limit = max(1, min(int(limit), 30))
    return {
        "service_filter": service or None,
        "errors_only": errors_only,
        "scanned_recent_logs": len(raw.get("recent_logs", [])),
        "matching_logs": len(logs),
        "message_groups": sorted(groups.values(), key=lambda g: g["count"], reverse=True)[:8],
        "latest": [{k: l.get(k) for k in ("timestamp", "service", "severity", "message", "trace_id")}
                   for l in logs[:limit]],
    }


# ================================================================= containers
def _docker(args: list[str]) -> str:
    if args[0] not in ("ps", "inspect"):
        raise ToolError("only docker ps / inspect are allowed")
    proc = subprocess.run(["docker", *args], capture_output=True, encoding="utf-8", errors="replace",
                          timeout=30, check=False)
    if proc.returncode != 0 and not proc.stdout.strip():
        raise ToolError((proc.stderr or "docker failed").strip()[:300])
    return proc.stdout


def _demo_names() -> list[str]:
    docker = eyes.collect_docker()
    return [c["name"] for c in docker.get("containers", []) if eyes._is_demo_container(c)]


def _inspect(names: list[str]) -> list[dict[str, Any]]:
    out = _docker(["inspect", *names]) if names else "[]"
    try:
        return json.loads(out) or []
    except json.JSONDecodeError:
        return []


def container_details(name: str) -> dict[str, Any]:
    """State, health, restart count, exit code, OOM kill, start/finish times and memory limit of one demo container."""
    names = _demo_names()
    if name not in names:
        raise ToolError(f"{name!r} is not a demo container. Known: {sorted(names)}")
    item = (_inspect([name]) or [{}])[0]
    state = item.get("State") or {}
    health = state.get("Health") or {}
    return {
        "name": name,
        "state": state.get("Status"),
        "health": health.get("Status"),
        "last_health_check": _short((health.get("Log") or [{}])[-1].get("Output"), 200) if health.get("Log") else None,
        "restart_count": item.get("RestartCount"),
        "exit_code": state.get("ExitCode"),
        "oom_killed": state.get("OOMKilled"),
        "error": state.get("Error") or None,
        "started_at": state.get("StartedAt"),
        "finished_at": state.get("FinishedAt") if not str(state.get("FinishedAt", "")).startswith("0001") else None,
        "image": (item.get("Config") or {}).get("Image"),
        "memory_limit_mb": round(((item.get("HostConfig") or {}).get("Memory") or 0) / 2**20) or None,
    }


def deploy_history(limit: int = 10) -> dict[str, Any]:
    """Demo containers ordered by most recent (re)start, with image and restart count."""
    rows = []
    for item in _inspect(_demo_names()):
        state = item.get("State") or {}
        rows.append({"name": str(item.get("Name", "")).lstrip("/"), "state": state.get("Status"),
                     "started_at": state.get("StartedAt"), "restart_count": item.get("RestartCount"),
                     "image": (item.get("Config") or {}).get("Image")})
    rows.sort(key=lambda r: r["started_at"] or "", reverse=True)
    return {"containers": rows[: max(1, min(int(limit), 30))], "total": len(rows)}


# ================================================================ registry
TOOLS: dict[str, tuple[Callable[..., dict[str, Any]], str, dict[str, Any]]] = {
    "check_alerts": (check_alerts,
                     "Current threshold breaches from the Eyes detector and stopped/unhealthy containers.",
                     {}),
    "service_health": (service_health,
                       "Per-service request rate, error ratio and p95 latency (HTTP and gRPC services), with a 30-minute "
                       "baseline. Best first look at which services are affected.",
                       {"window_minutes": {"type": "integer", "description": "rate window, default 5"}}),
    "find_error_origins": (find_error_origins,
                           "Samples recent traces and reports where errors START (failing spans with no failing "
                           "children), error spans per service and the slowest operations by self time. "
                           "Use the entry point (empty service) or an affected service.",
                           {"service": {"type": "string", "description": "service to search, empty = entry point"},
                            "lookback_minutes": {"type": "integer", "description": "default 15"}}),
    "get_trace": (get_trace,
                  "One trace as a call tree with durations and error messages. Use a trace id from another tool.",
                  {"trace_id": {"type": "string", "description": "32-char hex trace id"}}),
    "search_logs": (search_logs,
                    "Newest log records, optionally for one service, errors only, or containing text; grouped by message.",
                    {"service": {"type": "string"}, "errors_only": {"type": "boolean", "description": "default true"},
                     "contains": {"type": "string"}, "limit": {"type": "integer", "description": "default 15"}}),
    "container_details": (container_details,
                          "Docker state of one demo container: running/exited, health, restarts, exit code, OOM kill.",
                          {"name": {"type": "string", "description": "container name, e.g. cart"}}),
    "deploy_history": (deploy_history,
                       "Demo containers ordered by most recent (re)start: spot restarts and recent changes.",
                       {"limit": {"type": "integer", "description": "default 10"}}),
    "query_promql": (query_promql,
                     "Run a read-only instant PromQL query for anything the other tools do not cover.",
                     {"query": {"type": "string"}}),
    "list_metrics": (list_metrics,
                     "List Prometheus metric names containing a substring, to build a PromQL query.",
                     {"contains": {"type": "string"}}),
}


def openai_tool_specs() -> list[dict[str, Any]]:
    required = {"get_trace": ["trace_id"], "container_details": ["name"], "query_promql": ["query"]}
    return [
        {"type": "function", "function": {
            "name": name, "description": description,
            "parameters": {"type": "object", "properties": params, "required": required.get(name, [])},
        }}
        for name, (_, description, params) in TOOLS.items()
    ]


def call_tool(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    if name not in TOOLS:
        raise ToolError(f"Unknown tool {name!r}. Available: {sorted(TOOLS)}")
    function, _, params = TOOLS[name]
    clean = {k: v for k, v in (arguments or {}).items() if k in params and v is not None}
    return function(**clean)


if __name__ == "__main__":  # quick manual check: python tools.py service_health '{"window_minutes": 5}'
    import sys
    print(json.dumps(call_tool(sys.argv[1], json.loads(sys.argv[2]) if len(sys.argv) > 2 else {}), indent=2))
