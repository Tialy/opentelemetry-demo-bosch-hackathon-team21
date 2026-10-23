#!/usr/bin/env python3
"""Brain component for the Team 21 incident-response agent.

Analyses an Eyes snapshot and produces a structured incident diagnosis.

Two analysis modes:
1. **Rule-based** (default, zero dependencies): deterministic pattern
   matching against known OpenTelemetry Demo failure scenarios.
2. **LLM-assisted** (``--llm``): sends the snapshot to an OpenAI-compatible
   chat-completions endpoint for deeper reasoning.

The rule-based engine is always run first to produce an initial diagnosis.
When ``--llm`` is enabled, the rules output is enriched with LLM reasoning.

Usage (from the repository root)::

    # Rule-based only (no API key needed)
    python team21_agent/brain.py

    # LLM-assisted (requires an OpenAI-compatible endpoint)
    $env:LLM_BASE_URL = "https://api.openai.com/v1"
    $env:API_KEY = "sk-..."
    python team21_agent/brain.py --llm

    # Analyse a previously-saved snapshot file
    python team21_agent/brain.py --snapshot snapshot.json

    # Pretty-print a human-readable report instead of JSON
    python team21_agent/brain.py --report
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import textwrap
from datetime import datetime, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def _load_dotenv() -> None:
    """Load key-value pairs from .env or team21_agent/.env if present."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(base_dir, ".env"),
        os.path.join(os.path.dirname(base_dir), ".env"),
    ]
    for env_path in candidates:
        if os.path.isfile(env_path):
            try:
                with open(env_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and "=" in line:
                            k, v = line.split("=", 1)
                            k, v = k.strip(), v.strip().strip('"').strip("'")
                            if k and k not in os.environ:
                                os.environ[k] = v
            except Exception:
                pass


_load_dotenv()

# ---------------------------------------------------------------------------
# Import the Eyes collector (same package)
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from eyes import main as eyes_main, collect_signal, collect_jaeger, \
    collect_prometheus, collect_opensearch_logs, collect_docker, \
    collect_snapshot, \
    JAEGER_URL, PROMETHEUS_URL, OPENSEARCH_URL


# ---------------------------------------------------------------------------
# Known feature-flag failure scenarios
# ---------------------------------------------------------------------------

KNOWN_FAILURE_FLAGS: dict[str, dict[str, Any]] = {
    "adFailure": {
        "affected_service": "ad",
        "description": "Ad service returns errors for all ad requests",
        "symptom_patterns": ["ad", "error", "fail"],
    },
    "adHighCpu": {
        "affected_service": "ad",
        "description": "Ad service consumes excessive CPU via busy-loop",
        "symptom_patterns": ["ad", "cpu", "high"],
    },
    "adManualGc": {
        "affected_service": "ad",
        "description": "Ad service triggers full manual garbage collections causing latency spikes",
        "symptom_patterns": ["ad", "gc", "latency"],
    },
    "cartFailure": {
        "affected_service": "cart",
        "description": "Cart service returns errors for a percentage of requests",
        "symptom_patterns": ["cart", "error", "fail"],
    },
    "cartMetricCardinalityOverflow": {
        "affected_service": "cart",
        "description": "Cart service injects trace IDs into metric attributes causing cardinality explosion",
        "symptom_patterns": ["cart", "cardinality", "metric"],
    },
    "emailMemoryLeak": {
        "affected_service": "email",
        "description": "Email service leaks memory on each send, eventually OOM",
        "symptom_patterns": ["email", "memory", "oom", "leak"],
    },
    "imageSlowLoad": {
        "affected_service": "image-provider",
        "description": "Image provider adds artificial delay causing slow page loads",
        "symptom_patterns": ["image", "slow", "latency", "frontend"],
    },
    "intlShippingSlowdown": {
        "affected_service": "shipping",
        "description": "Shipping service adds delay for international quotes",
        "symptom_patterns": ["shipping", "slow", "latency", "international"],
    },
    "kafkaConsumerDead": {
        "affected_service": "fraud-detection",
        "description": "Fraud-detection unsubscribes from Kafka, causing consumer lag to climb",
        "symptom_patterns": ["kafka", "fraud", "consumer", "lag", "dead"],
    },
    "kafkaQueueProblems": {
        "affected_service": "fraud-detection",
        "description": "Fraud-detection consumer is throttled, causing Kafka lag to grow",
        "symptom_patterns": ["kafka", "fraud", "lag", "slow", "queue"],
    },
    "loadGeneratorFloodHomepage": {
        "affected_service": "frontend",
        "description": "Load generator floods frontend with excessive traffic",
        "symptom_patterns": ["frontend", "flood", "load", "traffic"],
    },
    "paymentFailure": {
        "affected_service": "payment",
        "description": "Payment service rejects charge requests for a percentage of orders",
        "symptom_patterns": ["payment", "error", "fail", "charge"],
    },
    "paymentUnreachable": {
        "affected_service": "payment",
        "description": "Payment service is completely unreachable",
        "symptom_patterns": ["payment", "unreachable", "connection", "refused"],
    },
    "productCatalogFailure": {
        "affected_service": "product-catalog",
        "description": "Product catalog fails on a specific product ID (OLJCESPC7Z)",
        "symptom_patterns": ["product", "catalog", "fail", "OLJCESPC7Z"],
    },
    "productCatalogLockContention": {
        "affected_service": "product-catalog",
        "description": "Product catalog triggers database lock contention",
        "symptom_patterns": ["product", "catalog", "lock", "contention", "database"],
    },
    "recommendationCacheFailure": {
        "affected_service": "recommendation",
        "description": "Recommendation service cache fails, forcing DB lookups every time",
        "symptom_patterns": ["recommendation", "cache", "fail"],
    },
    "failedReadinessProbe": {
        "affected_service": "cart",
        "description": "Cart service readiness probe fails",
        "symptom_patterns": ["cart", "readiness", "health", "probe"],
    },
    "aiRunawayAgent": {
        "affected_service": "agent",
        "description": "LLM agent loops tool calls until recursion limit",
        "symptom_patterns": ["agent", "runaway", "loop", "recursion"],
    },
    "aiSlowResponse": {
        "affected_service": "agent",
        "description": "LLM agent responses are artificially delayed",
        "symptom_patterns": ["agent", "slow", "response", "llm"],
    },
}


# ---------------------------------------------------------------------------
# Rule-based analysis engine
# ---------------------------------------------------------------------------

class Finding:
    """A single diagnostic finding from the rule engine."""
    def __init__(self, severity: str, title: str, detail: str,
                 affected_services: list[str],
                 evidence: list[str],
                 possible_flags: list[str] | None = None,
                 recommended_actions: list[str] | None = None):
        self.severity = severity  # P1 / P2 / P3 / P4
        self.title = title
        self.detail = detail
        self.affected_services = affected_services
        self.evidence = evidence
        self.possible_flags = possible_flags or []
        self.recommended_actions = recommended_actions or []

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "affected_services": self.affected_services,
            "evidence": self.evidence,
            "possible_flags": self.possible_flags,
            "recommended_actions": self.recommended_actions,
        }


def _analyze_containers(signal: dict[str, Any]) -> list[Finding]:
    """Check for unhealthy or stopped demo containers."""
    findings: list[Finding] = []
    if signal.get("status") != "ok":
        findings.append(Finding(
            severity="P2",
            title="Container signal unavailable",
            detail=f"Docker status collection failed: {signal.get('error', 'unknown')}",
            affected_services=["docker"],
            evidence=[f"Signal error: {signal.get('error')}"],
        ))
        return findings

    demo_prefixes = (
        "frontend", "cart", "checkout", "payment", "shipping", "email",
        "recommendation", "product-catalog", "ad", "currency", "quote",
        "accounting", "fraud-detection", "image-provider", "load-generator",
        "flagd", "kafka", "otel-collector", "jaeger", "prometheus",
        "opensearch", "grafana", "valkey", "astronomy-db", "opamp-server",
        "telemetry-docs", "flagd-ui",
    )

    unhealthy = signal.get("unhealthy_containers", [])
    stopped = signal.get("stopped_containers", [])

    # Filter to demo containers only
    demo_unhealthy = [c for c in unhealthy
                      if any(c["name"].startswith(p) for p in demo_prefixes)]
    demo_stopped = [c for c in stopped
                    if any(c["name"].startswith(p) for p in demo_prefixes)]

    if demo_unhealthy:
        names = [c["name"] for c in demo_unhealthy]
        findings.append(Finding(
            severity="P1",
            title=f"Unhealthy containers: {', '.join(names)}",
            detail="One or more demo containers are reporting unhealthy status.",
            affected_services=names,
            evidence=[f"{c['name']}: {c['status']}" for c in demo_unhealthy],
            recommended_actions=[f"Investigate and restart {n}" for n in names],
        ))

    if demo_stopped:
        names = [c["name"] for c in demo_stopped]
        findings.append(Finding(
            severity="P1",
            title=f"Stopped containers: {', '.join(names)}",
            detail="One or more demo containers have exited.",
            affected_services=names,
            evidence=[f"{c['name']}: {c['status']}" for c in demo_stopped],
            recommended_actions=[f"Restart {n}" for n in names],
        ))

    return findings


def _analyze_traces(signal: dict[str, Any]) -> list[Finding]:
    """Check Jaeger traces for anomalies."""
    findings: list[Finding] = []
    if signal.get("status") != "ok":
        findings.append(Finding(
            severity="P2",
            title="Trace signal unavailable",
            detail=f"Jaeger query failed: {signal.get('error', 'unknown')}",
            affected_services=["jaeger"],
            evidence=[f"Signal error: {signal.get('error')}"],
        ))
        return findings

    services = signal.get("services", [])
    if not services:
        findings.append(Finding(
            severity="P2",
            title="No services reporting traces",
            detail="Jaeger has zero discovered services — trace pipeline may be broken.",
            affected_services=["otel-collector", "jaeger"],
            evidence=["service_count: 0"],
            recommended_actions=["Check otel-collector is running and forwarding to Jaeger"],
        ))

    expected_services = {
        "frontend", "checkout", "cart", "payment", "shipping",
        "email", "recommendation", "product-catalog", "ad", "currency",
        "quote", "accounting", "fraud-detection",
    }
    if services:
        missing = expected_services - set(services)
        if missing:
            findings.append(Finding(
                severity="P3",
                title=f"Services missing from traces: {', '.join(sorted(missing))}",
                detail="Expected services are not appearing in Jaeger.",
                affected_services=sorted(missing),
                evidence=[f"Missing from Jaeger: {sorted(missing)}"],
                recommended_actions=[f"Check if {s} is running and instrumented" for s in sorted(missing)],
            ))

    trace_count = signal.get("recent_frontend_trace_count", 0)
    if trace_count == 0 and services:
        findings.append(Finding(
            severity="P3",
            title="No recent frontend traces",
            detail="No frontend traces found in the last hour. Load generator may be down.",
            affected_services=["frontend", "load-generator"],
            evidence=["recent_frontend_trace_count: 0"],
            recommended_actions=["Check load-generator is running"],
        ))

    error_traces = signal.get("error_traces", [])
    if error_traces:
        affected = signal.get("affected_error_services", [])
        findings.append(Finding(
            severity="P1" if any(s in ("frontend", "checkout", "payment") for s in affected) else "P2",
            title=f"Error spans detected in {', '.join(affected) or 'services'}",
            detail=f"{len(error_traces)} active trace error(s) discovered in Jaeger.",
            affected_services=affected,
            evidence=[f"Trace {t.get('trace_id', 'unknown')[:12]}: service={t.get('service')}, span={t.get('span_name')}, http={t.get('http_status')}, rpc={t.get('rpc_status')}" for t in error_traces[:3]],
            recommended_actions=[f"Inspect trace spans for {s}" for s in affected],
        ))

    return findings


def _analyze_metrics(signal: dict[str, Any]) -> list[Finding]:
    """Check Prometheus metrics for anomalies."""
    findings: list[Finding] = []
    if signal.get("status") != "ok":
        findings.append(Finding(
            severity="P2",
            title="Metrics signal unavailable",
            detail=f"Prometheus query failed: {signal.get('error', 'unknown')}",
            affected_services=["prometheus"],
            evidence=[f"Signal error: {signal.get('error')}"],
        ))
        return findings

    metric_count = signal.get("metric_name_count", 0)
    if metric_count == 0:
        findings.append(Finding(
            severity="P2",
            title="No metrics in Prometheus",
            detail="Prometheus has zero metric names -- metric pipeline may be broken.",
            affected_services=["otel-collector", "prometheus"],
            evidence=["metric_name_count: 0"],
        ))

    samples = signal.get("sample_series", {})
    for name, info in samples.items():
        if info.get("available") and info.get("series_count", 0) == 0:
            findings.append(Finding(
                severity="P3",
                title=f"Metric {name} has zero series",
                detail=f"Expected container metric '{name}' exists but returns 0 series.",
                affected_services=["otel-collector"],
                evidence=[f"{name}: series_count=0"],
            ))
        if info.get("query_error"):
            findings.append(Finding(
                severity="P3",
                title=f"Metric query error for {name}",
                detail=info["query_error"],
                affected_services=["prometheus"],
                evidence=[f"{name}: {info['query_error']}"],
            ))

    low_uptime = signal.get("low_uptime_containers", [])
    if low_uptime:
        cnames = [item["container"] for item in low_uptime]
        findings.append(Finding(
            severity="P2",
            title=f"Low container uptime: {', '.join(cnames)}",
            detail="One or more demo containers have uptime < 300s, indicating a recent restart or crash-loop.",
            affected_services=cnames,
            evidence=[f"{item['container']}: uptime={item['uptime_seconds']:.1f}s" for item in low_uptime],
            recommended_actions=[f"Check logs and health of {n}" for n in cnames],
        ))

    return findings


def _analyze_logs(signal: dict[str, Any]) -> list[Finding]:
    """Check OpenSearch logs for error patterns."""
    findings: list[Finding] = []
    if signal.get("status") != "ok":
        findings.append(Finding(
            severity="P3",
            title="Logs signal unavailable",
            detail=f"OpenSearch query failed: {signal.get('error', 'unknown')}",
            affected_services=["opensearch"],
            evidence=[f"Signal error: {signal.get('error')}"],
        ))
        return findings

    doc_count = signal.get("matching_document_count", 0)
    if doc_count == 0:
        findings.append(Finding(
            severity="P3",
            title="No log documents in OpenSearch",
            detail="OpenSearch has zero log documents -- log pipeline may be broken.",
            affected_services=["otel-collector", "opensearch"],
            evidence=["matching_document_count: 0"],
        ))

    err_logs = signal.get("recent_error_logs", [])
    if not err_logs:
        err_logs = [log for log in signal.get("recent_logs", [])
                    if (log.get("severity") or "").upper() in ("ERROR", "FATAL", "CRITICAL")]
    if err_logs:
        from collections import defaultdict
        grouped = defaultdict(list)
        for log in err_logs:
            svc = log.get("service") or "unknown"
            grouped[svc].append(log)

        for svc, logs_list in grouped.items():
            possible = [flag_name for flag_name, flag_info in KNOWN_FAILURE_FLAGS.items()
                        if flag_info["affected_service"] == svc]
            sample_msg = logs_list[0].get("message") or "(no message)"
            findings.append(Finding(
                severity="P2",
                title=f"Error logs in {svc} ({len(logs_list)} events)",
                detail=sample_msg[:200],
                affected_services=[svc],
                evidence=[f"[{l.get('timestamp')}] {l.get('severity')}: {str(l.get('message'))[:100]}" for l in logs_list[:3]],
                possible_flags=possible,
                recommended_actions=[f"Investigate application errors in {svc}"],
            ))

    return findings


def _correlate_flags(findings: list[Finding]) -> None:
    """Enrich findings with possible feature-flag root causes."""
    for finding in findings:
        if finding.possible_flags:
            continue
        for svc in finding.affected_services:
            for flag_name, flag_info in KNOWN_FAILURE_FLAGS.items():
                if flag_info["affected_service"] == svc:
                    finding.possible_flags.append(flag_name)


def _overall_severity(findings: list[Finding]) -> str:
    """Return the highest (most severe) level across all findings."""
    if not findings:
        return "OK"
    levels = {"P1": 1, "P2": 2, "P3": 3, "P4": 4}
    best = min(findings, key=lambda f: levels.get(f.severity, 99))
    return best.severity


def rule_based_analysis(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Run all rule-based checks and return a diagnosis dict with root cause and confidence."""
    signals = snapshot.get("signals", {})
    findings: list[Finding] = []

    findings.extend(_analyze_containers(signals.get("containers", {})))
    findings.extend(_analyze_traces(signals.get("traces", {})))
    findings.extend(_analyze_metrics(signals.get("metrics", {})))
    findings.extend(_analyze_logs(signals.get("logs", {})))
    _correlate_flags(findings)

    severity = _overall_severity(findings)
    all_affected = sorted({s for f in findings for s in f.affected_services})
    all_flags = sorted({fl for f in findings for fl in f.possible_flags})

    levels = {"P1": 1, "P2": 2, "P3": 3, "P4": 4}
    if not findings:
        root_cause = "No anomalies detected; all services healthy."
        confidence = "high"
        evidence_list = ["All telemetry signals nominal."]
    else:
        top_finding = min(findings, key=lambda f: levels.get(f.severity, 99))
        root_cause = f"{top_finding.title}: {top_finding.detail}"
        confidence = "high" if top_finding.evidence else "medium"
        evidence_list = [ev for f in findings for ev in f.evidence]

    all_actions = list(dict.fromkeys(act for f in findings for act in f.recommended_actions))

    return {
        "analysis_mode": "rule_based",
        "severity": severity,
        "root_cause": root_cause,
        "confidence": confidence,
        "affected_services": all_affected,
        "evidence": evidence_list,
        "finding_count": len(findings),
        "findings": [f.to_dict() for f in findings],
        "possible_feature_flags": all_flags,
        "recommended_actions": all_actions,
        "summary": _build_summary(severity, findings),
    }


def _build_summary(severity: str, findings: list[Finding]) -> str:
    if severity == "OK":
        return "All signals healthy. No anomalies detected."
    parts = [f"Severity: {severity} -- {len(findings)} finding(s) detected."]
    p1 = [f for f in findings if f.severity == "P1"]
    if p1:
        parts.append("Critical: " + "; ".join(f.title for f in p1))
    p2 = [f for f in findings if f.severity == "P2"]
    if p2:
        parts.append("High: " + "; ".join(f.title for f in p2))
    return " ".join(parts)


# ---------------------------------------------------------------------------
# LLM-assisted analysis
# ---------------------------------------------------------------------------

LLM_BASE_URL = os.getenv("LLM_BASE_URL", "https://api.groq.com/openai/v1" if os.getenv("GROQ_API_KEY") else "https://api.openai.com/v1").rstrip("/")
LLM_MODEL = os.getenv("LLM_MODEL", "qwen-2.5-32b" if os.getenv("GROQ_API_KEY") else "gpt-4o-mini")
API_KEY = os.getenv("API_KEY") or os.getenv("GROQ_API_KEY") or os.getenv("OPENAI_API_KEY") or ""

SYSTEM_PROMPT = textwrap.dedent("""\
    You are a senior SRE incident responder analysing the OpenTelemetry
    Astronomy Shop Demo application. You receive a JSON snapshot from the
    "Eyes" evidence collector and a preliminary rule-based diagnosis.

    The demo uses feature flags (via flagd) to inject faults. Known flags:
    {flag_list}

    Your job:
    1. Confirm or refine the rule-based findings.
    2. Identify the most likely root cause, including which feature flag
       may have been toggled ON.
    3. Suggest specific remediation steps (e.g. "set flag X to 'off'",
       "restart container Y").
    4. Assign an overall severity: P1 (customer-facing outage),
       P2 (degraded but functional), P3 (minor/cosmetic), P4 (informational).

    Respond ONLY with valid JSON matching this schema:
    {{
      "severity": "P1|P2|P3|P4|OK",
      "root_cause": "short description",
      "confidence": "high|medium|low",
      "affected_services": ["svc1", ...],
      "suspected_flags": ["flagName", ...],
      "evidence_summary": "what telemetry data supports your conclusion",
      "recommended_actions": [
        {{"action": "description", "target": "service or flag", "priority": 1}}
      ],
      "additional_observations": "any other notes"
    }}
""")


def _build_flag_list() -> str:
    lines = []
    for name, info in sorted(KNOWN_FAILURE_FLAGS.items()):
        lines.append(f"  - {name}: {info['description']} (affects {info['affected_service']})")
    return "\n".join(lines)


def llm_analysis(snapshot: dict[str, Any],
                 rule_diagnosis: dict[str, Any]) -> dict[str, Any]:
    """Send the snapshot + rule diagnosis to an LLM for deeper reasoning."""
    if not API_KEY:
        return {
            "llm_status": "skipped",
            "reason": "No API_KEY or OPENAI_API_KEY set. Set one to enable LLM analysis.",
        }

    system_msg = SYSTEM_PROMPT.format(flag_list=_build_flag_list())

    signals = snapshot.get("signals", {})
    concise_snapshot = {
        "signals": {
            "containers": {
                "stopped": signals.get("containers", {}).get("stopped_containers", []),
                "unhealthy": signals.get("containers", {}).get("unhealthy_containers", []),
                "running_count": signals.get("containers", {}).get("running_count", 0),
            },
            "logs": {
                "error_logs": signals.get("logs", {}).get("recent_error_logs", []),
                "error_log_count": signals.get("logs", {}).get("error_log_count", 0),
            },
            "traces": {
                "error_traces": signals.get("traces", {}).get("error_traces", []),
                "affected_services": signals.get("traces", {}).get("affected_error_services", []),
            },
            "metrics": {
                "low_uptime_containers": signals.get("metrics", {}).get("low_uptime_containers", []),
            },
            "deploy_history": {
                "current_commit": signals.get("deploy_history", {}).get("current_commit"),
                "recent_commits": signals.get("deploy_history", {}).get("recent_git_commits", [])[:3],
            },
        }
    }

    user_content = json.dumps({
        "eyes_telemetry_summary": concise_snapshot,
        "preliminary_rule_diagnosis": rule_diagnosis,
    }, indent=2, ensure_ascii=False)

    payload = {
        "model": LLM_MODEL,
        "messages": [
            {"role": "system", "content": system_msg},
            {"role": "user", "content": user_content},
        ],
        "temperature": 0.2,
        "max_tokens": 2000,
    }

    url = f"{LLM_BASE_URL}/chat/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {API_KEY}",
        "User-Agent": "Team21-IncidentAgent/1.0",
    }

    data = json.dumps(payload).encode("utf-8")
    req = Request(url, data=data, headers=headers, method="POST")

    try:
        with urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
        response = json.loads(raw)
    except (HTTPError, URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        return {
            "llm_status": "error",
            "error": str(exc),
            "endpoint": url,
        }

    try:
        content = response["choices"][0]["message"]["content"]
        # Try to extract JSON from the response (handle markdown code fences)
        content = content.strip()
        if content.startswith("```"):
            content = content.split("\n", 1)[1]  # remove opening fence
            if content.endswith("```"):
                content = content[:-3]
            content = content.strip()
        llm_result = json.loads(content)
        llm_result["llm_status"] = "ok"
        llm_result["model"] = LLM_MODEL
        return llm_result
    except (KeyError, IndexError, json.JSONDecodeError) as exc:
        return {
            "llm_status": "parse_error",
            "raw_response": content if 'content' in dir() else str(response)[:500],
            "error": str(exc),
        }


# ---------------------------------------------------------------------------
# Human-readable report formatter
# ---------------------------------------------------------------------------

def format_report(diagnosis: dict[str, Any]) -> str:
    """Format the diagnosis as a human-readable text report."""
    lines: list[str] = []
    lines.append("=" * 60)
    lines.append("  INCIDENT DIAGNOSIS REPORT")
    lines.append(f"  Generated: {diagnosis.get('generated_at', 'N/A')}")
    lines.append("=" * 60)
    lines.append("")

    rules = diagnosis.get("rule_based", {})
    severity = rules.get("severity", "UNKNOWN")
    badge = {"P1": "[CRIT]", "P2": "[HIGH]", "P3": "[WARN]", "P4": "[INFO]", "OK": "[ OK ]"}.get(severity, "[????]")
    lines.append(f"  Overall Severity: {badge}  {severity}")
    lines.append(f"  Root Cause:       {diagnosis.get('root_cause') or rules.get('root_cause', 'N/A')}")
    lines.append(f"  Confidence:       {diagnosis.get('confidence') or rules.get('confidence', 'N/A')}")
    lines.append(f"  Summary:          {rules.get('summary', 'N/A')}")
    lines.append("")

    findings = rules.get("findings", [])
    if findings:
        lines.append(f"  Findings ({len(findings)}):")
        lines.append("-" * 60)
        for i, f in enumerate(findings, 1):
            sev_badge = {"P1": "[CRIT]", "P2": "[HIGH]", "P3": "[WARN]", "P4": "[INFO]"}.get(f["severity"], "[????]")
            lines.append(f"  {i}. [{sev_badge} {f['severity']}] {f['title']}")
            lines.append(f"     Detail: {f['detail'][:120]}")
            if f.get("affected_services"):
                lines.append(f"     Services: {', '.join(f['affected_services'])}")
            if f.get("possible_flags"):
                lines.append(f"     Possible flags: {', '.join(f['possible_flags'])}")
            if f.get("recommended_actions"):
                for action in f["recommended_actions"]:
                    lines.append(f"     -> {action}")
            lines.append("")
    else:
        lines.append("  [OK] No findings -- all signals healthy.")
        lines.append("")

    llm = diagnosis.get("llm_enhanced")
    if llm:
        lines.append("=" * 60)
        lines.append("  LLM-ENHANCED ANALYSIS")
        lines.append("=" * 60)
        status = llm.get("llm_status", "unknown")
        if status == "ok":
            lines.append(f"  Model: {llm.get('model', 'N/A')}")
            lines.append(f"  Root Cause: {llm.get('root_cause', 'N/A')}")
            lines.append(f"  Confidence: {llm.get('confidence', 'N/A')}")
            lines.append(f"  Suspected Flags: {', '.join(llm.get('suspected_flags', []))}")
            lines.append(f"  Evidence: {llm.get('evidence_summary', 'N/A')}")
            actions = llm.get("recommended_actions", [])
            if actions:
                lines.append("  Recommended Actions:")
                for a in actions:
                    if isinstance(a, dict):
                        lines.append(f"    {a.get('priority', '?')}. [{a.get('target', '?')}] {a.get('action', '?')}")
                    else:
                        lines.append(f"    - {a}")
            if llm.get("additional_observations"):
                lines.append(f"  Notes: {llm['additional_observations']}")
        elif status == "skipped":
            lines.append(f"  Skipped: {llm.get('reason', 'N/A')}")
        else:
            lines.append(f"  Error: {llm.get('error', 'unknown')}")
        lines.append("")

    lines.append("=" * 60)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run_eyes() -> dict[str, Any]:
    """Run the Eyes collector and capture the snapshot."""
    return collect_snapshot()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Brain: incident diagnosis for the OpenTelemetry Demo",
    )
    parser.add_argument(
        "--snapshot", metavar="FILE",
        help="Path to a previously-saved Eyes snapshot JSON file. "
             "If omitted, Eyes is run live.",
    )
    parser.add_argument(
        "--llm", action="store_true",
        help="Enable LLM-assisted analysis (requires API_KEY env var).",
    )
    parser.add_argument(
        "--report", action="store_true",
        help="Print a human-readable report instead of raw JSON.",
    )
    parser.add_argument(
        "--save", metavar="FILE",
        help="Save diagnosis JSON to a file.",
    )
    args = parser.parse_args()

    # Step 1: Get the Eyes snapshot
    if args.snapshot:
        with open(args.snapshot, "r", encoding="utf-8") as f:
            snapshot = json.load(f)
        print("[brain] Loaded snapshot from file.", file=sys.stderr)
    else:
        print("[brain] Running Eyes collector...", file=sys.stderr)
        snapshot = run_eyes()
        print("[brain] Eyes snapshot captured.", file=sys.stderr)

    # Step 2: Rule-based analysis
    print("[brain] Running rule-based analysis...", file=sys.stderr)
    rule_diagnosis = rule_based_analysis(snapshot)
    print(f"[brain] Rule result: {rule_diagnosis['severity']} "
          f"({rule_diagnosis['finding_count']} findings)", file=sys.stderr)

    # Step 3: Optional LLM analysis
    llm_result = None
    if args.llm:
        print(f"[brain] Running LLM analysis ({LLM_MODEL} @ {LLM_BASE_URL})...",
              file=sys.stderr)
        llm_result = llm_analysis(snapshot, rule_diagnosis)
        print(f"[brain] LLM status: {llm_result.get('llm_status', 'unknown')}",
              file=sys.stderr)

    # Step 4: Build the final diagnosis
    diagnosis: dict[str, Any] = {
        "schema_version": "1.0",
        "component": "brain",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "snapshot_time": snapshot.get("generated_at"),
        "severity": rule_diagnosis["severity"],
        "root_cause": rule_diagnosis["root_cause"],
        "confidence": rule_diagnosis["confidence"],
        "affected_services": rule_diagnosis["affected_services"],
        "evidence": rule_diagnosis["evidence"],
        "recommended_actions": rule_diagnosis["recommended_actions"],
        "possible_feature_flags": rule_diagnosis.get("possible_feature_flags", []),
        "rule_based": rule_diagnosis,
    }
    if llm_result:
        diagnosis["llm_enhanced"] = llm_result
        if llm_result.get("root_cause"):
            diagnosis["root_cause"] = llm_result["root_cause"]
        if llm_result.get("confidence"):
            diagnosis["confidence"] = llm_result["confidence"]
        if llm_result.get("severity"):
            diagnosis["severity"] = llm_result["severity"]
        if llm_result.get("affected_services"):
            diagnosis["affected_services"] = llm_result["affected_services"]
        if llm_result.get("recommended_actions"):
            diagnosis["recommended_actions"] = llm_result["recommended_actions"]

    # Step 5: Output
    if args.save:
        with open(args.save, "w", encoding="utf-8") as f:
            json.dump(diagnosis, f, indent=2, ensure_ascii=False)
        print(f"[brain] Diagnosis saved to {args.save}", file=sys.stderr)

    if args.report:
        print(format_report(diagnosis))
    else:
        print(json.dumps(diagnosis, indent=2, ensure_ascii=False))

    # Exit code: 0 = OK/P4, 1 = P1-P3
    if rule_diagnosis["severity"] in ("P1", "P2", "P3"):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
