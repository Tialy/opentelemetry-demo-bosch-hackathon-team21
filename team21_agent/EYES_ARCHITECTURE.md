# Team 21 — Eyes architecture (one-page sketch)

```mermaid
flowchart TD
    PROM[Prometheus API\nHTTP counters + duration histograms]
    RULES[Threshold evaluator\n5xx error rate and p95 latency\nconfigurable window + thresholds]
    POLL{Threshold breached?}
    WAIT[Wait for next polling interval]
    EVENT[Create incident event\nservice + observed value + threshold + metric evidence]
    J[Jaeger API v3 via frontend proxy\nquery traces for implicated service]
    O[OpenSearch API\nquery recent logs for implicated service]
    D[Docker CLI\ncheck container status/health]
    E[Evidence snapshot JSON\nmetrics + traces + logs + container status]
    B[Brain component\nroot-cause diagnosis and confidence]
    SAFE[Read-only boundary\nno flags, config edits, or remediation]

    PROM --> RULES --> POLL
    POLL -- No --> WAIT --> PROM
    POLL -- Yes --> EVENT
    EVENT --> J
    EVENT --> O
    EVENT --> D
    J --> E
    O --> E
    D --> E
    E --> B
    SAFE -. constrains .-> RULES
    SAFE -. constrains .-> J
    SAFE -. constrains .-> O
    SAFE -. constrains .-> D
```

**Trigger rules (defaults):** HTTP 5xx error ratio ≥ 5% (only after ≥20 requests) or HTTP request p95 latency ≥ 1,000 ms, evaluated over the preceding 300 seconds. All thresholds are configurable. An unhealthy/stopped container is also surfaced as a secondary observation.

**Evidence policy:** The watcher starts with metrics and container status. It queries traces/logs only after a threshold incident is detected. It reports the observed value, threshold, time window, source metric/PromQL, trace summaries, log samples, and related container status. It does not infer root cause; Brain owns diagnosis.

**Safety boundary:** no demo configuration or feature-flag reads, no manual fault injection, no service changes, no calls to remediation/action APIs. Live incident testing must use the hackathon-approved practice-incident mechanism.
