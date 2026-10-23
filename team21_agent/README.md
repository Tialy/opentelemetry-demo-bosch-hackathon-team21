# Team 21 Agent — Eyes

Eyes is the read-only incident detection and evidence-gathering component for the Bosch hackathon. It monitors Prometheus for HTTP 5xx error-rate and p95 request-latency threshold breaches. When a breach appears, it automatically gathers targeted Jaeger traces, OpenSearch logs, and Docker container status for the affected service. It reports symptoms and evidence for Brain; it does not decide a root cause or perform remediation.

## Requirements

- Python 3.11+
- Docker Desktop running the OpenTelemetry Demo
- Demo endpoints reachable from the host (defaults below)
- No third-party Python packages are required

## Commands (Windows PowerShell)

Run from the repository root:

```powershell
# Detailed telemetry snapshot + threshold evaluation (default)
py -3.11 .\team21_agent\eyes.py

# One metric-threshold evaluation; if an incident is detected, investigate it immediately
py -3.11 .\team21_agent\eyes.py --once

# Continuously monitor and automatically investigate each newly active incident
py -3.11 .\team21_agent\eyes.py --watch --interval 15

# Run the local unit tests (no Docker faults are injected)
py -3.11 -m unittest discover -s .\team21_agent -p "test_eyes.py" -v
```

Stop watch mode with `Ctrl+C`. `--watch` prints JSON events. It investigates a new incident once while its fingerprint remains active; once it clears, the same incident can trigger a new investigation if it recurs.

## Thresholds

Defaults are deliberately explicit and configurable:

- HTTP 5xx error rate: `5%` over the configured window
- HTTP request p95 latency: `1000 ms` over the configured window
- Minimum request count before evaluating an error ratio: `20`
- Window: `300` seconds
- Watch interval: `15` seconds

You can override these on the command line, for example:

```powershell
py -3.11 .\team21_agent\eyes.py --watch --error-rate-threshold 0.03 --latency-threshold-ms 750 --window-seconds 300 --min-requests 20
```

The detector discovers supported metric names from Prometheus instead of assuming every deployment uses the same instrumentation. Supported histogram/counter names and status labels are enumerated in `eyes.py`. If no compatible metrics or too little traffic is available, the output reports a degraded/partial state rather than claiming that the system is healthy.

## Endpoint defaults

- Jaeger API through the working frontend-proxy path: `http://localhost:8080/jaeger/ui`
- Prometheus: `http://localhost:9090`
- OpenSearch: `http://localhost:55704`
- Docker CLI: `docker ps`

Environment overrides: `JAEGER_URL`, `PROMETHEUS_URL`, `OPENSEARCH_URL`, `OPENSEARCH_LOGS_INDEX`, `EYES_HTTP_TIMEOUT`, `EYES_ERROR_RATE_THRESHOLD`, `EYES_P95_LATENCY_THRESHOLD_MS`, `EYES_WINDOW_SECONDS`, `EYES_MIN_REQUESTS`, and `EYES_WATCH_INTERVAL`.

## Investigation flow

1. Query Prometheus for the available metric names and supported HTTP counters/histograms.
2. Evaluate the 5xx-rate and p95-latency thresholds over the selected time window.
3. If no incident is detected, do not bulk-query traces and logs in watch mode; poll again at the configured interval.
4. If a threshold breach is detected, query Jaeger for the implicated service, search OpenSearch logs for that service, and check the corresponding Docker container state.
5. Emit a structured evidence object that Brain can use to diagnose root cause. Missing evidence is reported as unavailable rather than invented.

## Safety boundary

Eyes is read-only. It does not change the OpenTelemetry Demo source/configuration, inspect feature-flag settings, call `faultctl`, restart/scale services, change traffic, or invoke a remediation API. Use only the hackathon-approved practice-incident mechanism for live validation. Hands/action execution and human approval are separate components.
