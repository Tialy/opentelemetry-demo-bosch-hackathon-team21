# Team 21 Incident-Response Agent

An autonomous incident-response agent for the OpenTelemetry Demo, built for the Bosch Hackathon.

## Architecture

```
  Eyes (evidence)  -->  Brain (diagnosis)  -->  Hands (remediation)
   eyes.py               brain.py               (Checkpoint 3)
```

| Component | Checkpoint | Status | Description |
|-----------|------------|--------|-------------|
| **Eyes** | Checkpoint 1 (10 pts) | **Complete** | Read-only evidence collector across 5 signals: Traces, Metrics, Logs, Deploy History, Containers. Includes human-readable symptom summarizer (`--summary`). |
| **Brain** | Checkpoint 2 (20 pts) | **Complete** | Root-cause diagnosis with confidence & evidence: rule-based engine + optional LLM reasoning. Standardized JSON output. |
| **Hands** | Checkpoint 3 (20 pts) | Next Step | Safe remediation: allowlisted actions, human approval gate, execution, recovery verification, and kill switch. |

---

## Prerequisites

- Windows PowerShell / Linux / macOS
- Python 3.11 or newer
- Docker Desktop with OpenTelemetry Demo running
- Zero external Python dependencies (pure Python standard library: `urllib`, `json`, `subprocess`, `argparse`)

---

## Checkpoint 1: Eyes (Telemetry Collection & Symptoms)

Collects evidence across **5 distinct signals**:
1. **Traces (Jaeger)**: discovered services, recent frontend traces, and active error spans.
2. **Metrics (Prometheus)**: metric availability, container resource usage, and low-uptime/crash-looping containers (`container_uptime_seconds < 300`).
3. **Logs (OpenSearch)**: recent application logs, error/exception logs with proper service attribution and severity extraction.
4. **Deploy History (Git & Docker)**: recent git commits (`git log`) and container deployment/restart timestamps.
5. **Containers (Docker)**: container status filtered specifically for OpenTelemetry Demo services (ignoring unrelated host containers).

### Usage

```powershell
# 1. Human-readable symptom summary (for Checkpoint 1 mentor demo)
python team21_agent\eyes.py --summary

# 2. Machine-readable JSON snapshot (to stdout)
python team21_agent\eyes.py

# 3. Save snapshot to file
python team21_agent\eyes.py --save snapshot.json
```

---

## Checkpoint 2: Brain (Incident Diagnosis)

Analyses the Eyes snapshot to determine **root cause**, **evidence**, and **confidence**:

- **Rule-based mode (default)**: Zero API keys, 100% deterministic, sub-second execution. Detects stopped/unhealthy containers, trace error spans, metric anomalies, low uptime/restarts, and error logs.
- **LLM-assisted mode (`--llm`)**: Deep multi-signal reasoning and natural language explanation via any OpenAI-compatible API.

### Required Output Format (JSON Schema)

Every diagnosis includes the required scoring fields:
- `root_cause`: concise diagnosis string
- `confidence`: `high` / `medium` / `low`
- `severity`: `P1` (critical outage), `P2` (degraded), `P3` (minor), `P4` (info), or `OK`
- `affected_services`: list of impacted services
- `evidence`: concrete telemetry strings from logs, traces, metrics, and containers
- `recommended_actions`: allowlisted actions for human approval
- `possible_feature_flags`: hypotheses mapped from telemetry symptoms

### Usage

```powershell
# 1. Human-readable diagnosis report (for Checkpoint 2 mentor demo)
python team21_agent\brain.py --report

# 2. Structured JSON output (for automated scoring harness)
python team21_agent\brain.py

# 3. Save diagnosis to file
python team21_agent\brain.py --save diagnosis.json

# 4. Diagnose a previously saved snapshot
python team21_agent\brain.py --snapshot snapshot.json --report

# 5. LLM-assisted diagnosis
$env:LLM_BASE_URL = "https://api.openai.com/v1"
$env:API_KEY = "sk-..."
python team21_agent\brain.py --llm --report
```

---

## Hackathon Compliance & Safety Boundaries

1. **Strictly Read-Only Diagnosis**: Diagnosis comes **purely from telemetry** (traces, metrics, logs, containers). The agent **NEVER** reads feature flag settings (`flagd` files, flag UI, or flag API) to diagnose incidents.
2. **Auto-Discovered Ports**: Dynamically resolves container ports using `docker port` so it works seamlessly on any laptop port configuration.
3. **No Hard-Coded Answers**: The diagnosis is dynamically derived from real-time evidence queries against the running demo.
4. **Safety Approval Gate**: No system changes are made by Eyes or Brain. Remediation is strictly deferred to Hands under human approval.
