# Team 21 Agent: Brain

Brain is the diagnosis agent. It takes an incident from Eyes (or a manual alert) and runs an LLM tool-calling loop. The LLM decides which read-only tool to call next based on what it has found so far. It ends by submitting a root cause with a confidence and the evidence behind it. Brain changes nothing; remediation belongs to Hands and needs human approval.

## Files

| File | Role |
|---|---|
| `tools.py` | The agent's read-only tools, built on `eyes.py` |
| `brain.py` | Agent loop, evidence verification, confidence calibration, report |
| `reports/` | One JSON report per run (created automatically) |

## Tools the agent can call

| Tool | What it returns |
|---|---|
| `check_alerts` | Current Eyes threshold breaches and stopped/unhealthy containers |
| `service_health` | Per-service req/s, error ratio and p95 from span metrics (HTTP **and** gRPC), with a 30-minute baseline |
| `find_error_origins` | Sampled traces: where errors **start** (failing spans with no failing children), errors per service, and the slowest operations by self time |
| `get_trace` | One trace as a call tree with durations and error messages |
| `search_logs` | Newest logs for a service (errors only by default), grouped by message |
| `container_details` | Docker state, health, restarts, exit code and OOM kill for one demo container |
| `deploy_history` | Demo containers ordered by most recent (re)start |
| `query_promql` / `list_metrics` | Any other read-only Prometheus query |

## Setup

Create `.env` in the repository root or in `team21_agent/` (see `.env.example`). It works with any OpenAI-compatible API:

| Provider | `LLM_BASE_URL` | `LLM_MODEL` example |
|---|---|---|
| Groq | `https://api.groq.com/openai/v1` | `llama-3.3-70b-versatile` |
| Gemini | `https://generativelanguage.googleapis.com/v1beta/openai` | `gemini-2.5-flash` |
| OpenAI | `https://api.openai.com/v1` | `gpt-4o-mini` |
| Ollama (local) | `http://localhost:11434/v1` | `qwen2.5:7b` (no key needed) |

## Commands (Windows PowerShell, from the repository root)

```powershell
# Run Eyes once; if it finds an incident, diagnose it
py -3.11 .\team21_agent\brain.py

# Diagnose an incident from saved Eyes output (--once/--snapshot JSON or a --watch log)
py -3.11 .\team21_agent\eyes.py --once > incident_run.json
py -3.11 .\team21_agent\brain.py --from-eyes incident_run.json

# Manual alert, e.g. a practice incident the mentor names
py -3.11 .\team21_agent\brain.py --service checkout --symptom "checkout requests are failing"
```

Progress (each tool call) is printed to stderr; the final report is printed to stdout as JSON and saved under `reports/`. Exit codes: `0` diagnosed, `2` escalated, `3` no incident, `1` error.

## Honesty and safety controls

- **Evidence verification (in code):** every evidence `reference` must appear verbatim in a tool output from this run. References that don't are moved to `unverified_evidence_dropped`, and confidence is reduced in proportion.
- **Confidence calibration:** fewer than 2 verified evidence items caps confidence at 0.5. A root-cause service that never appeared in any tool output caps it at 0.3.
- **Escalation:** below `BRAIN_MIN_CONFIDENCE` (default 0.6) the outcome is `escalated`. The recommended action becomes `escalate_to_human`, with the proposed fix kept for the human to judge.
- **Actions are proposals from an allowlist:** `restart_service`, `toggle_feature_flag`, `throttle_load_generator`, `scale_service`, `escalate_to_human`, `no_action`. Nothing is executed by Brain.
- **No feature-flag access:** tools refuse queries mentioning flags, drop flagd services, and strip `feature_flag.*` span data before the LLM sees it.
- **Bounded:** at most `BRAIN_MAX_STEPS` tool calls (default 10). After that, the model must submit what it has.

## Report fields

`incident_id`, `outcome` (diagnosed / escalated), `trigger`, `symptoms_summary`, `root_cause` {service, component, cause, category}, `confidence`, `model_confidence`, `confidence_notes`, `evidence[]` (verified), `unverified_evidence_dropped[]`, `alternatives_ruled_out[]`, `recommended_action`, `prevention`, `investigation[]` (every tool call with arguments and timing), `llm`, `schema_problems`.

When the organisers' JSON schema arrives, map these fields in `build_report()` / `validate_report()` in `brain.py`.

## Known limitations

- Trace analysis samples 30 recent traces; a rare intermittent error may be missed. The agent can search a specific service to compensate.
- Log search reads the 100 newest records (Eyes' OpenSearch query has no time filter), so older errors may not be visible.
- Evidence verification checks that a reference exists in tool output, not that the LLM interpreted it correctly.
- Diagnosis quality depends on the LLM. Small local models follow the tool protocol less reliably.
