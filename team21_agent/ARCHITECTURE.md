# Team 21 Incident-Response Agent: Architecture Overview

A one-page technical architecture covering agent components, tool use, decision pipeline, and safety boundaries.

```
+-------------------------------------------------------------------------------+
|                             OBSERVABILITY STACK                               |
|   +-------------------+  +-------------------+  +--------------------------+  |
|   | Jaeger (Traces)   |  | Prometheus (Metrics)| | OpenSearch (Logs)        |  |
|   +---------+---------+  +---------+---------+  +------------+-------------+  |
|             |                      |                         |                |
|             |      +---------------+---------------+         |                |
|             |      | Docker & Git (Deploy History) |         |                |
|             |      +---------------+---------------+         |                |
+-------------|----------------------|-------------------------|----------------+
              |                      |                         |
              v                      v                         v
+-------------------------------------------------------------------------------+
|                           EYES (Evidence Collector)                           |
|  - Dynamically discovers ports via `docker port`                              |
|  - Queries Jaeger v3 for trace gaps & active error spans                      |
|  - Queries Prometheus for series counts, memory/cpu, and low uptime (<300s)   |
|  - Queries OpenSearch for recent logs & error/exception events                |
|  - Inspects Git commit history and Docker container health & restart events   |
|  - Strictly Read-Only: NEVER reads flagd files or flag UI                     |
|  - Output: 5-signal JSON snapshot + CLI symptom summarizer (`--summary`)      |
+------------------------------------+------------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------------+
|                            BRAIN (Diagnosis Engine)                           |
|                                                                               |
|   +------------------------------------+   +-------------------------------+  |
|   | Deterministic Rule Engine          |   | LLM Reasoning (Optional)      |  |
|   | - Multi-signal cross correlation   |   | - OpenAI-compatible endpoint  |  |
|   | - Severity classifier (P1 -> P4)   |   | - Root-cause hypothesis test  |  |
|   | - Flag symptom pattern matcher     |   | - Natural language synthesis  |  |
|   +-----------------+------------------+   +---------------+---------------+  |
|                     |                                      |                  |
|                     +------------------+-------------------+                  |
|                                        v                                      |
|   Standardized Output Schema:                                                 |
|   - root_cause               - evidence (traces, metrics, logs, containers)   |
|   - confidence (high/med/low)- recommended_actions                            |
|   - severity (P1-P4, OK)     - affected_services                              |
+----------------------------------------+--------------------------------------+
                                         |
                                         v
+-------------------------------------------------------------------------------+
|                            HANDS (Action & Safety)                            |
|                                                                               |
|   +--------------------+     +-------------------+     +------------------+   |
|   | Allowlisted Action | --> | Human Approval    | --> | Action API /     |   |
|   | Proposal           |     | Gate [Y/N]        |     | Verified Recovery|   |
|   +--------------------+     +-------------------+     +------------------+   |
|                                                                               |
|   Safety Controls:                                                            |
|   1. Read-Only Eyes & Brain: Agent cannot act without human intervention.     |
|   2. Strict Allowlist: Only restart container, toggle flag, scale service.   |
|   3. Mandatory Approval Gate: Human operator must confirm every action.       |
|   4. Kill Switch: Instant abort command terminating all automated actions.    |
|   5. Post-Action Verification: Eyes re-checks telemetry to verify recovery.  |
|   6. Complete Audit Log: All action proposals, approvals, and API calls logged|
+-------------------------------------------------------------------------------+
```

---

## 1. Components & Tool Use

- **`eyes.py` (Checkpoint 1 - 10 pts)**:
  - Telemetry gathering across traces, metrics, logs, deploy history, and containers.
  - Zero dependencies beyond standard Python 3.11+.
  - Resilient to container port randomization with automatic host port resolution.
  - Generates symptom summaries (`eyes.py --summary`) directly matching mentor demo criteria.

- **`brain.py` (Checkpoint 2 - 20 pts)**:
  - Consumes telemetry snapshots to identify root cause and calculate confidence.
  - Dual execution modes: deterministic fast rule matching or LLM-enhanced reasoning.
  - Strictly derives diagnosis from telemetry without peeking at feature flag configuration.
  - Compliant JSON schema output with `root_cause`, `confidence`, `evidence`, and `severity`.

- **`hands.py` (Checkpoint 3 - 20 pts)**:
  - Proposes safe, allowlisted remediations (e.g. restart service, toggle offending flag).
  - Enforces explicit interactive human confirmation before executing any change.
  - Re-triggers Eyes to verify telemetry returns to nominal status.

---

## 2. Safety Architecture & Human Approval Gate

1. **Telemetry-Only Diagnosis**: Complies with Hackathon rules; diagnosis is never based on reading `flagd` files or the flag UI.
2. **Approval Gate**: Autonomous action execution is disabled by default. Every action requires interactive confirmation (`[y/N]`) or an explicit dry-run flag.
3. **Emergency Kill Switch**: Any in-flight action can be immediately halted via `Ctrl+C` or `--abort`.
4. **Audit Trail**: Every diagnosis, proposal, human approval decision, and action result is persisted to an immutable incident audit log.
