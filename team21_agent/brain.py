#!/usr/bin/env python3
"""Team 21 Brain: an LLM agent that diagnoses an incident from telemetry.

Flow:
  1. Trigger: an Eyes incident (live detection, a saved Eyes JSON) or a manual alert
  2. Agent loop: the LLM sees the alert and a set of read-only tools (tools.py). It decides
     which tool to call next based on what it has found so far, up to --max-steps calls
  3. The LLM submits a diagnosis: root-cause service, cause, category, confidence, evidence
  4. Evidence check (code, not the LLM): every cited reference must appear verbatim in a tool
     output from this run. Invented evidence is dropped and confidence is lowered.
  5. Below the confidence bar, the outcome is "escalated": a human gets the findings
     instead of a guessed fix
  6. The report is printed and saved to reports/; nothing in the system is changed

LLM: any OpenAI-compatible chat-completions API with tool calling (Groq, Gemini, OpenAI, Ollama).
Configure in .env or environment variables: LLM_API_KEY, LLM_BASE_URL, LLM_MODEL.

Usage (Python 3.11+, standard library only):
  python brain.py                                   # run Eyes once, diagnose the first incident found
  python brain.py --from-eyes incident_run.json     # diagnose an incident from saved Eyes output
  python brain.py --service checkout --symptom "checkout requests failing"   # manual alert
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import eyes  # noqa: E402
import tools  # noqa: E402


# ----------------------------------------------------------------------------- config
def _load_dotenv() -> None:
    """Minimal .env loader: KEY=VALUE lines; real environment variables win."""
    for folder in (HERE, Path.cwd(), HERE.parent):  # team21_agent/.env first
        env_file = folder / ".env"
        if not env_file.is_file():
            continue
        for line in env_file.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


_load_dotenv()
LLM_API_KEY = (os.getenv("LLM_API_KEY") or os.getenv("GROQ_API_KEY") or os.getenv("GEMINI_API_KEY")
               or os.getenv("OPENAI_API_KEY") or "")
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "https://api.openai.com/v1").rstrip("/")
LLM_MODEL = os.getenv("LLM_MODEL", "gpt-4o-mini")
LLM_TIMEOUT = float(os.getenv("LLM_TIMEOUT", "90"))
MAX_STEPS = int(os.getenv("BRAIN_MAX_STEPS", "10"))
MAX_TOOL_CHARS = int(os.getenv("BRAIN_MAX_TOOL_CHARS", "4000"))
MIN_CONFIDENCE = float(os.getenv("BRAIN_MIN_CONFIDENCE", "0.6"))
REPORTS_DIR = HERE / "reports"

CATEGORIES = ["application_error", "dependency_unavailable", "container_down_or_restarting",
              "resource_exhaustion", "latency_degradation", "traffic_surge", "network_issue", "unknown"]
ACTIONS = ["restart_service", "toggle_feature_flag", "throttle_load_generator", "scale_service",
           "escalate_to_human", "no_action"]
EVIDENCE_SOURCES = ["metrics", "traces", "logs", "containers", "deploys", "alert"]

SYSTEM_PROMPT = f"""You are the on-call SRE agent for the OpenTelemetry Demo (Astronomy Shop), a microservice
e-commerce app (frontend-proxy, frontend, cart, checkout, payment, product-catalog, recommendation, ad,
currency, shipping, quote, email, accounting, fraud-detection, kafka, valkey-cart, ...).
You received an alert. Find the ROOT CAUSE using the read-only tools, then call submit_diagnosis.

How to investigate:
- Decide each next tool from what you have found so far. Do not call every tool by default.
- Separate cause from symptom. Errors propagate UP the call chain: a failing downstream service makes its
  callers fail too. The root cause is usually where errors START (find_error_origins), confirmed by that
  service's own logs, metrics or container state.
- Check infrastructure as well as code: a stopped, restarting, OOM-killed or CPU/memory-starved container,
  or an unreachable cache/database, shows up in container_details / deploy_history and as connection
  errors in the callers.
- For latency alerts, look at p95 against its baseline (service_health) and the slowest operations by self time.
- Stop when at least two independent signals agree (e.g. trace error origin + matching log lines, or
  stopped container + connection errors in callers). Usually 3-6 tool calls are enough.

Rules:
- Evidence must come from tool outputs in THIS investigation. In each evidence item, "reference" is ONE short
  snippet (under 120 characters) copied character-for-character from a single tool output: a trace id, part
  of a log/error message, or one field such as "state":"exited" or "error_ratio":1.0. Do not paraphrase,
  reorder, join several fields, or use "...". Put your explanation in "detail". 3-5 evidence items is ideal.
  Never invent ids, numbers or log lines: references are checked against the tool outputs by code.
- Be economical: avoid repeating a tool call with the same arguments.
- You cannot read or change feature-flag settings, and you change nothing. You only diagnose.
- Confidence (0-1) must reflect the evidence: >= 0.8 only when several signals agree; < 0.6 when evidence is
  thin or contradictory. If you are not sure, say so: escalating to a human with your findings is a correct
  outcome and scores better than a confident wrong answer.
- recommended_action must be one of {ACTIONS}. Use escalate_to_human when unsure.
- Finish by calling submit_diagnosis exactly once."""

SUBMIT_TOOL = {"type": "function", "function": {
    "name": "submit_diagnosis",
    "description": "Submit the final diagnosis. Call exactly once, when the investigation is done.",
    "parameters": {
        "type": "object",
        "properties": {
            "symptoms_summary": {"type": "string", "description": "2-3 sentences: what is observably wrong"},
            "root_cause": {"type": "object", "properties": {
                "service": {"type": "string", "description": "service/container where the fault originates"},
                "component": {"type": "string", "description": "operation, dependency or resource that fails"},
                "cause": {"type": "string", "description": "one sentence: why it fails"},
                "category": {"type": "string", "enum": CATEGORIES},
            }, "required": ["service", "cause", "category"]},
            "confidence": {"type": "number", "description": "0.0 to 1.0"},
            "evidence": {"type": "array", "items": {"type": "object", "properties": {
                "source": {"type": "string", "enum": EVIDENCE_SOURCES},
                "reference": {"type": "string", "description": "exact text copied from a tool output"},
                "detail": {"type": "string", "description": "what this shows"},
            }, "required": ["source", "reference", "detail"]}},
            "alternatives_ruled_out": {"type": "array", "items": {"type": "string"}},
            "recommended_action": {"type": "object", "properties": {
                "action": {"type": "string", "enum": ACTIONS},
                "target": {"type": "string"},
                "reason": {"type": "string"},
            }, "required": ["action", "reason"]},
            "prevention": {"type": "string", "description": "what would stop this recurring"},
        },
        "required": ["symptoms_summary", "root_cause", "confidence", "evidence", "recommended_action"],
    },
}}


def utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def log(message: str) -> None:
    """Progress goes to stderr so stdout stays pure JSON."""
    print(message, file=sys.stderr, flush=True)


# ----------------------------------------------------------------------------- LLM client
class LLMError(RuntimeError):
    pass


def chat(messages: list[dict[str, Any]], tool_specs: list[dict[str, Any]], force_submit: bool = False) -> dict[str, Any]:
    """One OpenAI-compatible chat-completions call with tools. Retries rate limits and 5xx."""
    if not LLM_API_KEY and "localhost" not in LLM_BASE_URL and "127.0.0.1" not in LLM_BASE_URL:
        raise LLMError("No LLM key. Set LLM_API_KEY (and LLM_BASE_URL / LLM_MODEL) in .env")
    body: dict[str, Any] = {"model": LLM_MODEL, "messages": messages, "tools": tool_specs, "temperature": 0}
    if force_submit:
        body["tool_choice"] = {"type": "function", "function": {"name": "submit_diagnosis"}}
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {LLM_API_KEY or 'none'}",
               "User-Agent": "team21-brain/1.0"}  # Cloudflare (Groq) blocks Python's default UA: error 1010
    for attempt in range(5):
        request = Request(f"{LLM_BASE_URL}/chat/completions", data=json.dumps(body).encode("utf-8"),
                          headers=headers, method="POST")
        try:
            with urlopen(request, timeout=LLM_TIMEOUT) as response:
                return json.loads(response.read().decode("utf-8", errors="replace"))
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:500]
            if exc.code == 429 or exc.code >= 500:
                wait = float(exc.headers.get("retry-after") or 0) or min(30.0, 2.0 ** (attempt + 1))
                log(f"   LLM HTTP {exc.code}, retrying in {wait:.0f}s")
                time.sleep(wait)
                continue
            if exc.code == 400 and force_submit and "tool_choice" in body:
                body.pop("tool_choice")  # some providers reject a forced tool choice
                continue
            raise LLMError(f"LLM HTTP {exc.code}: {detail}") from exc
        except (URLError, TimeoutError, OSError) as exc:
            if attempt < 2:
                time.sleep(2)
                continue
            raise LLMError(f"LLM unreachable at {LLM_BASE_URL}: {exc}") from exc
    raise LLMError("LLM kept failing (rate limit or server errors)")


# ----------------------------------------------------------------------------- trigger
def _compact(value: Any, limit: int) -> str:
    text = json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)
    return text if len(text) <= limit else text[:limit] + "...[truncated]"


def trigger_from_eyes_result(result: dict[str, Any]) -> dict[str, Any] | None:
    incidents = result.get("incidents") or []
    if not incidents:
        return None
    rank = {"critical": 0, "warning": 1}
    incident = sorted(incidents, key=lambda i: rank.get(str(i.get("severity")), 2))[0]
    investigation = next((inv for inv in result.get("investigations") or []
                          if inv.get("incident_id") == incident.get("id")), None)
    return {"source": "eyes", "incident": incident, "other_incidents": [i.get("id") for i in incidents if i is not incident],
            "eyes_evidence": (investigation or {}).get("evidence")}


def load_trigger(args: argparse.Namespace) -> dict[str, Any] | None:
    if args.service:
        return {"source": "manual", "incident": {
            "id": f"manual:{args.service}", "kind": "manual_alert", "service": args.service,
            "title": args.symptom or f"Suspected problem in {args.service}", "detected_at": utc_iso()}}
    if args.from_eyes:
        text = Path(args.from_eyes).read_text(encoding="utf-8-sig")
        candidates: list[dict[str, Any]] = []
        try:
            candidates = [json.loads(text)]
        except json.JSONDecodeError:  # --watch output: one JSON object per line
            for line in text.splitlines():
                try:
                    candidates.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        for item in reversed(candidates):
            trigger = trigger_from_eyes_result(item) if isinstance(item, dict) else None
            if trigger:
                return trigger
        return None
    log("Running Eyes detection once...")
    result = eyes.run_detection_cycle(eyes.DEFAULT_ERROR_RATE_THRESHOLD, eyes.DEFAULT_P95_LATENCY_THRESHOLD_MS,
                                      eyes.DEFAULT_WINDOW_SECONDS, eyes.DEFAULT_MIN_REQUESTS)
    return trigger_from_eyes_result(result)


# ----------------------------------------------------------------------------- evidence check
def _norm(text: str) -> str:
    """Formatting-insensitive form: JSON punctuation and quotes become spaces, so
    '"state":"exited"' and 'state: exited' compare equal. Values are kept intact."""
    text = re.sub(r"[\"'`{}\[\](),:;=|]", " ", str(text).lower())
    return " " + re.sub(r"\s+", " ", text).strip() + " "


def _match(reference: str, corpus: str, tokens: set[str]) -> str:
    """'full': every fragment of the reference appears contiguously in the tool outputs.
    'partial': fragments were reordered/combined, but every value in them really appeared.
    'none': something in the reference never appeared (invented id, number or text)."""
    fragments = [_norm(f).strip() for f in re.split(r"\.\.\.|…|[;,]\s|\n", reference)]
    fragments = [f for f in fragments if f]
    if not fragments or len("".join(fragments)) < 3:
        return "none"
    if all(f" {f} " in corpus or f in corpus for f in fragments):
        return "full"
    words = [w.rstrip(".") for f in fragments for w in f.split()]
    if not words or not all(w in tokens for w in words if w):
        return "none"  # some id, number or word never appeared anywhere
    # Every word is real; make sure they also belong together (key next to its value) so real
    # words cannot be recombined into a false fact like "state running" for a stopped container.
    for fragment in fragments:
        if f" {fragment} " in corpus:
            continue
        parts = [w.rstrip(".") for w in fragment.split()]
        pairs = list(zip(parts, parts[1:]))
        if pairs and sum(f" {a} {b} " in corpus for a, b in pairs) / len(pairs) < 0.5:
            return "none"
    return "partial"


def verify(diagnosis: dict[str, Any], ledger: list[str]) -> dict[str, Any]:
    """Check every evidence reference against what the tools actually returned in this run."""
    corpus = _norm("\n".join(ledger))
    tokens = {w.rstrip(".") for w in corpus.split()}
    verified, dropped = [], []
    for item in diagnosis.get("evidence") or []:
        match = _match(str(item.get("reference", "")), corpus, tokens)
        entry = {**item, "verified": match != "none", "match": match}
        (verified if match != "none" else dropped).append(entry)
    service = _norm((diagnosis.get("root_cause") or {}).get("service", "")).strip()
    return {"verified": verified, "dropped": dropped,
            "service_seen_in_tools": bool(service) and f" {service} " in corpus}


def calibrate(model_confidence: float, check: dict[str, Any]) -> tuple[float, list[str]]:
    """Lower the LLM's confidence when its evidence does not hold up."""
    notes = []
    confidence = max(0.0, min(1.0, float(model_confidence or 0)))
    total = len(check["verified"]) + len(check["dropped"])
    full = sum(1 for e in check["verified"] if e.get("match") == "full")
    partial = len(check["verified"]) - full
    if total and (check["dropped"] or partial):
        confidence *= (full + 0.75 * partial) / total
    if check["dropped"]:
        notes.append(f"{len(check['dropped'])} of {total} evidence items were not found in tool outputs and were dropped")
    if partial:
        notes.append(f"{partial} evidence item(s) only partially matched (values real, wording reordered)")
    if len(check["verified"]) < 2:
        confidence = min(confidence, 0.5)
        notes.append("fewer than 2 verified evidence items")
    if not check["service_seen_in_tools"]:
        confidence = min(confidence, 0.3)
        notes.append("root-cause service never appeared in any tool output")
    return round(confidence, 2), notes


def validate_report(report: dict[str, Any]) -> list[str]:
    """Structural check of the report (swap for the organisers' JSON schema when it arrives)."""
    problems = []
    for key in ("incident_id", "outcome", "symptoms_summary", "root_cause", "confidence", "evidence",
                "recommended_action", "investigation"):
        if key not in report:
            problems.append(f"missing {key}")
    root = report.get("root_cause") or {}
    if root.get("category") not in CATEGORIES:
        problems.append("root_cause.category not in allowed list")
    if not isinstance(report.get("confidence"), (int, float)) or not 0 <= report["confidence"] <= 1:
        problems.append("confidence must be 0..1")
    if (report.get("recommended_action") or {}).get("action") not in ACTIONS:
        problems.append("recommended_action.action not in allowlist")
    return problems


# ----------------------------------------------------------------------------- agent loop
def investigate(trigger: dict[str, Any], max_steps: int = MAX_STEPS) -> dict[str, Any]:
    tool_specs = tools.openai_tool_specs() + [SUBMIT_TOOL]
    alert_text = _compact(trigger, 3000)
    ledger: list[str] = [alert_text]          # everything the LLM was shown, for evidence checking
    steps: list[dict[str, Any]] = []
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"ALERT (from {trigger['source']}):\n{alert_text}\n\nInvestigate and diagnose."},
    ]
    diagnosis = None
    usage_tokens = 0
    started = time.perf_counter()

    for turn in range(max_steps + 2):
        out_of_budget = len(steps) >= max_steps
        if out_of_budget:
            messages.append({"role": "user", "content": "Tool budget used up. Call submit_diagnosis now with what "
                                                        "you have; lower your confidence if evidence is thin."})
        reply = chat(messages, tool_specs, force_submit=out_of_budget)
        usage_tokens += int((reply.get("usage") or {}).get("total_tokens") or 0)
        message = (reply.get("choices") or [{}])[0].get("message") or {}
        calls = message.get("tool_calls") or []
        if not calls:
            messages.append({"role": "assistant", "content": message.get("content") or ""})
            messages.append({"role": "user", "content": "Use the tools, then finish with submit_diagnosis."})
            continue

        for index, call in enumerate(calls):  # normalise ids for providers that omit them
            if not call.get("id"):
                call["id"] = f"call_{turn}_{index}"
            call.setdefault("type", "function")
        messages.append({"role": "assistant", "content": message.get("content") or "", "tool_calls": calls})

        for call in calls:
            name = call["function"]["name"]
            try:
                arguments = json.loads(call["function"].get("arguments") or "{}")
            except json.JSONDecodeError:
                arguments = None
            if name == "submit_diagnosis" and isinstance(arguments, dict):
                diagnosis = arguments
                messages.append({"role": "tool", "tool_call_id": call["id"], "content": "received"})
                continue
            if arguments is None:
                content = "ERROR: arguments were not valid JSON"
            else:
                step = {"step": len(steps) + 1, "tool": name, "args": arguments, "at": utc_iso()}
                t0 = time.perf_counter()
                try:
                    result = tools.call_tool(name, arguments)
                    content = _compact(result, MAX_TOOL_CHARS)
                    step["ok"] = True
                except Exception as exc:  # noqa: BLE001 - the LLM sees the error and can adapt
                    content = f"ERROR: {type(exc).__name__}: {exc}"
                    step["ok"] = False
                step["elapsed_ms"] = round((time.perf_counter() - t0) * 1000)
                step["result_preview"] = content[:200]
                steps.append(step)
                ledger.append(content)
                log(f"[step {step['step']}] {name}({json.dumps(arguments)[:80]}) -> {content[:140]}")
            messages.append({"role": "tool", "tool_call_id": call["id"], "content": content})
        if diagnosis:
            break

    if diagnosis is None:
        raise LLMError("The model never submitted a diagnosis")
    return {"diagnosis": diagnosis, "steps": steps, "ledger": ledger, "tokens": usage_tokens,
            "elapsed_s": round(time.perf_counter() - started, 1)}


def build_report(trigger: dict[str, Any], run: dict[str, Any]) -> dict[str, Any]:
    diagnosis = run["diagnosis"]
    check = verify(diagnosis, run["ledger"])
    confidence, notes = calibrate(diagnosis.get("confidence", 0), check)
    action = diagnosis.get("recommended_action") or {"action": "escalate_to_human", "reason": "none given"}
    escalate = confidence < MIN_CONFIDENCE or action.get("action") == "escalate_to_human"
    if escalate and action.get("action") != "escalate_to_human":
        action = {"action": "escalate_to_human", "target": action.get("target"),
                  "reason": f"Confidence {confidence} is below {MIN_CONFIDENCE}. "
                            f"Proposed fix kept for the human: {action.get('action')} {action.get('target') or ''}".strip(),
                  "proposed_fix": diagnosis.get("recommended_action")}
    incident = trigger.get("incident") or {}
    root = diagnosis.get("root_cause") or {}
    if root.get("category") not in CATEGORIES:
        root = {**root, "category": "unknown"}
    report = {
        "schema_version": "brain/1",
        "component": "brain",
        "incident_id": incident.get("id"),
        "generated_at": utc_iso(),
        "outcome": "escalated" if escalate else "diagnosed",
        "trigger": {k: incident.get(k) for k in ("id", "kind", "service", "title", "observed_value", "threshold", "severity")
                    if incident.get(k) is not None},
        "symptoms_summary": diagnosis.get("symptoms_summary"),
        "root_cause": root,
        "confidence": confidence,
        "model_confidence": diagnosis.get("confidence"),
        "confidence_notes": notes,
        "evidence": check["verified"],
        "unverified_evidence_dropped": check["dropped"],
        "alternatives_ruled_out": diagnosis.get("alternatives_ruled_out") or [],
        "recommended_action": action,
        "prevention": diagnosis.get("prevention"),
        "investigation": [{k: s[k] for k in ("step", "tool", "args", "ok", "elapsed_ms", "at")} for s in run["steps"]],
        "llm": {"model": LLM_MODEL, "tool_calls": len(run["steps"]), "tokens": run["tokens"], "elapsed_s": run["elapsed_s"]},
        "safety_note": "Diagnosis only: read-only tools, no feature-flag access, no changes made. "
                       "Any action requires human approval and goes through the Action API (Hands).",
    }
    report["schema_problems"] = validate_report(report)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="LLM root-cause diagnosis for an Eyes incident (read-only).")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--from-eyes", help="saved Eyes JSON (--once/--snapshot output or a --watch log)")
    source.add_argument("--service", help="manual alert: the service that looks affected")
    parser.add_argument("--symptom", help="manual alert: what is observed, e.g. 'checkout returns 500s'")
    parser.add_argument("--max-steps", type=int, default=MAX_STEPS, help=f"tool-call budget (default {MAX_STEPS})")
    parser.add_argument("--out", help="also write the report to this path")
    args = parser.parse_args(argv)
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

    trigger = load_trigger(args)
    if not trigger:
        print(json.dumps({"component": "brain", "outcome": "no_incident",
                          "note": "Eyes found no incident. Use --service/--symptom for a manual alert."}, indent=2))
        return 3
    log(f"Investigating {trigger['incident'].get('id')} with {LLM_MODEL} (max {args.max_steps} tool calls)")
    try:
        run = investigate(trigger, args.max_steps)
    except tools.ToolError as exc:
        log(f"Tool error: {exc}")
        return 1
    except LLMError as exc:
        print(json.dumps({"component": "brain", "outcome": "error", "error": str(exc)}, indent=2))
        return 1

    report = build_report(trigger, run)
    text = json.dumps(report, indent=2, ensure_ascii=False, default=str)
    print(text)
    REPORTS_DIR.mkdir(exist_ok=True)
    safe_id = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(report["incident_id"] or "incident"))
    saved = REPORTS_DIR / f"{datetime.now().strftime('%Y%m%d-%H%M%S')}_{safe_id}.json"
    saved.write_text(text + "\n", encoding="utf-8")
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
    log(f"Outcome: {report['outcome']} | root cause: {report['root_cause'].get('service')} "
        f"({report['root_cause'].get('category')}) | confidence {report['confidence']} | saved {saved}")
    return 0 if report["outcome"] == "diagnosed" else 2


if __name__ == "__main__":
    sys.exit(main())
