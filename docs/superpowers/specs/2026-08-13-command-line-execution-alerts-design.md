# Design Document: Command-Line Execution Alert Investigation

**Date:** 13 Aug 2026
**Source requirements:** CLAUDE.md §4.1 (Agentic Analyst state graph), ROADMAP.md Phase 4 (complete baseline this extends)

---

## Context

The Agentic Analyst's 9-step FSM (`app/agent/state_graph.py`) currently investigates alerts using only generic, SIEM-common fields — `source_ip`, `destination_ip`, `src_user`, `full_log` — and extracts network/identity-style indicators (IP, domain, URL, hash, email) via regex + LLM. It has no notion of process execution or command lines: `Alert.data` is a free-form dict holding whatever a Wazuh decoder produces, and nothing today reads a command-line field specifically, decodes obfuscated command arguments, or reasons about process-creation context.

This extends the pipeline to investigate **Windows Sysmon Event ID 1 (process creation)** alerts — decoding common obfuscation in the command line (base64, PowerShell `-EncodedCommand`, hex, URL-encoding) so hidden indicators become visible to the existing extraction pipeline, and giving the model bounded, structured command context to reason about freely in its existing closed-vocabulary outputs.

A real, pre-existing gap surfaced during brainstorming: `extract_and_validate()` (`app/agent/indicator_extraction.py`) only scans *top-level* string values of `alert.data` — Sysmon's fields live nested under `data.win.eventdata.*`, so they are invisible to indicator extraction today, independent of this feature. This design fixes that specifically for the fields it promotes to typed `Alert` fields; the broader nested-dict-scanning gap for other decoders is out of scope.

Decisions confirmed with the user during brainstorming:

1. **Scope** — Windows Sysmon Event ID 1 only, for now. Trigger condition is **data presence** (`Alert.process` populated), not rule identity — Sysmon can trigger many different Wazuh rule IDs, and this must apply to all of them, not one hardcoded rule.
2. **Decode scope** — common encoding schemes only (base64 incl. PowerShell `-enc`/`-EncodedCommand`, hex, URL-encoding), all deterministic. No LLM-assisted deobfuscation, no closed-vocabulary suspicious-pattern/LOLBin catalog — the model reasons about suspiciousness freely in its existing free-text `rationale`/`alert_summary` outputs, not through a rigid pattern gate.
3. **No new LLM call.** Decoded command context is added as bounded, structured input to the *existing* Risk Assessment / Draft Report / Self-Check calls. The 6-fixed-calls budget (CLAUDE.md §4.1) is unchanged.
4. **Decode is folded into Extract Indicators**, not a separate FSM step — its only purpose is feeding that step's regex/LLM extraction (a hidden IOC inside a base64 blob is invisible to regex until decoded), so a separate step would exist only to hand its output to the next one.
5. **Field mapping stays static and Sysmon-only for now**, explicitly structured as a short list of extractor functions (not a big config system) so a future decoder (auditd, macOS ES) is "add one function to the list," not a rewrite of `wazuh_source_to_alert()`. Config-driven mapping is a possible future evolution, not built now (YAGNI).
6. **Field mapping is NOT LLM-driven.** Considered and rejected: Sysmon's JSON shape is fixed and known, so there's no genuine ambiguity for an LLM to resolve — using one here would add latency and a new silent-misextraction failure mode for zero benefit, and would undermine the report's traceability guarantees. (LLM-assisted *authoring* of a new decoder's mapping, offline and human-reviewed, remains a reasonable future dev-time tool — not part of this design.)
7. **Alert gets one composite field**, `Alert.process: ProcessExecutionFields | None`, not several flat fields — keeps `Alert`'s core shape stable and gives a template for any future alert category (each gets one optional sub-object) without deciding now what those look like.
8. **Extend the `RecommendedAction` catalog** with a small number of process-response-specific entries.
9. **Extend Correlate** with one new canonical search template for command-line alerts.

---

## 1. Data Model

### `app/schemas.py`

```python
class ProcessExecutionFields(BaseModel):
    command_line: str | None = None
    parent_command_line: str | None = None
    process_name: str | None = None
    parent_process_name: str | None = None
    process_id: str | None = None
    parent_process_id: str | None = None
    process_hashes: str | None = None  # raw Sysmon Hashes field, e.g. "MD5=X,SHA256=Y,IMPHASH=Z"
```

`Alert` gains one field: `process: ProcessExecutionFields | None = None`.

### `app/integration/process_field_extractors.py` (new)

```python
def _extract_sysmon_fields(data: dict[str, Any]) -> ProcessExecutionFields | None:
    eventdata = data.get("win", {}).get("eventdata", {})
    command_line = eventdata.get("commandLine")
    if not command_line:
        return None
    return ProcessExecutionFields(
        command_line=command_line,
        parent_command_line=eventdata.get("parentCommandLine"),
        process_name=eventdata.get("image"),
        parent_process_name=eventdata.get("parentImage"),
        process_id=eventdata.get("processId"),
        parent_process_id=eventdata.get("parentProcessId"),
        process_hashes=eventdata.get("hashes"),
    )


_EXTRACTORS: list[Callable[[dict[str, Any]], ProcessExecutionFields | None]] = [_extract_sysmon_fields]


def extract_process_fields(data: dict[str, Any]) -> ProcessExecutionFields | None:
    for extractor in _EXTRACTORS:
        result = extractor(data)
        if result is not None:
            return result
    return None
```

The trigger condition used everywhere else in the pipeline (Extract Indicators, Risk Assessment, Report) is simply `alert.process is not None` — nothing downstream ever checks rule ID, rule group, or event ID. Adding a second decoder (auditd, macOS ES) later means writing one new `_extract_*_fields` function and appending it to `_EXTRACTORS` — zero changes anywhere else.

**`wazuh_source_to_alert()`** (`app/integration/wazuh_connector.py`) gains one line: `process=extract_process_fields(data)`.

---

## 2. Command Decoding (`app/agent/command_decode.py`, new)

A pure module — takes plain strings in, no `Alert`/Pydantic coupling beyond its own small output schema — independently testable.

```python
class DecodedSegment(BaseModel):
    encoding: Literal["powershell_encoded", "base64", "hex", "url"]
    original: str
    decoded: str


def decode_command_segments(process: ProcessExecutionFields) -> tuple[list[DecodedSegment], int, int]:
    """Returns (segments, attempted_count, discarded_count)."""
```

Scans `process.command_line` and `process.parent_command_line` (not `full_log` — bounded to these two fields):

1. **PowerShell encoded command** — regex for `-e(?:nc(?:odedcommand)?)?\s+([A-Za-z0-9+/=]{20,})` (case-insensitive), base64-decode, then try UTF-16LE decode first (PowerShell's actual encoding), falling back to UTF-8.
2. **Generic base64** — token regex on remaining text (`[A-Za-z0-9+/]{20,}={0,2}`), base64-decode.
3. **Hex** — long even-length hex runs (`(?:[0-9a-fA-F]{2}){10,}`), `bytes.fromhex`.
4. **URL-encoding** — presence of `%[0-9A-Fa-f]{2}` sequences, `urllib.parse.unquote`; only accepted if the result differs from the input.

Schemes are tried in the order above, and each match **consumes its matched span** — the generic base64 scanner (2) skips any text already matched by the PowerShell-specific pattern (1), and the hex scanner (3) skips spans already claimed by (1) or (2), so the same substring is never decoded twice under two different schemes.

**Merge gate, mirroring the existing indicator-extraction pattern exactly:** every decode attempt is validated against a printable-ratio threshold (e.g. ≥90% printable ASCII/UTF-8 characters) before being accepted. Failed decodes are **discarded, not corrected or retried** — counted, not detailed, consistent with the existing "N proposed, M validated, K discarded" style. Decode/format errors (`binascii.Error`, `UnicodeDecodeError`) are caught narrowly per attempt and treated as a discard, never propagated.

---

## 3. Extract Indicators Integration (step 3, unchanged step boundary)

`extract_and_validate()` (`app/agent/indicator_extraction.py`) gains an `extra_texts: list[str] = []` parameter, appended to its existing `text_sources` list before regex scanning — no change to its regex/validation logic itself.

`_step_extract_indicators` in `state_graph.py` becomes the orchestrator (mirroring how it already orchestrates regex + LLM merge today):

```python
decoded_segments, decode_attempted, decode_discarded = (
    decode_command_segments(alert.process) if alert.process else ([], 0, 0)
)
extra_texts = [t for t in (
    [alert.process.command_line, alert.process.parent_command_line, alert.process.process_hashes]
    if alert.process else []
) + [s.decoded for s in decoded_segments] if t]

validated, candidate_count, validated_count = extract_and_validate(alert, extra_texts=extra_texts)
```

This is also the fix for the nested-Sysmon-field gap noted in Context: `command_line`/`parent_command_line`/`process_hashes` (and any IOC decoded out of an obfuscated blob) become reachable by the same existing regex + LLM-assisted extraction, unchanged.

`CommandDecodeResult` (the object threaded forward to steps 6/7/8 and the final `Report`) is assembled here:

```python
class CommandDecodeResult(BaseModel):
    command_line: str | None
    parent_command_line: str | None
    decoded_segments: list[DecodedSegment]
```

`None` when `alert.process` is `None`.

**Timeline summary extends:** `"regex: 3 candidates, 2 validated; command decode: 2 segment(s) decoded, 1 discarded; LLM: 4 candidates, 3 validated"`.

---

## 4. Risk Assessment / Draft Report / Self-Check — bounded context, no new call

`build_risk_assessment_prompt`, `build_draft_canonical_prompt`, `build_draft_experimental_prompt`, and `build_self_check_prompt` (`app/agent/prompts.py`) each gain an optional `command_context: CommandDecodeResult | None` parameter, included in the structured JSON input block when not `None` (each string field truncated to a fixed cap, e.g. 500 chars, to keep prompts bounded per CLAUDE.md §4.2 rule 2).

This is a deliberate, scoped exception to "never `full_log` again past step 2" — `command_context` is a small, already-decoded, already-typed artifact (like enrichment verdicts or `pattern_type`), not the raw alert. The model is free to reason about suspiciousness in prose (`rationale`, `alert_summary`); the *decision* outputs stay exactly as closed-vocabulary as they are today (`severity`, `confidence`, `recommended_actions`). No new schema, no new call, no change to the 6-fixed-calls budget.

Self-Check receives the same `command_context` Draft-A saw, consistent with rule 3 ("same structured findings, not Draft-A's reasoning").

---

## 5. `RecommendedAction` catalog additions (`app/agent/schemas.py`)

Three new entries, appended to the existing 16-member enum:

```python
TERMINATE_SUSPICIOUS_PROCESS = "Terminate the suspicious process on the affected host"
REVIEW_PROCESS_EXECUTION_TREE = "Review the parent-child process execution tree for the affected host"
REVIEW_DECODED_COMMAND_PAYLOAD = "Manually review the decoded command payload for malicious intent"
```

No other changes to the enum or to how Draft-A/Self-Check select/audit actions — this is additive to an already-closed vocabulary.

---

## 6. Correlate — new canonical search template

Sysmon process-creation alerts typically have no `source_ip`/`destination_ip`, so today's canonical searches (`build_canonical_queries`, `app/agent/correlation_queries.py`) would reduce to just "same rule, same host" for these alerts. Add one new template, conditioned on `alert.process.command_line` being present:

```python
if alert.process and alert.process.command_line:
    queries[SearchTemplate.SAME_COMMAND_LINE_ENV_WIDE] = SearchQuery(
        clauses=[SearchClause(field="data.win.eventdata.commandLine", operator="eq", value=alert.process.command_line)],
        time_range=window,
    )
else:
    queries[SearchTemplate.SAME_COMMAND_LINE_ENV_WIDE] = None
```

Runs unconditionally alongside the other canonical searches (not host-scoped — deliberately environment-wide) so evidence distinguishes an isolated single-host event from the same command executing across many hosts (mass/scripted deployment). Its `total_count` folds into `evidence_count` exactly like the other three canonical templates; no change to `CorrelationDecision`'s schema or the follow-up/open-value-search logic.

`SearchTemplate` enum gains `SAME_COMMAND_LINE_ENV_WIDE`; it participates in the existing closed follow-up-query menu the LLM already picks from in step 5's `CorrelationDecision.follow_up_query`.

---

## 7. `Report` addition

```python
command_analysis: CommandDecodeResult | None = None
```

Populated in `_assemble_report` directly from the `CommandDecodeResult` produced in step 3 — gives an analyst visibility into exactly what was decoded, independent of whether the LLM's prose happened to mention it.

---

## 8. Wiring summary (`app/agent/state_graph.py`)

- `_step_extract_indicators` returns `(indicators, command_decode_result, InvestigationStep)` instead of `(indicators, InvestigationStep)`.
- `command_decode_result` threads into `_step_risk_assessment`, `_step_draft_report`, `_step_self_check` alongside the parameters they already take (`pattern_type`, `evidence_count`, `enrichment_results`, ...) — same threading pattern already used for those.
- `_assemble_report` takes `command_decode_result` and sets `Report.command_analysis`.
- No change to the FSM's step count, step order, or LLM-call count. `model_available=False` path: decoding still runs (it's deterministic, not LLM-gated) — only the LLM-assisted half of Extract Indicators and everything downstream skip as they already do.

---

## 9. Testing

- `tests/test_process_field_extractors.py` (new): Sysmon shape parses correctly; missing/malformed `data.win.eventdata` returns `None`; a non-Sysmon alert (`data` without `win`) returns `None`.
- `tests/test_command_decode.py` (new): each encoding scheme decodes correctly; garbage/non-printable decode attempts are discarded via the printable-ratio gate; a plain unencoded command line produces zero segments; PowerShell `-enc`/`-EncodedCommand`/`-e` variants all recognized.
- `tests/test_wazuh_alert_mapper.py`: extend to assert `Alert.process` is populated from a Sysmon-shaped fixture and `None` for existing non-Sysmon fixtures (regression check).
- `tests/test_indicator_extraction.py`: extend for `extra_texts` — an IOC present only inside a decoded segment is found; existing regex-only behavior unchanged when `extra_texts=[]`.
- `tests/test_state_graph.py`: new end-to-end case — a Sysmon alert with an encoded PowerShell command containing an embedded IP is decoded, the IP is extracted and enriched, `Report.command_analysis` is populated, and the existing non-Sysmon test fixtures remain green (`alert.process is None` path fully unaffected). New test for `SAME_COMMAND_LINE_ENV_WIDE` query construction and its `evidence_count` contribution.
- Prompt-builder tests (`tests/test_agent_schemas.py` or a new `tests/test_prompts.py` if one doesn't already exist): `command_context` appears in Risk Assessment / Draft Report / Self-Check prompt text when present, absent when `alert.process is None`.

---

## Open Items

None outstanding — all decisions confirmed during brainstorming (see Context, decisions 1-9).
