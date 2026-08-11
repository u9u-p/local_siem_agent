# Design Document: Agentic Analyst — Report Drafting + Self-Check (Phase 4d)

**Date:** 11 Aug 2026
**Source requirements:** CLAUDE.md §4.1 steps 7-8, §2.3 (`Report`), ROADMAP.md Phase 4d section

---

## Context

Phase 4c implemented the classification half of the Agentic Analyst state graph (Extract Indicators, Correlate, Risk Assessment) — real LLM calls, all schema-constrained, all validated or code-gated. Steps 7 (Draft Report) and 8 (Self-Check) are still stubs (`_stub_step` in `app/agent/state_graph.py`), and `_assemble_report` hardcodes placeholder text. This phase implements the report-generation half: the two-pass draft+critique loop, and the one place in the whole design with deliberately free-text (not closed-vocabulary) output.

Two items carried forward from Phase 4c's final review are folded into this same plan, per the "one plan, bigger task cluster" precedent set in 4c:

1. **Domain-regex over-extraction** (`app/agent/indicator_extraction.py`, flagged since Phase 4b): `_DOMAIN_RE` and `DomainIndicator`'s validator have no real-TLD check, so common filenames (`setup.exe`, `auth.log`) validate as DOMAIN candidates, route to `VirusTotalProvider`, and pollute `Report.enrichment_findings` with misleading rows.
2. **Prompt-capturing fake `LLMClient`** (flagged in 4c's final review): the existing `_FakeLLMClient` test double dispatches purely on schema class, so no test anywhere verifies that data threaded between steps (e.g. Correlate's `pattern_type` reaching Risk Assessment's prompt) actually reaches the prompt text. Phase 4d adds more cross-step threading (Draft-A's output reaching Self-Check), so this gap needs closing before it compounds.

This phase also adds a genuine extension beyond CLAUDE.md's original design, confirmed during brainstorming: a **false-positive/true-positive triage verdict**, explicitly flagged as experimental and never treated as vetted guidance — the same non-canonical pattern already established for `recommended_actions_freeform_experimental` in Phase 4c's design (not this phase's addition, but the precedent this one follows).

Decisions confirmed with the user during brainstorming:

1. **Action catalog enforcement** — one global fixed `RecommendedAction` enum (not narrowed per alert's `rule_groups` at the schema or code-validation level). Pydantic's own enum validation makes the field closed-vocabulary; no post-hoc code gate is needed for this field, unlike Extract Indicators.
2. **Domain-regex fix** — a blocklist of common non-TLD file extensions (not an allowlist of real TLDs), checked case-insensitively against the candidate's final dotted segment. Deliberate exception: `com` is NOT on the blocklist — it's the most common malicious TLD in practice, and blocking it to catch a rare legacy `.com`-executable filename would silently drop real malicious domains.
3. **Self-Check claim granularity** — `alert_summary` (1 claim) + `rationale` (1 claim) + each selected `recommended_action` (1 claim per action), audited individually.
4. **Scope** — domain-regex fix and the prompt-capturing fake are folded into this same plan, not split out.
5. **Triage verdict** — bundled into the existing Draft-B experimental call (not a new 7th LLM call); three-way `TRUE_POSITIVE / FALSE_POSITIVE / UNCERTAIN` vocabulary (not binary); accompanied by a one-sentence rationale field.

---

## 1. Domain-Regex Fix

**Files:** `app/agent/indicator_extraction.py`, `app/enrichment/indicators.py`

A new shared constant, `_FILENAME_EXTENSION_BLOCKLIST`, lives in `app/enrichment/indicators.py` (co-located with `DomainIndicator`, the authoritative gate) and is imported by `indicator_extraction.py` if it needs its own pre-filter — but since `extract_and_validate` already routes every regex candidate through `DomainIndicator` for validation (the "merge gate" pattern from Phase 4c), fixing the validator alone is sufficient; `_DOMAIN_RE` in `indicator_extraction.py` itself does not need to change.

```python
_FILENAME_EXTENSION_BLOCKLIST = frozenset({
    "exe", "dll", "so", "dylib", "bin", "msi", "bat", "ps1", "sh", "py", "rb", "pl",
    "php", "jar", "class", "log", "txt", "csv", "tsv", "json", "xml", "yaml", "yml",
    "conf", "cfg", "ini", "pem", "key", "crt", "cer", "csr", "db", "sql", "bak",
    "tmp", "dat", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "zip", "tar",
    "gz", "rar", "htm", "html", "css", "ts", "go", "rs", "cpp", "obj", "sys", "vbs",
    "scr", "apk", "deb", "rpm", "war",
})
```

`DomainIndicator._validate_domain` rejects a candidate whose final dotted segment (lowercased) is in this set, after the existing `_DOMAIN_RE` structural match:

```python
@field_validator("value")
@classmethod
def _validate_domain(cls, v: str) -> str:
    if not _DOMAIN_RE.match(v):
        raise ValueError(f"not a valid domain name: {v}")
    tld = v.rsplit(".", 1)[-1].lower()
    if tld in _FILENAME_EXTENSION_BLOCKLIST:
        raise ValueError(f"looks like a filename, not a domain: {v}")
    return v.lower()
```

No change to `Indicator`'s public shape; existing callers (Extract Indicators regex path and LLM-assisted path, both of which already funnel through this validator) get the fix automatically.

---

## 2. New Schemas (`app/agent/schemas.py`)

```python
class RecommendedAction(str, Enum):
    DISABLE_OR_RESET_ACCOUNT = "Disable or reset credentials for the affected user account"
    BLOCK_SOURCE_IP = "Block the source IP at the network perimeter"
    ISOLATE_HOST = "Isolate the affected host from the network pending investigation"
    ESCALATE_TO_IR = "Escalate to the incident response / Tier 2 team"
    REVIEW_AUTH_LOGS_WIDER_WINDOW = "Review authentication logs for this account over a wider time window"
    VERIFY_EXPECTED_SOURCE = "Verify whether the source IP/user is a known, expected service account or automation"
    RUN_AV_EDR_SCAN = "Run an antivirus/EDR scan on the affected host"
    REVIEW_FIM_BASELINE = "Review file integrity monitoring output for unauthorized changes on the affected host"
    PATCH_VULNERABLE_SOFTWARE = "Patch or update the vulnerable software identified for this host"
    NOTIFY_ASSET_OWNER = "Notify the asset owner of the affected host or agent"
    ROTATE_EXPOSED_CREDENTIALS = "Rotate any credentials or secrets that may have been exposed"
    REVIEW_FIREWALL_SEGMENTATION = "Review firewall/network segmentation rules for the affected subnet"
    CORRELATE_WIDER_ENVIRONMENT = "Correlate this indicator against the wider environment beyond this alert's time window"
    PRESERVE_EVIDENCE = "Preserve logs and evidence for the affected host pending further investigation"
    MONITOR_NO_ACTION = "No immediate action needed — monitor for recurrence"
    ESCALATE_TO_HUMAN_ANALYST = "Escalate to a human analyst for manual review"


class TriageVerdict(str, Enum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    UNCERTAIN = "uncertain"


class DraftReportCanonical(BaseModel):
    alert_summary: str
    rationale: str
    recommended_actions: list[RecommendedAction]


class DraftReportExperimental(BaseModel):
    recommended_actions_freeform: list[str]
    triage_verdict: TriageVerdict
    triage_rationale: str


class ClaimAudit(BaseModel):
    claim: str
    supported: bool
    correction: str | None = None


class SelfCheckResult(BaseModel):
    audits: list[ClaimAudit]
```

`RecommendedAction.ESCALATE_TO_HUMAN_ANALYST` doubles as the safe fallback value used when Draft-A's LLM call fails (see §3).

---

## 3. Draft Report — Step 7 (`app/agent/state_graph.py`, `app/agent/prompts.py`)

Two calls, both always run (not conditional on anything from Correlate — that conditionality belongs to the open-value search in step 5, not here):

- **Call 4 — Draft-A (canonical):** `build_draft_canonical_prompt(alert, pattern_type, evidence_count, enrichment_results, risk_assessment)` → `DraftReportCanonical`. Inputs are the same structured findings Risk Assessment (step 6) saw, plus step 6's own `RiskAssessment` output (severity, confidence, terse rationale) so Draft-A can expand the rationale coherently. **Never sees `full_log`** — consistent with the grounding discipline established from step 3 onward. The prompt lists all 16 `RecommendedAction` values as the closed menu to multi-select from.
- **Call 5 — Draft-B (experimental):** `build_draft_experimental_prompt(alert, pattern_type, evidence_count, enrichment_results, risk_assessment)` → `DraftReportExperimental`. Same structured findings as Draft-A, asked to (a) freely compose action sentences with no catalog constraint, and (b) classify whether this alert looks like a true or false positive, with a one-sentence rationale.

Both prompt builders take the same parameter shape as `build_risk_assessment_prompt` already does, so no new data needs to reach step 7 that step 6 didn't already have — `_step_risk_assessment`'s return value (the `RiskAssessment`) is threaded into `_step_draft_report`'s inputs the same way `pattern_type`/`evidence_count` already thread from Correlate into Risk Assessment today.

**Final report values.** `Report.risk_assessment` in the finished report is `RiskAssessment(severity=<step 6>, confidence=<step 6>, rationale=<Draft-A's expanded rationale>)` — severity/confidence are never re-decided by Draft-A, only the prose rationale is replaced. `Report.recommended_actions` is the list of `.value` strings from Draft-A's `recommended_actions` (post Self-Check corrections, see §4). `Report.recommended_actions_freeform_experimental`, `Report.triage_verdict_experimental`, `Report.triage_rationale_experimental` come directly from Draft-B, untouched by Self-Check.

**Failure handling** (§4.2 rule 1 — retry once, then safe default, never block the pipeline). The templated fallback summary, reused by both cases below, is built deterministically from alert fields already available: `f"Rule {alert.rule_id} ({alert.rule_description}), level {alert.rule_level}, on agent {alert.agent.name}."`
- Draft-A `LLMClientError` (call attempted, errored) → `DraftReportCanonical(alert_summary=<templated fallback>, rationale="draft report failed: {exc.kind}", recommended_actions=[RecommendedAction.ESCALATE_TO_HUMAN_ANALYST])`.
- Draft-A skipped (`model_available=False`, call never attempted) → same templated `alert_summary` and same one-action list, but `rationale="draft report skipped: model unavailable"` — the "skipped" (no attempt) vs "failed: {exc.kind}" (attempted, errored) wording split already used by `_step_risk_assessment`, kept consistent here.
- Draft-B `LLMClientError` or `model_available=False` → `None` for all three experimental fields either way (matches Phase 4c's existing pattern for optional/degraded outputs — no partial fallback, since nothing downstream depends on Draft-B succeeding, so the two cases don't need distinct wording).

`InvestigationStep` for this step logs whether each of the two calls succeeded or fell back, mirroring the existing `failed_note`/`follow_up_note` string-building style already used in `_step_correlate`.

---

## 4. Self-Check — Step 8 (`app/agent/state_graph.py`, `app/agent/prompts.py`)

**Call 6 — Self-Check:** a fresh call (no chat history, no access to Draft-A's reasoning) given Draft-A's output plus the same structured findings Draft-A saw. `build_self_check_prompt(draft, pattern_type, evidence_count, enrichment_results, risk_assessment)` → `SelfCheckResult`.

**Claim construction** (code-side, before the call): exactly `2 + len(draft.recommended_actions)` claims — the `alert_summary` string, the `rationale` string, and each `RecommendedAction.value` string — assembled into the prompt as a numbered list the model audits one-for-one, returning one `ClaimAudit` per claim in the same order.

**Applying corrections (code, deterministic, no further free-form editing pass):**
- `alert_summary` / `rationale` claims: if `supported=False` and `correction` is non-null, replace the field's text with the correction. If `supported=False` and `correction` is null, keep the original text (best effort) and note the gap in `uncertainty_notes`.
- Each `recommended_action` claim: if `supported=False`, **drop that action from the final `recommended_actions` list** — a correction string is never substituted into this field, since that would inject free text into what must stay closed-vocabulary. If dropping leaves the list empty, append `RecommendedAction.ESCALATE_TO_HUMAN_ANALYST` as a safety net (the report must never recommend zero actions to a human analyst). This append is unconditional whenever the corrected list is empty — including the edge case where `ESCALATE_TO_HUMAN_ANALYST` itself was the one action Draft-A picked and Self-Check flagged it unsupported. The safety net's job is only to guarantee non-empty output, not to make a truth judgement about that specific action, so it is exempt from being re-dropped by the claim it was just re-added for.

**`uncertainty_notes` — computed in code, not an LLM output field**, per CLAUDE.md's explicit "not the model's self-assessed confidence" rule and consistent with `evidence_count` already being code-computed in Phase 4c. Built as a joined list of whichever of these apply:
- Any claim flagged unsupported without a correction (quoted verbatim).
- Any `EnrichmentResult` with `error is not None` or `verdict == EnrichmentVerdict.UNKNOWN`.
- The correlation follow-up query was never triggered (`CorrelationDecision.follow_up_query == SearchTemplate.NONE_NEEDED`) or the open-value search never ran (`pattern_type` was not `NONE`/`OTHER`) — i.e. the closed correlation menu was left partially or fully unused.
- `alert.mitre` was empty (no MITRE mapping available from the Wazuh decoder).

If none of these apply, `uncertainty_notes = ""` (matches the field's existing default).

**Self-Check `LLMClientError` fallback:** skip corrections entirely (Draft-A's output stands as-is), and add `"self-check could not run: {exc.kind}"` to `uncertainty_notes` unconditionally — this alone is enough to force `Report.status` to `NEEDS_HUMAN_REVIEW` (see §5). When `model_available` is `False` from the start, the call is never attempted and the note reads `"self-check skipped: model unavailable"` instead — the same "skipped" (no attempt) vs "failed: {exc.kind}" (attempted, errored) wording split `_step_risk_assessment` already uses today, kept consistent here rather than introducing a third phrasing.

---

## 5. Wiring (`app/agent/state_graph.py`)

`investigate()` gains two real steps between Risk Assessment and Finalize, replacing the current `_step_draft_report(model_available)` / `_step_self_check(model_available)` stub calls:

```python
draft, draft_step = self._step_draft_report(alert, pattern_type, evidence_count, enrichment_results, risk_assessment, model_available)
timeline.append(draft_step)

final_report_fields, self_check_step = self._step_self_check(draft, pattern_type, evidence_count, enrichment_results, risk_assessment, model_available)
timeline.append(self_check_step)
```

When `model_available` is `False`, both steps skip their LLM calls and produce the same safe defaults as their `LLMClientError` fallback paths (templated `alert_summary`, `ESCALATE_TO_HUMAN_ANALYST`, empty experimental fields, `uncertainty_notes` noting the model was unavailable) — consistent with how `_step_risk_assessment` already handles `model_available=False` as a degraded-but-still-populated path, not a hard skip.

**`Report.status` determination** (code, in `_assemble_report`): track a single boolean `degraded` accumulated across the whole `investigate()` run — `True` if the model was ever unavailable, or any of the extraction/correlation/risk-assessment/draft/self-check LLM calls fell back on an `LLMClientError`. `Report.status = ReportStatus.COMPLETE` if `not degraded`, else `ReportStatus.NEEDS_HUMAN_REVIEW`. `ReportStatus.DRAFT` remains defined on the enum but unused by this pipeline (reserved for a future phase, e.g. a UI that shows in-progress investigations) — this is an existing enum value from Phase 1, not something this phase needs to remove.

`_assemble_report`'s hardcoded Phase 4c placeholder text (`"Stub report for alert..."`, the static `uncertainty_notes` string, `recommended_actions=[]`) is replaced with the real values threaded from steps 7-8.

---

## 6. Prompt-Capturing Fake `LLMClient`

**File:** `tests/test_state_graph.py`

`_FakeLLMClient.generate_structured` gains one line: append `(prompt, schema)` to a new `self.calls: list[tuple[str, type]]` before dispatching to the existing `responses`/`error` logic. No behavior change to existing tests (nothing reads `self.calls` unless a test asserts on it). New tests introduced by this phase's tasks use it to assert, e.g., that the Self-Check prompt (matched via `schema is SelfCheckResult`) contains Draft-A's actual `alert_summary` text, and that Draft-A's prompt contains the real `pattern_type` value Correlate produced for that test's fixture — closing the "wiring is correct on inspection but unverified" gap from 4c's final review.

---

## 7. Testing

- `tests/test_indicators.py` (or wherever `DomainIndicator` is currently tested): new cases proving `setup.exe`, `auth.log`, `invoice.pdf` are rejected, and that `evil.com` (a real, non-blocklisted TLD) still validates — proving the blocklist doesn't overreach.
- `tests/test_state_graph.py`: extend the 3 shared end-to-end tests' `_FakeLLMClient.responses` with `DraftReportCanonical`, `DraftReportExperimental`, and `SelfCheckResult` entries, mirroring how Phase 4c incrementally built these up per task. New unit tests for `_step_draft_report` (success, Draft-A failure, Draft-B failure, model unavailable) and `_step_self_check` (all claims supported, an unsupported free-text claim with/without correction, an unsupported action claim causing a drop, an unsupported action claim that empties the list entirely, self-check call failure).
- New tests using the prompt-capturing fake (§6) to verify cross-step data threading into Draft-A's and Self-Check's actual prompt text.
- `uncertainty_notes` construction: a dedicated unit test per structural-gap source (errored enrichment, `UNKNOWN` enrichment, unused follow-up menu, unused open-value search, missing MITRE mapping, unsupported claim without correction) plus a test proving `Report.status` flips to `NEEDS_HUMAN_REVIEW` when any degradation occurred and `COMPLETE` when none did.

---

## Open Items

None outstanding — all decisions confirmed during brainstorming (see Context, decisions 1-5).
