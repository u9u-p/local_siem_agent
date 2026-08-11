# Agentic Analyst — Report Drafting + Self-Check Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement state-graph steps 7 (Draft Report: canonical + experimental) and 8 (Self-Check), replacing their current stubs, plus two carried-forward fixes: the domain-regex over-extraction bug and a prompt-capturing fake `LLMClient` test double.

**Architecture:** Two new LLM calls in step 7 (Draft-A canonical schema-constrained; Draft-B experimental, including a new FP/TP triage verdict), one new LLM call in step 8 (Self-Check, auditing Draft-A's claims one-for-one and returning code-applied corrections), and a new cross-cutting `self._degraded_reasons` accumulator on `AgenticAnalyst` that determines the final `Report.status` from every degradation source across the whole investigation, not just this phase's own calls.

**Tech Stack:** Same as the rest of the project — Pydantic schemas, Ollama-backed `LLMClient.generate_structured`, pytest.

## Global Constraints

- Every LLM call in this phase is schema-constrained via `generate_structured(prompt, schema)`; on `LLMClientError` each call falls back to a safe default and never raises out of `investigate()` — no unbounded retries (CLAUDE.md §4.2 rule 1).
- Grounding: none of this phase's prompts see `alert.full_log` or `alert.data` — only the same structured findings Risk Assessment (step 6) already saw, plus step 6's own `RiskAssessment` output (CLAUDE.md §4.2 rule 2).
- `recommended_actions` is a **global fixed `RecommendedAction` enum**, not narrowed per alert's `rule_groups` — Pydantic's own enum validation makes this field closed-vocabulary; no extra code-side gate is needed for it (unlike Extract Indicators' regex/LLM merge gate).
- `RecommendedAction.ESCALATE_TO_HUMAN_ANALYST` is the universal safe-default action — used whenever Draft-A's call fails and whenever Self-Check would otherwise leave `recommended_actions` empty.
- The domain-regex fix blocklists common file extensions but deliberately **excludes `com`** — it is the most common malicious TLD in practice, and blocking it to catch a rare legacy `.com`-executable filename would silently drop real malicious domains.
- Self-Check claims are exactly `alert_summary` (1) + `rationale` (1) + each selected `recommended_action` (1 each), audited **positionally** — the model returns one `ClaimAudit` per claim in the same order it was given them. If the returned count doesn't match, treat it as a self-check failure (skip corrections) rather than trying to reconcile a mismatched list.
- Corrections apply asymmetrically: `alert_summary`/`rationale` (free text) get replaced by a correction string when unsupported; a `recommended_action` claim that's unsupported is **dropped from the list**, never replaced with free text — a correction string must never be injected into a field that must stay closed-vocabulary.
- `uncertainty_notes` is **computed deterministically in code**, never an LLM output field — CLAUDE.md is explicit that this must not be "the model's self-assessed confidence."
- Draft-B (experimental: freeform actions + FP/TP triage verdict + rationale) is bundled into **one** call, is never audited by Self-Check, and its failure never forces `Report.status` to `NEEDS_HUMAN_REVIEW` on its own — it is explicitly non-canonical, so nothing downstream depends on it succeeding.
- `Report.model_metadata.prompt_version` becomes `"4d-v1"` (this phase introduces new prompt templates project-wide) — bumped once, in Task 6, not per-task.
- `self._degraded_reasons: list[str]` must be **initialized in `__init__`** (not only reset inside `investigate()`), because several existing tests call step methods directly without going through `investigate()` first — an uninitialized attribute would raise `AttributeError` the moment those methods try to append to it.

---

### Task 1: Domain-regex over-extraction fix

**Files:**
- Modify: `app/enrichment/indicators.py`
- Modify: `tests/test_enrichment_indicators.py`
- Modify: `tests/test_indicator_extraction.py:47-60` (one existing assertion currently expects the bug's behavior)

**Interfaces:**
- Produces: no new public names — `DomainIndicator`'s existing validator behavior changes (stricter), nothing else in its signature changes.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_enrichment_indicators.py`, right after the existing `test_rejects_domain_with_trailing_newline` (around line 100):

```python
def test_rejects_common_filenames_as_domains():
    for filename in ("setup.exe", "auth.log", "invoice.pdf", "readme.txt", "config.json"):
        with pytest.raises(ValidationError):
            DomainIndicator(value=filename)


def test_still_accepts_real_dot_com_domain():
    assert DomainIndicator(value="evil.com").value == "evil.com"
```

`pytest` and `ValidationError` are already imported at the top of this file (used by the existing `test_rejects_malformed_domain` etc.) — no new imports needed.

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_enrichment_indicators.py -k "filenames_as_domains or dot_com" -v`
Expected: `test_rejects_common_filenames_as_domains` FAILS (currently `setup.exe` etc. validate successfully, so `pytest.raises` never fires). `test_still_accepts_real_dot_com_domain` PASSES already (no change needed for this one — it's here to prove the fix doesn't overreach).

- [ ] **Step 3: Add the blocklist and tighten the validator**

In `app/enrichment/indicators.py`, add the blocklist constant right after `_DOMAIN_RE` (around line 32):

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

Then update `DomainIndicator._validate_domain` (currently around line 55):

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

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_enrichment_indicators.py -v`
Expected: all PASS, including the two new tests.

- [ ] **Step 5: Fix the now-outdated existing assertion**

`tests/test_indicator_extraction.py:47-60` (`test_extract_and_validate_discards_invalid_candidates_and_counts_correctly`) currently asserts `payload.exe` validates as a `DomainIndicator` — that assertion documents the exact bug this task fixes. Update it:

```python
def test_extract_and_validate_discards_invalid_candidates_and_counts_correctly():
    alert = _make_alert(full_log=_SAMPLE_LOG)

    validated, candidate_count, validated_count = extract_and_validate(alert)

    assert candidate_count == 7
    assert validated_count == 5
    values_by_type = {(type(i), i.value) for i in validated}
    assert (IPIndicator, "203.0.113.5") in values_by_type
    assert (HashIndicator, "a" * 64) in values_by_type
    assert (URLIndicator, "http://malicious-example.test/payload.exe") in values_by_type
    assert (DomainIndicator, "evil-domain.test") in values_by_type
    assert (DomainIndicator, "malicious-example.test") in values_by_type
    assert (DomainIndicator, "payload.exe") not in values_by_type
```

Only `validated_count` (6 → 5) and the last two lines change. `candidate_count` stays 7 — the raw regex still extracts `payload.exe` as a *candidate* string before validation; only validation now rejects it.

- [ ] **Step 6: Run the full test suite**

Run: `pytest tests/ -v`
Expected: all PASS (this fix only tightens one validator; nothing else in the codebase currently depends on filenames validating as domains).

- [ ] **Step 7: Commit**

```bash
git add app/enrichment/indicators.py tests/test_enrichment_indicators.py tests/test_indicator_extraction.py
git commit -m "fix: reject common filenames as domain indicators"
```

---

### Task 2: Prompt-capturing fake `LLMClient`

**Files:**
- Modify: `tests/test_state_graph.py:87-104` (`_FakeLLMClient`)

**Interfaces:**
- Produces: `_FakeLLMClient.calls: list[tuple[str, type]]` — every `(prompt, schema)` pair passed to `generate_structured`, in call order. Later tasks' tests read this to verify cross-step data actually reaches a given prompt's text.

- [ ] **Step 1: Write the failing test**

Add anywhere in `tests/test_state_graph.py` after `_FakeLLMClient`'s definition (e.g. right before `_make_alert`):

```python
def test_fake_llm_client_records_prompt_and_schema_per_call():
    client = _FakeLLMClient(responses={RiskAssessment: RiskAssessment(
        severity=Severity.LOW, confidence=Confidence.LOW, rationale="x"
    )})

    client.generate_structured("first prompt", RiskAssessment)
    client.generate_structured("second prompt", RiskAssessment)

    assert client.calls == [("first prompt", RiskAssessment), ("second prompt", RiskAssessment)]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_state_graph.py -k test_fake_llm_client_records_prompt_and_schema_per_call -v`
Expected: FAIL with `AttributeError: '_FakeLLMClient' object has no attribute 'calls'`.

- [ ] **Step 3: Add call recording**

Update `_FakeLLMClient` (`tests/test_state_graph.py:87-104`):

```python
class _FakeLLMClient:
    def __init__(self, model_available=True, responses=None, error=None):
        self._model_available = model_available
        self._responses = responses or {}  # {schema_class: return_value}
        self._error = error
        self.calls: list[tuple[str, type]] = []

    def generate_structured(self, prompt, schema):
        self.calls.append((prompt, schema))
        if self._error is not None:
            raise self._error
        if schema in self._responses:
            return self._responses[schema]
        raise NotImplementedError(f"no canned response configured for {schema}")

    def health_check(self):
        return True

    def model_available(self):
        return self._model_available
```

The call is recorded even when `self._error` is set or no response is configured — a caller may want to assert on the prompt/schema of a call that's expected to fail.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_state_graph.py -k test_fake_llm_client_records_prompt_and_schema_per_call -v`
Expected: PASS.

- [ ] **Step 5: Run the full test suite**

Run: `pytest tests/ -v`
Expected: all PASS — this is a pure test-double addition, no production code touched, and no existing test reads `.calls` yet.

- [ ] **Step 6: Commit**

```bash
git add tests/test_state_graph.py
git commit -m "test: record prompt/schema per call in the fake LLM client"
```

---

### Task 3: New agent schemas + `Report` fields

**Files:**
- Modify: `app/agent/schemas.py`
- Modify: `app/schemas.py`
- Modify: `tests/test_agent_schemas.py`
- Modify: `tests/test_schemas.py`

**Interfaces:**
- Produces: `RecommendedAction`, `TriageVerdict`, `DraftReportCanonical`, `DraftReportExperimental`, `ClaimAudit`, `SelfCheckResult` (all in `app.agent.schemas`); `Report.triage_verdict_experimental: TriageVerdict | None`, `Report.triage_rationale_experimental: str | None` (in `app.schemas`).

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_agent_schemas.py`:

```python
from app.agent.schemas import (
    ClaimAudit,
    DraftReportCanonical,
    DraftReportExperimental,
    RecommendedAction,
    SelfCheckResult,
    TriageVerdict,
)


def test_recommended_action_has_sixteen_members():
    assert len(RecommendedAction) == 16
    assert RecommendedAction.ESCALATE_TO_HUMAN_ANALYST.value == "Escalate to a human analyst for manual review"


def test_triage_verdict_has_three_members():
    assert {v.value for v in TriageVerdict} == {"true_positive", "false_positive", "uncertain"}


def test_draft_report_canonical_requires_all_fields():
    draft = DraftReportCanonical(
        alert_summary="x", rationale="y",
        recommended_actions=[RecommendedAction.BLOCK_SOURCE_IP],
    )
    assert draft.recommended_actions == [RecommendedAction.BLOCK_SOURCE_IP]


def test_draft_report_canonical_rejects_unknown_action():
    with pytest.raises(ValidationError):
        DraftReportCanonical(alert_summary="x", rationale="y", recommended_actions=["not_a_real_action"])


def test_draft_report_experimental_requires_all_fields():
    draft = DraftReportExperimental(
        recommended_actions_freeform=["do something creative"],
        triage_verdict=TriageVerdict.UNCERTAIN,
        triage_rationale="not enough evidence either way",
    )
    assert draft.triage_verdict == TriageVerdict.UNCERTAIN


def test_claim_audit_correction_defaults_to_none():
    audit = ClaimAudit(claim="x", supported=True)
    assert audit.correction is None


def test_self_check_result_holds_a_list_of_audits():
    result = SelfCheckResult(audits=[ClaimAudit(claim="x", supported=False, correction="y")])
    assert len(result.audits) == 1
    assert result.audits[0].correction == "y"
```

Add `import pytest` and `from pydantic import ValidationError` at the top of `tests/test_agent_schemas.py` if not already present (check the existing file — it currently has neither, since none of its existing tests exercise validation failures).

Add to `tests/test_schemas.py`, right after `test_report_defaults` (around line 153):

```python
def test_report_triage_experimental_fields_default_to_none():
    report = _make_report()
    assert report.triage_verdict_experimental is None
    assert report.triage_rationale_experimental is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_agent_schemas.py tests/test_schemas.py -v`
Expected: FAIL with `ImportError` (new schemas don't exist yet) and `AttributeError`/`ValidationError` for the `Report` fields.

- [ ] **Step 3: Add the new agent schemas**

Add to `app/agent/schemas.py`, after the existing `OpenValueSearchProposal` class:

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

`Enum` and `BaseModel` are already imported at the top of `app/agent/schemas.py`.

- [ ] **Step 4: Add the new `Report` fields**

`app/schemas.py` cannot import `TriageVerdict` from `app/agent/schemas.py` — that module already imports `IndicatorType` from `app/schemas.py`, so the reverse import would create a circular import. `Report.triage_verdict_experimental` is therefore typed as `str | None` (not the enum) — `app.agent.schemas.TriageVerdict`'s values (`"true_positive"` etc.) are plain strings, so `DraftReportExperimental.triage_verdict.value` assigns into it without any conversion at the call site in Task 6.

Add to `app/schemas.py`'s `Report` class, after `recommended_actions_freeform_experimental` (around line 130):

```python
    triage_verdict_experimental: str | None = None
    triage_rationale_experimental: str | None = None
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_agent_schemas.py tests/test_schemas.py -v`
Expected: all PASS.

- [ ] **Step 6: Run the full test suite**

Run: `pytest tests/ -v`
Expected: all PASS.

- [ ] **Step 7: Commit**

```bash
git add app/agent/schemas.py app/schemas.py tests/test_agent_schemas.py tests/test_schemas.py
git commit -m "feat: add Draft Report / Self-Check schemas and Report triage fields"
```

---

### Task 4: Draft Report — step 7 (Draft-A canonical + Draft-B experimental)

**Files:**
- Modify: `app/agent/prompts.py`
- Modify: `app/agent/state_graph.py`
- Modify: `tests/test_state_graph.py`

**Interfaces:**
- Consumes: `RecommendedAction`, `DraftReportCanonical`, `DraftReportExperimental` (Task 3); `PatternType`, `RiskAssessment` (existing); `_FakeLLMClient.calls` (Task 2, for the new prompt-content test).
- Produces: `build_draft_canonical_prompt(alert, pattern_type, evidence_count, enrichment_results, risk_assessment) -> str`, `build_draft_experimental_prompt(alert, pattern_type, evidence_count, enrichment_results, risk_assessment) -> str` (both in `app/agent/prompts.py`); `AgenticAnalyst._step_draft_report(self, alert, pattern_type, evidence_count, enrichment_results, risk_assessment, model_available) -> tuple[DraftReportCanonical, DraftReportExperimental | None, InvestigationStep]` — later tasks (5, 6) consume this exact signature and return shape.

- [ ] **Step 1: Write the failing tests**

Replace the existing stub test at `tests/test_state_graph.py:602-609` (`test_step_draft_report_delegates_to_stub_step`) — its old signature (`_step_draft_report(model_available=True)`) no longer exists — with:

```python
def test_step_draft_report_returns_canonical_and_experimental_drafts():
    draft_canonical = DraftReportCanonical(
        alert_summary="Brute-force attempts from 203.0.113.5.",
        rationale="Repeated failed logins against a single account.",
        recommended_actions=[RecommendedAction.BLOCK_SOURCE_IP],
    )
    draft_experimental = DraftReportExperimental(
        recommended_actions_freeform=["Consider geo-blocking"],
        triage_verdict=TriageVerdict.TRUE_POSITIVE,
        triage_rationale="Matches known brute-force pattern.",
    )
    llm_client = _FakeLLMClient(responses={
        DraftReportCanonical: draft_canonical,
        DraftReportExperimental: draft_experimental,
    })
    analyst = _make_analyst(llm_client=llm_client)
    alert = _make_alert()
    risk_assessment = RiskAssessment(severity=Severity.HIGH, confidence=Confidence.HIGH, rationale="x")

    draft, experimental, step = analyst._step_draft_report(
        alert, PatternType.BRUTE_FORCE, 14, [], risk_assessment, model_available=True
    )

    assert draft == draft_canonical
    assert experimental == draft_experimental
    assert step.step_name == Step.DRAFT_REPORT.value
    assert step.action == "completed"


def test_step_draft_report_falls_back_when_canonical_call_fails():
    llm_client = _FakeLLMClient(error=LLMClientError("timeout", "took too long"))
    analyst = _make_analyst(llm_client=llm_client)
    alert = _make_alert()
    risk_assessment = RiskAssessment(severity=Severity.LOW, confidence=Confidence.LOW, rationale="x")

    draft, experimental, step = analyst._step_draft_report(
        alert, PatternType.OTHER, 0, [], risk_assessment, model_available=True
    )

    assert draft.recommended_actions == [RecommendedAction.ESCALATE_TO_HUMAN_ANALYST]
    assert "draft report failed: timeout" in draft.rationale
    assert experimental is None
    assert "draft report failed: timeout" in analyst._degraded_reasons[0]


def test_step_draft_report_skips_when_model_unavailable():
    analyst = _make_analyst()
    alert = _make_alert(rule_id="5710", rule_description="sshd brute force", rule_level=10)

    draft, experimental, step = analyst._step_draft_report(
        alert, PatternType.OTHER, 0, [], RiskAssessment(severity=Severity.LOW, confidence=Confidence.LOW, rationale="x"),
        model_available=False,
    )

    assert "5710" in draft.alert_summary
    assert draft.recommended_actions == [RecommendedAction.ESCALATE_TO_HUMAN_ANALYST]
    assert experimental is None
    assert step.action == "skipped"


def test_draft_canonical_prompt_contains_pattern_type_and_evidence_count():
    llm_client = _FakeLLMClient(responses={
        DraftReportCanonical: DraftReportCanonical(
            alert_summary="x", rationale="y", recommended_actions=[RecommendedAction.MONITOR_NO_ACTION]
        ),
        DraftReportExperimental: DraftReportExperimental(
            recommended_actions_freeform=[], triage_verdict=TriageVerdict.UNCERTAIN, triage_rationale="z"
        ),
    })
    analyst = _make_analyst(llm_client=llm_client)
    alert = _make_alert()
    risk_assessment = RiskAssessment(severity=Severity.MEDIUM, confidence=Confidence.MEDIUM, rationale="w")

    analyst._step_draft_report(alert, PatternType.SCANNING, 7, [], risk_assessment, model_available=True)

    canonical_prompt = next(p for p, schema in llm_client.calls if schema is DraftReportCanonical)
    assert "scanning" in canonical_prompt
    assert "7" in canonical_prompt
```

Add these imports to the top of `tests/test_state_graph.py`'s existing `from app.agent.schemas import (...)` block: `DraftReportCanonical`, `DraftReportExperimental`, `RecommendedAction`, `TriageVerdict`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_state_graph.py -k "draft_report or draft_canonical_prompt" -v`
Expected: FAIL — `_step_draft_report` still has the old `(model_available)`-only signature from the stub.

- [ ] **Step 3: Write the prompt builders**

Add to `app/agent/prompts.py`, after `build_open_value_search_prompt`:

```python
def _findings_block(alert, pattern_type, evidence_count, enrichment_results, risk_assessment) -> str:
    enrichment_summary = "\n".join(
        f"- {e.indicator_type.value} {e.indicator_value}: {e.verdict.value} (provider {e.provider_id})"
        for e in enrichment_results
    ) or "none"
    return (
        f"Rule: {alert.rule_id} - {alert.rule_description} (level {alert.rule_level}, "
        f"groups: {', '.join(alert.rule_groups)}).\n"
        f"Correlation findings: pattern_type={pattern_type.value}, evidence_count={evidence_count}.\n"
        f"Enrichment findings:\n{enrichment_summary}\n"
        f"Risk assessment: severity={risk_assessment.severity.value}, confidence={risk_assessment.confidence.value}, "
        f"rationale: {risk_assessment.rationale}\n"
    )


def build_draft_canonical_prompt(alert, pattern_type, evidence_count, enrichment_results, risk_assessment) -> str:
    action_menu = "\n".join(f"- {a.value}" for a in RecommendedAction)
    return (
        "You are drafting the canonical, vetted section of a security investigation report for a human analyst.\n\n"
        f"{_findings_block(alert, pattern_type, evidence_count, enrichment_results, risk_assessment)}\n"
        "Write a plain-language alert_summary (1-2 sentences), an expanded rationale (2-4 sentences) explaining "
        "the risk assessment above in more detail, and select every recommended_action below that applies to "
        "this alert — you MUST only pick from this exact list:\n"
        f"{action_menu}"
    )


def build_draft_experimental_prompt(alert, pattern_type, evidence_count, enrichment_results, risk_assessment) -> str:
    return (
        "You are drafting an EXPERIMENTAL, not-yet-vetted section of a security investigation report. "
        "This output will be clearly labeled experimental and will not be treated as trusted guidance.\n\n"
        f"{_findings_block(alert, pattern_type, evidence_count, enrichment_results, risk_assessment)}\n"
        "Freely propose any additional recommended actions in your own words (no fixed list this time), then "
        "classify whether this alert looks like a true_positive, false_positive, or uncertain, with a "
        "one-sentence rationale for that triage call."
    )
```

Add `from app.agent.schemas import RecommendedAction` to `app/agent/prompts.py`'s imports (it currently only imports `from app.schemas import Alert`).

- [ ] **Step 4: Implement `_step_draft_report`**

In `app/agent/state_graph.py`, add to the imports: `DraftReportCanonical`, `DraftReportExperimental`, `RecommendedAction` (from `app.agent.schemas`); `build_draft_canonical_prompt`, `build_draft_experimental_prompt` (from `app.agent.prompts`).

Replace `_step_draft_report` (currently `def _step_draft_report(self, model_available: bool) -> InvestigationStep: return self._stub_step(Step.DRAFT_REPORT, model_available)`) with:

```python
    def _step_draft_report(
        self, alert: Alert, pattern_type: PatternType, evidence_count: int,
        enrichment_results: list[EnrichmentResult], risk_assessment: RiskAssessment, model_available: bool,
    ) -> tuple[DraftReportCanonical, DraftReportExperimental | None, InvestigationStep]:
        fallback_summary = (
            f"Rule {alert.rule_id} ({alert.rule_description}), level {alert.rule_level}, "
            f"on agent {alert.agent.name}."
        )
        if not model_available:
            draft = DraftReportCanonical(
                alert_summary=fallback_summary,
                rationale="draft report skipped: model unavailable",
                recommended_actions=[RecommendedAction.ESCALATE_TO_HUMAN_ANALYST],
            )
            step = InvestigationStep(
                step_name=Step.DRAFT_REPORT.value, action="skipped", tool_used=None, input=None,
                output_summary="skipped: model unavailable", timestamp=datetime.now(timezone.utc),
            )
            return draft, None, step

        draft = self._draft_canonical(
            alert, pattern_type, evidence_count, enrichment_results, risk_assessment, fallback_summary
        )
        experimental = self._draft_experimental(alert, pattern_type, evidence_count, enrichment_results, risk_assessment)
        summary = f"draft-A: {len(draft.recommended_actions)} action(s) selected"
        summary += (
            "; draft-B failed" if experimental is None
            else f"; draft-B: experimental triage={experimental.triage_verdict.value}"
        )
        step = InvestigationStep(
            step_name=Step.DRAFT_REPORT.value, action="completed", tool_used="llm", input=None,
            output_summary=summary, timestamp=datetime.now(timezone.utc),
        )
        return draft, experimental, step

    def _draft_canonical(
        self, alert: Alert, pattern_type: PatternType, evidence_count: int,
        enrichment_results: list[EnrichmentResult], risk_assessment: RiskAssessment, fallback_summary: str,
    ) -> DraftReportCanonical:
        prompt = build_draft_canonical_prompt(alert, pattern_type, evidence_count, enrichment_results, risk_assessment)
        try:
            return self._llm_client.generate_structured(prompt, DraftReportCanonical)
        except LLMClientError as exc:
            self._degraded_reasons.append(f"draft report failed: {exc.kind}")
            return DraftReportCanonical(
                alert_summary=fallback_summary,
                rationale=f"draft report failed: {exc.kind}",
                recommended_actions=[RecommendedAction.ESCALATE_TO_HUMAN_ANALYST],
            )

    def _draft_experimental(
        self, alert: Alert, pattern_type: PatternType, evidence_count: int,
        enrichment_results: list[EnrichmentResult], risk_assessment: RiskAssessment,
    ) -> DraftReportExperimental | None:
        prompt = build_draft_experimental_prompt(alert, pattern_type, evidence_count, enrichment_results, risk_assessment)
        try:
            return self._llm_client.generate_structured(prompt, DraftReportExperimental)
        except LLMClientError:
            return None
```

Also add, in `__init__` (right after `self._llm_client = llm_client`):

```python
        self._degraded_reasons: list[str] = []
```

This is declared here (not only reset in `investigate()`) specifically so `_step_draft_report` (and Task 6's retrofits of `_step_gather_context` etc.) can be called directly in tests without first calling `investigate()`.

Do **not** remove `_stub_step` yet — `_step_self_check` still uses it until Task 5.

- [ ] **Step 5: Update `investigate()`'s call site**

In `investigate()`, replace `timeline.append(self._step_draft_report(model_available))` with:

```python
        draft, experimental, draft_step = self._step_draft_report(
            alert, pattern_type, evidence_count, enrichment_results, risk_assessment, model_available
        )
        timeline.append(draft_step)
```

`draft` and `experimental` aren't consumed by `_assemble_report` yet (that's Task 6) — they're just threaded through so Task 5 can pass `draft` into `_step_self_check`.

- [ ] **Step 6: Extend the 3 shared end-to-end tests' `_FakeLLMClient` responses**

In `tests/test_state_graph.py`, add `DraftReportCanonical` and `DraftReportExperimental` entries to the `responses={...}` dict in all three of: `test_investigate_runs_full_pipeline_and_persists_report`, `test_investigate_degrades_gracefully_when_siem_context_unavailable`, `test_investigate_degrades_gracefully_when_alert_not_yet_saved`. For each, add:

```python
                DraftReportCanonical: DraftReportCanonical(
                    alert_summary="Brute-force login attempts detected from 203.0.113.5 against web-01.",
                    rationale="High confidence based on repeated failed logins and a known-malicious source IP.",
                    recommended_actions=[RecommendedAction.BLOCK_SOURCE_IP, RecommendedAction.DISABLE_OR_RESET_ACCOUNT],
                ),
                DraftReportExperimental: DraftReportExperimental(
                    recommended_actions_freeform=["Consider geo-blocking the source region"],
                    triage_verdict=TriageVerdict.TRUE_POSITIVE,
                    triage_rationale="Pattern matches a known brute-force signature.",
                ),
```

`test_investigate_degrades_gracefully_when_model_unavailable` needs no change — with `model_available=False`, `_step_draft_report` never calls `generate_structured`, so no response entry is needed for it.

- [ ] **Step 7: Run tests to verify they pass**

Run: `pytest tests/test_state_graph.py -v`
Expected: all PASS. (`test_step_draft_report_delegates_to_stub_step` is gone, replaced by the 4 new tests from Step 1.)

- [ ] **Step 8: Run the full test suite**

Run: `pytest tests/ -v`
Expected: all PASS.

- [ ] **Step 9: Commit**

```bash
git add app/agent/prompts.py app/agent/state_graph.py tests/test_state_graph.py
git commit -m "feat: implement Draft Report step (canonical + experimental)"
```

---

### Task 5: Self-Check — step 8

**Files:**
- Modify: `app/agent/prompts.py`
- Modify: `app/agent/state_graph.py`
- Modify: `tests/test_state_graph.py`

**Interfaces:**
- Consumes: `ClaimAudit`, `SelfCheckResult` (Task 3); `DraftReportCanonical`, `RecommendedAction` (Task 3/4); `_step_draft_report`'s return shape (Task 4).
- Produces: `build_self_check_prompt(draft, pattern_type, evidence_count, enrichment_results, risk_assessment) -> str` (in `app/agent/prompts.py`); `AgenticAnalyst._step_self_check(self, alert, draft, pattern_type, evidence_count, enrichment_results, risk_assessment, correlate_step, model_available) -> tuple[DraftReportCanonical, str, InvestigationStep]` — Task 6 consumes this exact signature and return shape (corrected draft, computed `uncertainty_notes`, the step).

- [ ] **Step 1: Write the failing tests**

Replace the existing stub test at `tests/test_state_graph.py:611-617` (`test_step_self_check_delegates_to_stub_step`) — its old signature no longer exists — with:

```python
def _draft_with_two_actions():
    return DraftReportCanonical(
        alert_summary="Brute-force attempts from 203.0.113.5.",
        rationale="Repeated failed logins against a single account.",
        recommended_actions=[RecommendedAction.BLOCK_SOURCE_IP, RecommendedAction.DISABLE_OR_RESET_ACCOUNT],
    )


def _passthrough_correlate_step():
    return InvestigationStep(
        step_name=Step.CORRELATE.value, action="completed", tool_used="siem_connector+llm", input=None,
        output_summary="pattern_type=brute_force, evidence_count=14",
        timestamp=datetime.now(timezone.utc),
    )


def test_step_self_check_keeps_all_claims_when_all_supported():
    draft = _draft_with_two_actions()
    llm_client = _FakeLLMClient(responses={
        SelfCheckResult: SelfCheckResult(audits=[
            ClaimAudit(claim=draft.alert_summary, supported=True),
            ClaimAudit(claim=draft.rationale, supported=True),
            ClaimAudit(claim=RecommendedAction.BLOCK_SOURCE_IP.value, supported=True),
            ClaimAudit(claim=RecommendedAction.DISABLE_OR_RESET_ACCOUNT.value, supported=True),
        ])
    })
    analyst = _make_analyst(llm_client=llm_client)
    alert = _make_alert()
    risk_assessment = RiskAssessment(severity=Severity.HIGH, confidence=Confidence.HIGH, rationale="x")

    corrected, notes, step = analyst._step_self_check(
        alert, draft, PatternType.BRUTE_FORCE, 14, [], risk_assessment,
        _passthrough_correlate_step(), model_available=True,
    )

    assert corrected == draft
    assert notes == ""
    assert step.action == "completed"


def test_step_self_check_applies_correction_to_unsupported_free_text_claim():
    draft = _draft_with_two_actions()
    llm_client = _FakeLLMClient(responses={
        SelfCheckResult: SelfCheckResult(audits=[
            ClaimAudit(claim=draft.alert_summary, supported=False, correction="Corrected summary text."),
            ClaimAudit(claim=draft.rationale, supported=True),
            ClaimAudit(claim=RecommendedAction.BLOCK_SOURCE_IP.value, supported=True),
            ClaimAudit(claim=RecommendedAction.DISABLE_OR_RESET_ACCOUNT.value, supported=True),
        ])
    })
    analyst = _make_analyst(llm_client=llm_client)
    alert = _make_alert()
    risk_assessment = RiskAssessment(severity=Severity.HIGH, confidence=Confidence.HIGH, rationale="x")

    corrected, notes, step = analyst._step_self_check(
        alert, draft, PatternType.BRUTE_FORCE, 14, [], risk_assessment,
        _passthrough_correlate_step(), model_available=True,
    )

    assert corrected.alert_summary == "Corrected summary text."
    assert corrected.recommended_actions == draft.recommended_actions


def test_step_self_check_drops_unsupported_action_without_using_its_correction():
    draft = _draft_with_two_actions()
    llm_client = _FakeLLMClient(responses={
        SelfCheckResult: SelfCheckResult(audits=[
            ClaimAudit(claim=draft.alert_summary, supported=True),
            ClaimAudit(claim=draft.rationale, supported=True),
            ClaimAudit(claim=RecommendedAction.BLOCK_SOURCE_IP.value, supported=False, correction="Do something else instead"),
            ClaimAudit(claim=RecommendedAction.DISABLE_OR_RESET_ACCOUNT.value, supported=True),
        ])
    })
    analyst = _make_analyst(llm_client=llm_client)
    alert = _make_alert()
    risk_assessment = RiskAssessment(severity=Severity.HIGH, confidence=Confidence.HIGH, rationale="x")

    corrected, notes, step = analyst._step_self_check(
        alert, draft, PatternType.BRUTE_FORCE, 14, [], risk_assessment,
        _passthrough_correlate_step(), model_available=True,
    )

    assert corrected.recommended_actions == [RecommendedAction.DISABLE_OR_RESET_ACCOUNT]
    assert "Do something else instead" not in [a.value for a in corrected.recommended_actions]
    assert analyst._degraded_reasons == ["self-check flagged 1 unsupported claim(s)"]


def test_step_self_check_falls_back_to_escalate_when_all_actions_dropped():
    draft = DraftReportCanonical(
        alert_summary="x", rationale="y", recommended_actions=[RecommendedAction.BLOCK_SOURCE_IP],
    )
    llm_client = _FakeLLMClient(responses={
        SelfCheckResult: SelfCheckResult(audits=[
            ClaimAudit(claim=draft.alert_summary, supported=True),
            ClaimAudit(claim=draft.rationale, supported=True),
            ClaimAudit(claim=RecommendedAction.BLOCK_SOURCE_IP.value, supported=False),
        ])
    })
    analyst = _make_analyst(llm_client=llm_client)
    alert = _make_alert()
    risk_assessment = RiskAssessment(severity=Severity.LOW, confidence=Confidence.LOW, rationale="x")

    corrected, notes, step = analyst._step_self_check(
        alert, draft, PatternType.OTHER, 0, [], risk_assessment,
        _passthrough_correlate_step(), model_available=True,
    )

    assert corrected.recommended_actions == [RecommendedAction.ESCALATE_TO_HUMAN_ANALYST]


def test_step_self_check_notes_unsupported_claim_without_correction():
    draft = _draft_with_two_actions()
    llm_client = _FakeLLMClient(responses={
        SelfCheckResult: SelfCheckResult(audits=[
            ClaimAudit(claim=draft.alert_summary, supported=False, correction=None),
            ClaimAudit(claim=draft.rationale, supported=True),
            ClaimAudit(claim=RecommendedAction.BLOCK_SOURCE_IP.value, supported=True),
            ClaimAudit(claim=RecommendedAction.DISABLE_OR_RESET_ACCOUNT.value, supported=True),
        ])
    })
    analyst = _make_analyst(llm_client=llm_client)
    alert = _make_alert()
    risk_assessment = RiskAssessment(severity=Severity.HIGH, confidence=Confidence.HIGH, rationale="x")

    corrected, notes, step = analyst._step_self_check(
        alert, draft, PatternType.BRUTE_FORCE, 14, [], risk_assessment,
        _passthrough_correlate_step(), model_available=True,
    )

    assert corrected.alert_summary == draft.alert_summary  # kept as-is, best effort
    assert f"unsupported claim: {draft.alert_summary!r}" in notes


def test_step_self_check_notes_errored_and_unknown_enrichments():
    draft = _draft_with_two_actions()
    llm_client = _FakeLLMClient(responses={
        SelfCheckResult: SelfCheckResult(audits=[
            ClaimAudit(claim=draft.alert_summary, supported=True),
            ClaimAudit(claim=draft.rationale, supported=True),
            ClaimAudit(claim=RecommendedAction.BLOCK_SOURCE_IP.value, supported=True),
            ClaimAudit(claim=RecommendedAction.DISABLE_OR_RESET_ACCOUNT.value, supported=True),
        ])
    })
    analyst = _make_analyst(llm_client=llm_client)
    alert = _make_alert()
    risk_assessment = RiskAssessment(severity=Severity.HIGH, confidence=Confidence.HIGH, rationale="x")
    enrichment_results = [
        _make_enrichment_result(error="rate_limited"),
        _make_enrichment_result(verdict=EnrichmentVerdict.UNKNOWN),
    ]

    corrected, notes, step = analyst._step_self_check(
        alert, draft, PatternType.BRUTE_FORCE, 14, enrichment_results, risk_assessment,
        _passthrough_correlate_step(), model_available=True,
    )

    assert "2 enrichment lookup(s) errored or returned unknown verdicts" in notes


def test_step_self_check_notes_unused_correlation_menu():
    draft = _draft_with_two_actions()
    llm_client = _FakeLLMClient(responses={
        SelfCheckResult: SelfCheckResult(audits=[
            ClaimAudit(claim=draft.alert_summary, supported=True),
            ClaimAudit(claim=draft.rationale, supported=True),
            ClaimAudit(claim=RecommendedAction.BLOCK_SOURCE_IP.value, supported=True),
            ClaimAudit(claim=RecommendedAction.DISABLE_OR_RESET_ACCOUNT.value, supported=True),
        ])
    })
    analyst = _make_analyst(llm_client=llm_client)
    alert = _make_alert()
    risk_assessment = RiskAssessment(severity=Severity.HIGH, confidence=Confidence.HIGH, rationale="x")
    unused_correlate_step = InvestigationStep(
        step_name=Step.CORRELATE.value, action="completed", tool_used="siem_connector+llm", input=None,
        output_summary="pattern_type=brute_force, evidence_count=14",  # no "follow-up" or "open-value search" text
        timestamp=datetime.now(timezone.utc),
    )

    corrected, notes, step = analyst._step_self_check(
        alert, draft, PatternType.BRUTE_FORCE, 14, [], risk_assessment,
        unused_correlate_step, model_available=True,
    )

    assert "correlation follow-up/open-value search menu was not used" in notes


def test_step_self_check_notes_missing_mitre_mapping():
    draft = _draft_with_two_actions()
    llm_client = _FakeLLMClient(responses={
        SelfCheckResult: SelfCheckResult(audits=[
            ClaimAudit(claim=draft.alert_summary, supported=True),
            ClaimAudit(claim=draft.rationale, supported=True),
            ClaimAudit(claim=RecommendedAction.BLOCK_SOURCE_IP.value, supported=True),
            ClaimAudit(claim=RecommendedAction.DISABLE_OR_RESET_ACCOUNT.value, supported=True),
        ])
    })
    analyst = _make_analyst(llm_client=llm_client)
    alert = _make_alert()  # _make_alert's defaults never set `mitre`, so it defaults to None
    risk_assessment = RiskAssessment(severity=Severity.HIGH, confidence=Confidence.HIGH, rationale="x")

    corrected, notes, step = analyst._step_self_check(
        alert, draft, PatternType.BRUTE_FORCE, 14, [], risk_assessment,
        _passthrough_correlate_step(), model_available=True,
    )

    assert "no MITRE ATT&CK mapping available for this alert" in notes


def test_step_self_check_falls_back_when_call_fails():
    draft = _draft_with_two_actions()
    llm_client = _FakeLLMClient(error=LLMClientError("timeout", "took too long"))
    analyst = _make_analyst(llm_client=llm_client)
    alert = _make_alert()
    risk_assessment = RiskAssessment(severity=Severity.HIGH, confidence=Confidence.HIGH, rationale="x")

    corrected, notes, step = analyst._step_self_check(
        alert, draft, PatternType.BRUTE_FORCE, 14, [], risk_assessment,
        _passthrough_correlate_step(), model_available=True,
    )

    assert corrected == draft
    assert "self-check could not run" in notes
    assert analyst._degraded_reasons == ["self-check failed: timeout"]


def test_step_self_check_falls_back_when_audit_count_mismatches_claim_count():
    draft = _draft_with_two_actions()
    llm_client = _FakeLLMClient(responses={
        SelfCheckResult: SelfCheckResult(audits=[ClaimAudit(claim=draft.alert_summary, supported=True)])
    })
    analyst = _make_analyst(llm_client=llm_client)
    alert = _make_alert()
    risk_assessment = RiskAssessment(severity=Severity.HIGH, confidence=Confidence.HIGH, rationale="x")

    corrected, notes, step = analyst._step_self_check(
        alert, draft, PatternType.BRUTE_FORCE, 14, [], risk_assessment,
        _passthrough_correlate_step(), model_available=True,
    )

    assert corrected == draft


def test_step_self_check_skips_when_model_unavailable():
    draft = _draft_with_two_actions()
    analyst = _make_analyst()
    alert = _make_alert()
    risk_assessment = RiskAssessment(severity=Severity.LOW, confidence=Confidence.LOW, rationale="x")

    corrected, notes, step = analyst._step_self_check(
        alert, draft, PatternType.OTHER, 0, [], risk_assessment,
        _passthrough_correlate_step(), model_available=False,
    )

    assert corrected == draft
    assert "self-check skipped: model unavailable" in notes
    assert step.action == "skipped"


def test_self_check_prompt_contains_draft_alert_summary():
    draft = _draft_with_two_actions()
    llm_client = _FakeLLMClient(responses={
        SelfCheckResult: SelfCheckResult(audits=[
            ClaimAudit(claim=draft.alert_summary, supported=True),
            ClaimAudit(claim=draft.rationale, supported=True),
            ClaimAudit(claim=RecommendedAction.BLOCK_SOURCE_IP.value, supported=True),
            ClaimAudit(claim=RecommendedAction.DISABLE_OR_RESET_ACCOUNT.value, supported=True),
        ])
    })
    analyst = _make_analyst(llm_client=llm_client)
    alert = _make_alert()
    risk_assessment = RiskAssessment(severity=Severity.HIGH, confidence=Confidence.HIGH, rationale="x")

    analyst._step_self_check(
        alert, draft, PatternType.BRUTE_FORCE, 14, [], risk_assessment,
        _passthrough_correlate_step(), model_available=True,
    )

    self_check_prompt = next(p for p, schema in llm_client.calls if schema is SelfCheckResult)
    assert draft.alert_summary in self_check_prompt
```

Add `ClaimAudit`, `DraftReportCanonical`, `SelfCheckResult` to `tests/test_state_graph.py`'s `app.agent.schemas` import block (`RecommendedAction`, `DraftReportExperimental`, `TriageVerdict` were already added in Task 4). `_make_enrichment_result(**overrides)` (`tests/test_state_graph.py:170-181`) already forwards arbitrary keyword overrides onto its defaults dict before constructing `EnrichmentResult`, so `_make_enrichment_result(error="rate_limited")` and `_make_enrichment_result(verdict=EnrichmentVerdict.UNKNOWN)` both already work — no change needed to this helper.

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_state_graph.py -k "self_check" -v`
Expected: FAIL — `_step_self_check` still has the old `(model_available)`-only stub signature.

- [ ] **Step 3: Write the prompt builder**

Add to `app/agent/prompts.py`, after `build_draft_experimental_prompt`:

```python
def build_self_check_prompt(draft, pattern_type, evidence_count, enrichment_results, risk_assessment) -> str:
    claims = [draft.alert_summary, draft.rationale, *[a.value for a in draft.recommended_actions]]
    claims_block = "\n".join(f"{i + 1}. {claim}" for i, claim in enumerate(claims))
    enrichment_summary = "\n".join(
        f"- {e.indicator_type.value} {e.indicator_value}: {e.verdict.value} (provider {e.provider_id})"
        for e in enrichment_results
    ) or "none"
    return (
        "You are auditing a draft security report against the structured findings that produced it. "
        "For EACH numbered claim below, decide whether the structured findings support it. If not, and you "
        "can propose a better-supported replacement, provide a correction; otherwise leave correction empty.\n\n"
        f"Correlation findings: pattern_type={pattern_type.value}, evidence_count={evidence_count}.\n"
        f"Enrichment findings:\n{enrichment_summary}\n"
        f"Risk assessment: severity={risk_assessment.severity.value}, confidence={risk_assessment.confidence.value}.\n\n"
        f"Claims to audit, in order:\n{claims_block}\n\n"
        "Return exactly one audit per claim, in the same order."
    )
```

- [ ] **Step 4: Write `_compute_uncertainty_notes` and `_apply_self_check_corrections`**

Add to `app/agent/state_graph.py`, as module-level functions right before the `AgenticAnalyst` class:

```python
def _compute_uncertainty_notes(
    alert: Alert, enrichment_results: list[EnrichmentResult],
    correlate_step: InvestigationStep, flagged_claims: list[str],
) -> str:
    gaps: list[str] = [f"unsupported claim: {claim!r}" for claim in flagged_claims]

    errored_or_unknown = [
        r for r in enrichment_results if r.error is not None or r.verdict == EnrichmentVerdict.UNKNOWN
    ]
    if errored_or_unknown:
        gaps.append(f"{len(errored_or_unknown)} enrichment lookup(s) errored or returned unknown verdicts")

    if "follow-up" not in correlate_step.output_summary and "open-value search" not in correlate_step.output_summary:
        gaps.append("correlation follow-up/open-value search menu was not used")

    if not alert.mitre:
        gaps.append("no MITRE ATT&CK mapping available for this alert")

    return "; ".join(gaps)


def _apply_self_check_corrections(
    draft: DraftReportCanonical, result: SelfCheckResult
) -> tuple[DraftReportCanonical, list[str]]:
    claims = [draft.alert_summary, draft.rationale, *[a.value for a in draft.recommended_actions]]
    if len(result.audits) != len(claims):
        return draft, []

    alert_summary = draft.alert_summary
    rationale = draft.rationale
    flagged_claims: list[str] = []

    summary_audit = result.audits[0]
    if not summary_audit.supported:
        if summary_audit.correction:
            alert_summary = summary_audit.correction
        else:
            flagged_claims.append(summary_audit.claim)

    rationale_audit = result.audits[1]
    if not rationale_audit.supported:
        if rationale_audit.correction:
            rationale = rationale_audit.correction
        else:
            flagged_claims.append(rationale_audit.claim)

    kept_actions = []
    for action, audit in zip(draft.recommended_actions, result.audits[2:]):
        if audit.supported:
            kept_actions.append(action)
        else:
            flagged_claims.append(audit.claim)
    if not kept_actions:
        kept_actions = [RecommendedAction.ESCALATE_TO_HUMAN_ANALYST]

    corrected = DraftReportCanonical(alert_summary=alert_summary, rationale=rationale, recommended_actions=kept_actions)
    return corrected, flagged_claims
```

- [ ] **Step 5: Implement `_step_self_check`**

In `app/agent/state_graph.py`, add `ClaimAudit`, `SelfCheckResult` to the imports from `app.agent.schemas`, and `build_self_check_prompt` to the imports from `app.agent.prompts`.

Replace `_step_self_check` (currently `def _step_self_check(self, model_available: bool) -> InvestigationStep: return self._stub_step(Step.SELF_CHECK, model_available)`) with:

```python
    def _step_self_check(
        self, alert: Alert, draft: DraftReportCanonical, pattern_type: PatternType, evidence_count: int,
        enrichment_results: list[EnrichmentResult], risk_assessment: RiskAssessment,
        correlate_step: InvestigationStep, model_available: bool,
    ) -> tuple[DraftReportCanonical, str, InvestigationStep]:
        if not model_available:
            notes = _compute_uncertainty_notes(alert, enrichment_results, correlate_step, [])
            notes = "self-check skipped: model unavailable" + (f"; {notes}" if notes else "")
            step = InvestigationStep(
                step_name=Step.SELF_CHECK.value, action="skipped", tool_used=None, input=None,
                output_summary="skipped: model unavailable", timestamp=datetime.now(timezone.utc),
            )
            return draft, notes, step

        result = self._run_self_check(draft, pattern_type, evidence_count, enrichment_results, risk_assessment)
        if result is None:
            notes = _compute_uncertainty_notes(alert, enrichment_results, correlate_step, [])
            notes = "self-check could not run" + (f"; {notes}" if notes else "")
            step = InvestigationStep(
                step_name=Step.SELF_CHECK.value, action="completed", tool_used="llm", input=None,
                output_summary="self-check call failed; corrections not applied", timestamp=datetime.now(timezone.utc),
            )
            return draft, notes, step

        corrected_draft, flagged_claims = _apply_self_check_corrections(draft, result)
        if flagged_claims:
            self._degraded_reasons.append(f"self-check flagged {len(flagged_claims)} unsupported claim(s)")
        notes = _compute_uncertainty_notes(alert, enrichment_results, correlate_step, flagged_claims)
        step = InvestigationStep(
            step_name=Step.SELF_CHECK.value, action="completed", tool_used="llm", input=None,
            output_summary=f"audited {len(result.audits)} claim(s), {len(flagged_claims)} flagged",
            timestamp=datetime.now(timezone.utc),
        )
        return corrected_draft, notes, step

    def _run_self_check(
        self, draft: DraftReportCanonical, pattern_type: PatternType, evidence_count: int,
        enrichment_results: list[EnrichmentResult], risk_assessment: RiskAssessment,
    ) -> SelfCheckResult | None:
        prompt = build_self_check_prompt(draft, pattern_type, evidence_count, enrichment_results, risk_assessment)
        try:
            return self._llm_client.generate_structured(prompt, SelfCheckResult)
        except LLMClientError as exc:
            self._degraded_reasons.append(f"self-check failed: {exc.kind}")
            return None
```

Now remove `_stub_step` entirely — nothing calls it anymore — and remove its two direct tests, `test_stub_step_logs_stub_when_model_available` and `test_stub_step_logs_skipped_when_model_unavailable` (`tests/test_state_graph.py:319-337`), since they test dead code.

- [ ] **Step 6: Update `investigate()`'s call site**

Replace `timeline.append(self._step_self_check(model_available))` with:

```python
        draft, uncertainty_notes, self_check_step = self._step_self_check(
            alert, draft, pattern_type, evidence_count, enrichment_results, risk_assessment,
            correlate_step, model_available,
        )
        timeline.append(self_check_step)
```

`correlate_step` is already in scope from the earlier `_step_correlate` call in `investigate()`. `draft` is reassigned here (Self-Check may have corrected it) — Task 6's `_assemble_report` call must use this post-correction `draft`, not the one Task 4 produced.

- [ ] **Step 7: Extend the 3 shared end-to-end tests with a `SelfCheckResult` response**

In each of the three shared tests (same three as Task 4 Step 6), add to the `responses={...}` dict:

```python
                SelfCheckResult: SelfCheckResult(audits=[
                    ClaimAudit(claim="Brute-force login attempts detected from 203.0.113.5 against web-01.", supported=True),
                    ClaimAudit(claim="High confidence based on repeated failed logins and a known-malicious source IP.", supported=True),
                    ClaimAudit(claim=RecommendedAction.BLOCK_SOURCE_IP.value, supported=True),
                    ClaimAudit(claim=RecommendedAction.DISABLE_OR_RESET_ACCOUNT.value, supported=True),
                ]),
```

The claim strings must match exactly the `DraftReportCanonical` fixture added in Task 4 Step 6 (`alert_summary`, `rationale`, and both `recommended_actions` values, in that order) — otherwise `_apply_self_check_corrections`'s length check still passes (4 claims, 4 audits) but is a coincidence rather than a genuine match; matching the text keeps the fixture internally consistent and readable.

- [ ] **Step 8: Run tests to verify they pass**

Run: `pytest tests/test_state_graph.py -v`
Expected: all PASS.

- [ ] **Step 9: Run the full test suite**

Run: `pytest tests/ -v`
Expected: all PASS.

- [ ] **Step 10: Commit**

```bash
git add app/agent/prompts.py app/agent/state_graph.py tests/test_state_graph.py
git commit -m "feat: implement Self-Check step with claim audits and corrections"
```

---

### Task 6: Report status determination + final wiring

**Files:**
- Modify: `app/agent/state_graph.py`
- Modify: `tests/test_state_graph.py`

**Interfaces:**
- Consumes: `self._degraded_reasons` (declared in Task 4's `__init__` change; appended to by Tasks 4 and 5's new methods); `_step_draft_report`, `_step_self_check` (Tasks 4, 5).
- Produces: `AgenticAnalyst._assemble_report`'s final signature: `(self, alert, timeline, enrichment_results, risk_assessment, draft, experimental, uncertainty_notes, model_available) -> Report`. This is the last signature change in this plan — nothing later depends on it.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_state_graph.py`:

```python
def test_step_gather_context_degrades_marks_investigation_degraded():
    siem = _FakeSIEMConnector(context_error=SIEMConnectorError("unreachable", "connection refused"))
    analyst = _make_analyst(siem=siem)
    alert = _make_alert()

    analyst._step_gather_context(alert)

    assert analyst._degraded_reasons == ["SIEM context unavailable: unreachable"]


def test_step_risk_assessment_llm_failure_marks_investigation_degraded():
    llm_client = _FakeLLMClient(model_available=True, error=LLMClientError("timeout", "took too long"))
    analyst = _make_analyst(llm_client=llm_client)
    alert = _make_alert()

    analyst._step_risk_assessment(alert, PatternType.OTHER, 0, [], model_available=True)

    assert analyst._degraded_reasons == ["risk assessment failed: timeout"]


def test_assemble_report_status_complete_when_nothing_degraded(tmp_path):
    analyst = _make_analyst()
    alert = _make_alert()
    draft = _draft_with_two_actions()
    risk_assessment = RiskAssessment(severity=Severity.HIGH, confidence=Confidence.HIGH, rationale="x")

    report = analyst._assemble_report(
        alert, [], [], risk_assessment, draft, None, "", model_available=True,
    )

    assert report.status == ReportStatus.COMPLETE
    assert report.alert_summary == draft.alert_summary
    assert report.risk_assessment.rationale == draft.rationale
    assert report.recommended_actions == [a.value for a in draft.recommended_actions]
    assert report.model_metadata.prompt_version == "4d-v1"


def test_assemble_report_status_needs_human_review_when_degraded():
    analyst = _make_analyst()
    analyst._degraded_reasons.append("risk assessment failed: timeout")
    alert = _make_alert()
    draft = _draft_with_two_actions()
    risk_assessment = RiskAssessment(severity=Severity.LOW, confidence=Confidence.LOW, rationale="x")

    report = analyst._assemble_report(alert, [], [], risk_assessment, draft, None, "", model_available=True)

    assert report.status == ReportStatus.NEEDS_HUMAN_REVIEW


def test_assemble_report_includes_experimental_fields_when_present():
    analyst = _make_analyst()
    alert = _make_alert()
    draft = _draft_with_two_actions()
    experimental = DraftReportExperimental(
        recommended_actions_freeform=["do X"], triage_verdict=TriageVerdict.FALSE_POSITIVE, triage_rationale="y",
    )
    risk_assessment = RiskAssessment(severity=Severity.LOW, confidence=Confidence.LOW, rationale="x")

    report = analyst._assemble_report(alert, [], [], risk_assessment, draft, experimental, "", model_available=True)

    assert report.recommended_actions_freeform_experimental == ["do X"]
    assert report.triage_verdict_experimental == "false_positive"
    assert report.triage_rationale_experimental == "y"
```

`_draft_with_two_actions` was defined in Task 5's test additions and is reused here.

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_state_graph.py -k "degraded_marks or assemble_report" -v`
Expected: FAIL — `_step_gather_context`/`_step_risk_assessment` don't append to `_degraded_reasons` yet, and `_assemble_report` still has its Phase 4c signature and hardcoded `NEEDS_HUMAN_REVIEW`/stub text.

- [ ] **Step 3: Retrofit existing steps to record degradation**

In `app/agent/state_graph.py`:

`_step_gather_context`'s `except SIEMConnectorError as exc:` branch — add one line before building `step`:

```python
        except SIEMConnectorError as exc:
            self._degraded_reasons.append(f"SIEM context unavailable: {exc.kind}")
            step = InvestigationStep(
```

`_step_correlate` — right after computing `failed_note`, add:

```python
        if failed_count:
            self._degraded_reasons.append(f"{failed_count} canonical search(es) failed")
```

and in the follow-up `except SIEMConnectorError:` branch:

```python
                except SIEMConnectorError:
                    follow_up_note = f"; follow-up {decision.follow_up_query.value} failed"
                    self._degraded_reasons.append(f"correlation follow-up {decision.follow_up_query.value} failed")
```

`_classify_correlation`'s `except LLMClientError:` branch:

```python
        except LLMClientError as exc:
            self._degraded_reasons.append(f"correlation classification failed: {exc.kind}")
            return CorrelationDecision(pattern_type=PatternType.OTHER, follow_up_query=SearchTemplate.NONE_NEEDED)
```

(this changes `except LLMClientError:` to `except LLMClientError as exc:` — capture the exception where it wasn't captured before.)

`_step_extract_indicators` — where `llm_error is not None` is already checked to build the summary text, add:

```python
        if llm_error is not None:
            self._degraded_reasons.append(f"indicator extraction LLM failed: {llm_error}")
            summary = (
```

`_assess_risk`'s `except LLMClientError as exc:` branch:

```python
        except LLMClientError as exc:
            self._degraded_reasons.append(f"risk assessment failed: {exc.kind}")
            return RiskAssessment(
```

`investigate()` — right after `model_available = self._llm_client.model_available()`, add the reset and the top-level check:

```python
        self._degraded_reasons = []
        model_available = self._llm_client.model_available()
        if not model_available:
            self._degraded_reasons.append("model unavailable")
```

(Note: `self._degraded_reasons = []` must come first so the `model_available` check's append isn't immediately wiped.)

`_run_open_value_search`'s `except SIEMConnectorError:` branch — this one does NOT append to `_degraded_reasons`: an open-value search is already an experimental, best-effort hop (per the Phase 4c design), so its failure alone shouldn't force `NEEDS_HUMAN_REVIEW`. Leave it unchanged.

- [ ] **Step 4: Rewrite `_assemble_report`**

Replace the entire method:

```python
    def _assemble_report(
        self, alert: Alert, timeline: list[InvestigationStep], enrichment_results: list[EnrichmentResult],
        risk_assessment: RiskAssessment, draft: DraftReportCanonical, experimental: DraftReportExperimental | None,
        uncertainty_notes: str, model_available: bool,
    ) -> Report:
        status = ReportStatus.NEEDS_HUMAN_REVIEW if self._degraded_reasons else ReportStatus.COMPLETE
        return Report(
            report_id=uuid4(),
            alert_id=alert.alert_id,
            generated_at=datetime.now(timezone.utc),
            alert_summary=draft.alert_summary,
            investigation_timeline=timeline,
            enrichment_findings=enrichment_results,
            risk_assessment=RiskAssessment(
                severity=risk_assessment.severity, confidence=risk_assessment.confidence, rationale=draft.rationale,
            ),
            recommended_actions=[a.value for a in draft.recommended_actions],
            recommended_actions_freeform_experimental=(
                experimental.recommended_actions_freeform if experimental is not None else None
            ),
            triage_verdict_experimental=experimental.triage_verdict.value if experimental is not None else None,
            triage_rationale_experimental=experimental.triage_rationale if experimental is not None else None,
            uncertainty_notes=uncertainty_notes,
            status=status,
            model_metadata=ModelMetadata(
                model_name="gemma4:12b" if model_available else "none",
                model_version="none",
                prompt_version="4d-v1",
            ),
        )
```

- [ ] **Step 5: Update `investigate()`'s final assembly call**

Replace the tail of `investigate()`:

```python
        report = self._assemble_report(alert, timeline, enrichment_results, risk_assessment, model_available)
        finalize_step = self._step_finalize_and_persist(alert, report)
```

with:

```python
        report = self._assemble_report(
            alert, timeline, enrichment_results, risk_assessment, draft, experimental, uncertainty_notes, model_available,
        )
        finalize_step = self._step_finalize_and_persist(alert, report)
```

- [ ] **Step 6: Update the 3 shared end-to-end tests' final assertions**

`test_investigate_runs_full_pipeline_and_persists_report` — this test now represents a genuinely fully-successful run (SIEM reachable, all LLM calls succeed, all self-check claims supported). Update:

```python
    assert report.status == ReportStatus.COMPLETE
    assert report.alert_summary == "Brute-force login attempts detected from 203.0.113.5 against web-01."
    assert report.risk_assessment.severity == Severity.HIGH
    assert report.risk_assessment.confidence == Confidence.HIGH
    assert report.risk_assessment.rationale == "High confidence based on repeated failed logins and a known-malicious source IP."
    assert report.recommended_actions == [
        RecommendedAction.BLOCK_SOURCE_IP.value, RecommendedAction.DISABLE_OR_RESET_ACCOUNT.value,
    ]
    assert report.triage_verdict_experimental == "true_positive"
    assert report.model_metadata.model_name == "gemma4:12b"
    assert report.model_metadata.prompt_version == "4d-v1"
```

(replacing the old `assert report.status == ReportStatus.NEEDS_HUMAN_REVIEW`, `assert report.risk_assessment.severity == Severity.HIGH`, `assert report.risk_assessment.confidence == Confidence.HIGH`, and `assert report.model_metadata.prompt_version == "4c-v1"` lines — keep the other existing assertions in this test, e.g. `step_names`, `len(report.enrichment_findings)`, the `alert_store` checks, unchanged).

`test_investigate_degrades_gracefully_when_siem_context_unavailable` — no assertion change needed: it already asserts `report.status == ReportStatus.NEEDS_HUMAN_REVIEW`, and this now holds because `_step_gather_context`'s degradation is recorded in `_degraded_reasons` (Step 3 above), not because of the hardcoded default.

`test_investigate_degrades_gracefully_when_alert_not_yet_saved` — no assertion change needed; it doesn't check `report.status`.

- [ ] **Step 7: Run tests to verify they pass**

Run: `pytest tests/test_state_graph.py -v`
Expected: all PASS.

- [ ] **Step 8: Run the full test suite**

Run: `pytest tests/ -v`
Expected: all PASS.

- [ ] **Step 9: Commit**

```bash
git add app/agent/state_graph.py tests/test_state_graph.py
git commit -m "feat: wire Report.status to accumulated degradation reasons across the pipeline"
```

---

## Self-Review Notes (for the plan author, not a task)

- **Spec coverage:** §1 (domain-regex) → Task 1. §2 (schemas) → Task 3. §3 (Draft-A/B) → Task 4. §4 (Self-Check) → Task 5. §5 (wiring/status) → Task 6. §6 (prompt-capturing fake) → Task 2. §7 (testing) → distributed across all tasks' Step 1s.
- **Refinement beyond the spec, made during planning:** the spec's `uncertainty_notes`/status design didn't originally account for non-LLM degradation sources (`_step_gather_context` failing, Correlate's canonical searches failing) even though an existing Phase 4c test (`test_investigate_degrades_gracefully_when_siem_context_unavailable`) already required `Report.status == NEEDS_HUMAN_REVIEW` from a SIEM failure alone, with no LLM failures involved. Task 6 widens `self._degraded_reasons` to cover these sources so that pre-existing, already-green test keeps passing under the new, real status logic instead of passing only by coincidence (the old hardcoded default).
- **Type consistency check:** `_step_draft_report`'s return type (`tuple[DraftReportCanonical, DraftReportExperimental | None, InvestigationStep]`, Task 4) matches what Task 5's `_step_self_check` and Task 6's `investigate()`/`_assemble_report` consume. `_step_self_check`'s return type (`tuple[DraftReportCanonical, str, InvestigationStep]`, Task 5) matches what Task 6's `_assemble_report` call consumes.
