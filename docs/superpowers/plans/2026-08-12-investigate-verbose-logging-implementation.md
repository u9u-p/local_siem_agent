# Verbose Logging for investigate-all/investigate-one Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add opt-in DEBUG-level tracing of every Agentic Analyst step's real input/output to `investigate-all`/`investigate-one`, directable to stdout or a file.

**Architecture:** `app/agent/state_graph.py` gains a module logger (`app.agent.state_graph`) with `logger.debug(...)` calls at every step method's entry/exit and every LLM-call helper's prompt/response. `app/cli.py` gains `--verbose`/`-v` and `--log-file` options on both commands, wired through one shared `_configure_verbose_logging()` function that sets the `"app"` logger's level and handler — `app.agent.state_graph` inherits both via normal logger-hierarchy propagation, with zero changes needed to its own configuration.

**Tech Stack:** Python's standard `logging` module only — no new dependency.

## Global Constraints

- Verbose mode affects only the `"app"` logger and its children (e.g. `app.agent.state_graph`) — never the root logger, so `httpx`/`openai`'s own logging stays untouched regardless of `--verbose`.
- For every LLM-calling helper, log the **exact** prompt string and the **exact** `model_dump_json()` of the result (or the `LLMClientError.kind` and fallback used on failure) — no truncation.
- `--log-file PATH` implies verbose tracing is on even without `-v`; passing neither option leaves behavior identical to today (no log calls become visible, since nothing raises the `"app"` logger's level above its default).
- `_configure_verbose_logging` must be idempotent — clear any handlers already attached to the `"app"` logger before deciding whether to add a new one, so repeated calls in one process (relevant for `CliRunner`-based tests, which invoke commands in-process rather than as subprocesses) never accumulate handlers.
- Every added `logger.debug(...)` call is additive only — no existing behavior, return value, or control flow in `app/agent/state_graph.py` changes.

---

### Task 1: Logging for steps 1-4 (Ingest & Parse, Extract Indicators, Enrich, Gather Context)

**Files:**
- Modify: `app/agent/state_graph.py`
- Modify: `tests/test_state_graph.py`

**Interfaces:**
- Produces: `logger = logging.getLogger(__name__)` at module level in `state_graph.py` — Tasks 2 and 3 use the same `logger` object (already present after this task; they only add more `logger.debug(...)` calls to their own methods).

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_state_graph.py` (near the existing enrich/gather-context tests):

```python
import logging


def test_step_extract_indicators_logs_input_and_output(caplog):
    analyst = _make_analyst()
    alert = _make_alert(full_log="Invalid user admin from 203.0.113.5")

    with caplog.at_level(logging.DEBUG, logger="app.agent.state_graph"):
        analyst._step_extract_indicators(alert, model_available=False)

    assert "_step_extract_indicators input" in caplog.text
    assert str(alert.alert_id) in caplog.text
    assert "_step_extract_indicators output" in caplog.text
    assert "203.0.113.5" in caplog.text


def test_step_enrich_logs_input_and_output(caplog):
    registry = EnrichmentRegistry()
    registry.register(_FakeIPProvider(result=_make_enrichment_result()))
    analyst = _make_analyst(enrichment_registry=registry)
    indicators, _ = analyst._step_extract_indicators(
        _make_alert(full_log="Invalid user admin from 203.0.113.5"), model_available=False
    )

    with caplog.at_level(logging.DEBUG, logger="app.agent.state_graph"):
        analyst._step_enrich(indicators)

    assert "_step_enrich input" in caplog.text
    assert "203.0.113.5" in caplog.text
    assert "_step_enrich output" in caplog.text


def test_step_gather_context_logs_input_and_output(caplog):
    siem = _FakeSIEMConnector(
        agent_context=AgentContext(id="001", name="web-01", ip="10.0.0.5", status="active"),
        rule_metadata=RuleMetadata(rule_id="5710", description="x", level=5),
    )
    analyst = _make_analyst(siem=siem)
    alert = _make_alert()

    with caplog.at_level(logging.DEBUG, logger="app.agent.state_graph"):
        analyst._step_gather_context(alert)

    assert "_step_gather_context input" in caplog.text
    assert "001" in caplog.text
    assert "_step_gather_context output" in caplog.text
    assert "web-01" in caplog.text
```

`EnrichmentRegistry`, `_FakeIPProvider`, `_make_enrichment_result`, `_FakeSIEMConnector`, `AgentContext`, `RuleMetadata`, `_make_analyst`, `_make_alert` are all already imported/defined in this file — no new imports needed for the test bodies themselves, only `import logging` at the top (add it if not already present).

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_state_graph.py -k "logs_input_and_output" -v`
Expected: FAIL — 3 failures, each because no `logger.debug` calls exist yet (empty `caplog.text`).

- [ ] **Step 3: Add the module logger and instrument the four methods**

In `app/agent/state_graph.py`, add near the top, after the existing imports (before `_INDICATOR_TYPE_TO_VALIDATOR`):

```python
import logging

logger = logging.getLogger(__name__)
```

Replace `_step_ingest_and_parse` (currently a single `return InvestigationStep(...)`) with:

```python
    def _step_ingest_and_parse(self, alert: Alert, model_available: bool) -> InvestigationStep:
        logger.debug(
            "_step_ingest_and_parse input: alert_id=%s, rule_id=%s, model_available=%s",
            alert.alert_id, alert.rule_id, model_available,
        )
        step = InvestigationStep(
            step_name=Step.INGEST_AND_PARSE.value,
            action="completed",
            tool_used=None,
            input=None,
            output_summary=f"alert {alert.alert_id} ingested; model available: {model_available}",
            timestamp=datetime.now(timezone.utc),
        )
        logger.debug("_step_ingest_and_parse output: %s", step.output_summary)
        return step
```

Replace `_step_extract_indicators` with:

```python
    def _step_extract_indicators(
        self, alert: Alert, model_available: bool
    ) -> tuple[list[Indicator], InvestigationStep]:
        logger.debug(
            "_step_extract_indicators input: alert_id=%s, model_available=%s", alert.alert_id, model_available
        )
        validated, candidate_count, validated_count = extract_and_validate(alert)

        if not model_available:
            step = InvestigationStep(
                step_name=Step.EXTRACT_INDICATORS.value,
                action="completed",
                tool_used="regex_extraction",
                input=None,
                output_summary=(
                    f"regex: {candidate_count} candidates, {validated_count} validated "
                    "(LLM-assisted extraction skipped: model unavailable)"
                ),
                timestamp=datetime.now(timezone.utc),
            )
            logger.debug(
                "_step_extract_indicators output: %s indicator(s): %s",
                len(validated), [(type(i).__name__, i.value) for i in validated],
            )
            return validated, step

        llm_validated, llm_candidate_count, llm_validated_count, llm_error = self._extract_indicators_via_llm(alert)
        merged = _merge_indicators(validated, llm_validated)

        if llm_error is not None:
            self._degraded_reasons.append(f"indicator extraction LLM failed: {llm_error}")
            summary = (
                f"regex: {candidate_count} candidates, {validated_count} validated; "
                f"LLM-assisted extraction failed: {llm_error}"
            )
        else:
            summary = (
                f"regex: {candidate_count} candidates, {validated_count} validated; "
                f"LLM: {llm_candidate_count} candidates, {llm_validated_count} validated"
            )

        step = InvestigationStep(
            step_name=Step.EXTRACT_INDICATORS.value,
            action="completed",
            tool_used="regex_extraction+llm_extraction",
            input=None,
            output_summary=summary,
            timestamp=datetime.now(timezone.utc),
        )
        logger.debug(
            "_step_extract_indicators output: %s indicator(s): %s",
            len(merged), [(type(i).__name__, i.value) for i in merged],
        )
        return merged, step
```

Replace `_extract_indicators_via_llm` with:

```python
    def _extract_indicators_via_llm(self, alert: Alert) -> tuple[list[Indicator], int, int, str | None]:
        prompt = build_extract_indicators_prompt(alert)
        logger.debug("_extract_indicators_via_llm prompt: %s", prompt)
        try:
            result = self._llm_client.generate_structured(prompt, ExtractedIndicators)
        except LLMClientError as exc:
            logger.debug("_extract_indicators_via_llm failed: %s", exc.kind)
            return [], 0, 0, exc.kind
        logger.debug("_extract_indicators_via_llm result: %s", result.model_dump_json())

        validated: list[Indicator] = []
        for candidate in result.candidates:
            validator_cls = _INDICATOR_TYPE_TO_VALIDATOR.get(candidate.type)
            if validator_cls is None:
                continue
            try:
                validated.append(validator_cls(value=candidate.value))
            except ValidationError:
                continue
        return validated, len(result.candidates), len(validated), None
```

Replace `_step_enrich` with:

```python
    def _step_enrich(self, indicators: list[Indicator]) -> tuple[list[EnrichmentResult], InvestigationStep]:
        logger.debug(
            "_step_enrich input: %s indicator(s): %s",
            len(indicators), [(type(i).__name__, i.value) for i in indicators],
        )
        if not indicators:
            step = InvestigationStep(
                step_name=Step.ENRICH.value,
                action="skipped",
                tool_used=None,
                input=None,
                output_summary="skipped: no validated indicators to enrich",
                timestamp=datetime.now(timezone.utc),
            )
            logger.debug("_step_enrich output: skipped, no indicators")
            return [], step

        results: list[EnrichmentResult] = []
        for indicator in indicators:
            try:
                results.append(self._enrichment_registry.enrich(indicator))
            except ValueError:
                queried_at = datetime.now(timezone.utc)
                results.append(
                    EnrichmentResult(
                        indicator_type=indicator.indicator_type,
                        indicator_value=indicator.value,
                        provider_id="none",
                        queried_at=queried_at,
                        verdict=EnrichmentVerdict.UNKNOWN,
                        score=0.0,
                        cache_expires_at=queried_at,
                        error="no_provider_registered",
                    )
                )
        step = InvestigationStep(
            step_name=Step.ENRICH.value,
            action="completed",
            tool_used="enrichment_registry",
            input=None,
            output_summary=f"enriched {len(results)} indicator(s)",
            timestamp=datetime.now(timezone.utc),
        )
        logger.debug("_step_enrich output: %s", [r.model_dump_json() for r in results])
        return results, step
```

Replace `_step_gather_context` with:

```python
    def _step_gather_context(
        self, alert: Alert
    ) -> tuple[AgentContext | None, RuleMetadata | None, InvestigationStep]:
        logger.debug("_step_gather_context input: agent_id=%s, rule_id=%s", alert.agent.id, alert.rule_id)
        try:
            agent_context = self._siem.get_agent_context(alert.agent.id)
            rule_metadata = self._siem.get_rule_metadata(alert.rule_id)
        except SIEMConnectorError as exc:
            self._degraded_reasons.append(f"SIEM context unavailable: {exc.kind}")
            step = InvestigationStep(
                step_name=Step.GATHER_CONTEXT.value,
                action="degraded",
                tool_used="siem_connector",
                input=None,
                output_summary=f"could not gather host/rule context: {exc.kind}",
                timestamp=datetime.now(timezone.utc),
            )
            logger.debug("_step_gather_context output: failed: %s", exc.kind)
            return None, None, step

        step = InvestigationStep(
            step_name=Step.GATHER_CONTEXT.value,
            action="completed",
            tool_used="siem_connector",
            input=None,
            output_summary=f"gathered context for agent {alert.agent.id}, rule {alert.rule_id}",
            timestamp=datetime.now(timezone.utc),
        )
        logger.debug(
            "_step_gather_context output: agent_context=%s, rule_metadata=%s",
            agent_context.model_dump_json(), rule_metadata.model_dump_json(),
        )
        return agent_context, rule_metadata, step
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_state_graph.py -k "logs_input_and_output" -v`
Expected: all 3 PASS.

- [ ] **Step 5: Run the full test suite**

Run: `pytest tests/ -v`
Expected: all PASS — these are additive `logger.debug` calls only; no existing test's assertions on `InvestigationStep`/return values change, since nothing about what's returned or persisted changed.

- [ ] **Step 6: Commit**

```bash
git add app/agent/state_graph.py tests/test_state_graph.py
git commit -m "feat: add debug logging to Ingest/Extract Indicators/Enrich/Gather Context steps"
```

---

### Task 2: Logging for steps 5-6 (Correlate, Risk Assessment)

**Files:**
- Modify: `app/agent/state_graph.py`
- Modify: `tests/test_state_graph.py`

**Interfaces:**
- Consumes: the module-level `logger` from Task 1 (already present in the file — do not redefine it).

- [ ] **Step 1: Write the failing test**

Add to `tests/test_state_graph.py`:

```python
def test_step_risk_assessment_logs_prompt_and_result(caplog):
    llm_client = _FakeLLMClient(
        model_available=True,
        responses={
            RiskAssessment: RiskAssessment(
                severity=Severity.HIGH, confidence=Confidence.HIGH, rationale="matches known malicious IP"
            )
        },
    )
    analyst = _make_analyst(llm_client=llm_client)
    alert = _make_alert()

    with caplog.at_level(logging.DEBUG, logger="app.agent.state_graph"):
        analyst._step_risk_assessment(alert, PatternType.BRUTE_FORCE, 14, [], model_available=True)

    assert "_step_risk_assessment input" in caplog.text
    assert "_assess_risk prompt" in caplog.text
    assert alert.rule_id in caplog.text
    assert "_assess_risk result" in caplog.text
    assert "matches known malicious IP" in caplog.text
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_state_graph.py -k test_step_risk_assessment_logs_prompt_and_result -v`
Expected: FAIL (empty `caplog.text`).

- [ ] **Step 3: Instrument `_step_correlate`, `_classify_correlation`, `_run_open_value_search`, `_step_risk_assessment`, `_assess_risk`**

Replace `_step_correlate` with:

```python
    def _step_correlate(
        self, alert: Alert, model_available: bool
    ) -> tuple[PatternType, int, InvestigationStep]:
        logger.debug("_step_correlate input: alert_id=%s, model_available=%s", alert.alert_id, model_available)
        queries, results, evidence_count, failed_count = self._run_canonical_searches(alert)
        failed_note = f"; {failed_count} canonical search(es) failed" if failed_count else ""
        if failed_count:
            self._degraded_reasons.append(f"{failed_count} canonical search(es) failed")

        if not model_available:
            step = InvestigationStep(
                step_name=Step.CORRELATE.value,
                action="completed",
                tool_used="siem_connector",
                input=None,
                output_summary=(
                    f"ran {len(results)} canonical search(es), {evidence_count} total evidence"
                    f"{failed_note} (classification skipped: model unavailable)"
                ),
                timestamp=datetime.now(timezone.utc),
            )
            logger.debug("_step_correlate output: pattern_type=other (skipped), evidence_count=%s", evidence_count)
            return PatternType.OTHER, evidence_count, step

        decision = self._classify_correlation(alert, results, evidence_count)

        follow_up_note = ""
        if decision.follow_up_query != SearchTemplate.NONE_NEEDED:
            follow_up_query = queries.get(decision.follow_up_query)
            if follow_up_query is not None:
                try:
                    follow_up_result = self._siem.search(follow_up_query)
                    evidence_count += follow_up_result.total_count
                    follow_up_note = f"; follow-up {decision.follow_up_query.value} added {follow_up_result.total_count}"
                except SIEMConnectorError:
                    follow_up_note = f"; follow-up {decision.follow_up_query.value} failed"
                    self._degraded_reasons.append(f"correlation follow-up {decision.follow_up_query.value} failed")

        open_value_note = ""
        if decision.pattern_type in (PatternType.NONE, PatternType.OTHER):
            open_value_note = self._run_open_value_search(alert, results)

        step = InvestigationStep(
            step_name=Step.CORRELATE.value,
            action="completed",
            tool_used="siem_connector+llm",
            input=None,
            output_summary=(
                f"pattern_type={decision.pattern_type.value}, evidence_count={evidence_count}"
                f"{failed_note}{follow_up_note}{open_value_note}"
            ),
            timestamp=datetime.now(timezone.utc),
        )
        logger.debug(
            "_step_correlate output: pattern_type=%s, evidence_count=%s%s%s",
            decision.pattern_type.value, evidence_count, follow_up_note, open_value_note,
        )
        return decision.pattern_type, evidence_count, step
```

Replace `_classify_correlation` with:

```python
    def _classify_correlation(
        self, alert: Alert, canonical_results: dict[SearchTemplate, SearchResult], evidence_count: int
    ) -> CorrelationDecision:
        prompt = build_correlation_decision_prompt(alert, canonical_results, evidence_count)
        logger.debug("_classify_correlation prompt: %s", prompt)
        try:
            decision = self._llm_client.generate_structured(prompt, CorrelationDecision)
        except LLMClientError as exc:
            self._degraded_reasons.append(f"correlation classification failed: {exc.kind}")
            logger.debug("_classify_correlation failed: %s, falling back to OTHER/NONE_NEEDED", exc.kind)
            return CorrelationDecision(pattern_type=PatternType.OTHER, follow_up_query=SearchTemplate.NONE_NEEDED)
        logger.debug("_classify_correlation result: %s", decision.model_dump_json())
        return decision
```

Replace `_run_open_value_search` with:

```python
    def _run_open_value_search(
        self, alert: Alert, canonical_results: dict[SearchTemplate, SearchResult]
    ) -> str:
        prompt = build_open_value_search_prompt(alert, canonical_results)
        logger.debug("_run_open_value_search prompt: %s", prompt)
        try:
            proposal = self._llm_client.generate_structured(prompt, OpenValueSearchProposal)
        except LLMClientError:
            logger.debug("_run_open_value_search: proposal call failed, skipping")
            return ""
        logger.debug("_run_open_value_search result: %s", proposal.model_dump_json())

        query = SearchQuery(
            clauses=[SearchClause(field="full_log", operator="contains", value=proposal.search_value)],
            time_range=(alert.timestamp - CANONICAL_SEARCH_WINDOW, alert.timestamp),
        )
        try:
            result = self._siem.search(query)
        except SIEMConnectorError:
            return f"; open-value search for {proposal.search_value!r} failed"
        return (
            f"; open-value search for {proposal.search_value!r} found {result.total_count} "
            "(noisier, unstructured match)"
        )
```

Replace `_step_risk_assessment` with:

```python
    def _step_risk_assessment(
        self, alert: Alert, pattern_type: PatternType, evidence_count: int,
        enrichment_results: list[EnrichmentResult], model_available: bool,
    ) -> tuple[RiskAssessment, InvestigationStep]:
        logger.debug(
            "_step_risk_assessment input: pattern_type=%s, evidence_count=%s, enrichment_count=%s, model_available=%s",
            pattern_type.value, evidence_count, len(enrichment_results), model_available,
        )
        if not model_available:
            assessment = RiskAssessment(
                severity=Severity.LOW, confidence=Confidence.LOW,
                rationale="risk assessment skipped: model unavailable",
            )
            step = InvestigationStep(
                step_name=Step.RISK_ASSESSMENT.value, action="skipped", tool_used=None, input=None,
                output_summary="skipped: model unavailable", timestamp=datetime.now(timezone.utc),
            )
            logger.debug("_step_risk_assessment output: skipped: %s", assessment.model_dump_json())
            return assessment, step

        assessment = self._assess_risk(alert, pattern_type, evidence_count, enrichment_results)
        step = InvestigationStep(
            step_name=Step.RISK_ASSESSMENT.value, action="completed", tool_used="llm", input=None,
            output_summary=f"severity={assessment.severity.value}, confidence={assessment.confidence.value}",
            timestamp=datetime.now(timezone.utc),
        )
        logger.debug("_step_risk_assessment output: %s", assessment.model_dump_json())
        return assessment, step
```

Replace `_assess_risk` with:

```python
    def _assess_risk(
        self, alert: Alert, pattern_type: PatternType, evidence_count: int,
        enrichment_results: list[EnrichmentResult],
    ) -> RiskAssessment:
        prompt = build_risk_assessment_prompt(alert, pattern_type, evidence_count, enrichment_results)
        logger.debug("_assess_risk prompt: %s", prompt)
        try:
            assessment = self._llm_client.generate_structured(prompt, RiskAssessment)
        except LLMClientError as exc:
            self._degraded_reasons.append(f"risk assessment failed: {exc.kind}")
            logger.debug("_assess_risk failed: %s", exc.kind)
            return RiskAssessment(
                severity=Severity.LOW, confidence=Confidence.LOW,
                rationale=f"risk assessment failed: {exc.kind}",
            )
        logger.debug("_assess_risk result: %s", assessment.model_dump_json())
        return assessment
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_state_graph.py -k test_step_risk_assessment_logs_prompt_and_result -v`
Expected: PASS.

- [ ] **Step 5: Run the full test suite**

Run: `pytest tests/ -v`
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add app/agent/state_graph.py tests/test_state_graph.py
git commit -m "feat: add debug logging to Correlate and Risk Assessment steps"
```

---

### Task 3: Logging for steps 7-9 (Draft Report, Self-Check, Finalize & Persist)

**Files:**
- Modify: `app/agent/state_graph.py`
- Modify: `tests/test_state_graph.py`

**Interfaces:**
- Consumes: the module-level `logger` from Task 1 (already present).

- [ ] **Step 1: Write the failing test**

Add to `tests/test_state_graph.py`:

```python
def test_step_self_check_logs_input_and_output(caplog):
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

    with caplog.at_level(logging.DEBUG, logger="app.agent.state_graph"):
        analyst._step_self_check(
            alert, draft, PatternType.BRUTE_FORCE, 14, [], risk_assessment,
            _passthrough_correlate_step(), model_available=True,
        )

    assert "_step_self_check input" in caplog.text
    assert "_run_self_check prompt" in caplog.text
    assert "_run_self_check result" in caplog.text
    assert "_step_self_check output" in caplog.text
```

`_draft_with_two_actions` and `_passthrough_correlate_step` are already defined in this file (from Phase 4d) — no new fixtures needed.

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_state_graph.py -k test_step_self_check_logs_input_and_output -v`
Expected: FAIL.

- [ ] **Step 3: Instrument `_step_draft_report`, `_draft_canonical`, `_draft_experimental`, `_step_self_check`, `_run_self_check`, `_step_finalize_and_persist`**

Replace `_step_draft_report` with:

```python
    def _step_draft_report(
        self, alert: Alert, pattern_type: PatternType, evidence_count: int,
        enrichment_results: list[EnrichmentResult], risk_assessment: RiskAssessment, model_available: bool,
    ) -> tuple[DraftReportCanonical, DraftReportExperimental | None, InvestigationStep]:
        logger.debug(
            "_step_draft_report input: pattern_type=%s, evidence_count=%s, severity=%s, model_available=%s",
            pattern_type.value, evidence_count, risk_assessment.severity.value, model_available,
        )
        fallback_summary = (
            f"Rule {alert.rule_id} ({alert.rule_description}), level {alert.rule_level}, "
            f"on agent {alert.agent.name}."
        )
        if not model_available:
            draft = DraftReportCanonical(
                alert_summary=fallback_summary,
                rationale=risk_assessment.rationale,
                recommended_actions=[RecommendedAction.ESCALATE_TO_HUMAN_ANALYST],
            )
            step = InvestigationStep(
                step_name=Step.DRAFT_REPORT.value, action="skipped", tool_used=None, input=None,
                output_summary="skipped: model unavailable", timestamp=datetime.now(timezone.utc),
            )
            logger.debug("_step_draft_report output: skipped: %s", draft.model_dump_json())
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
        logger.debug(
            "_step_draft_report output: draft=%s, experimental=%s",
            draft.model_dump_json(), experimental.model_dump_json() if experimental is not None else None,
        )
        return draft, experimental, step
```

Replace `_draft_canonical` with:

```python
    def _draft_canonical(
        self, alert: Alert, pattern_type: PatternType, evidence_count: int,
        enrichment_results: list[EnrichmentResult], risk_assessment: RiskAssessment, fallback_summary: str,
    ) -> DraftReportCanonical:
        prompt = build_draft_canonical_prompt(alert, pattern_type, evidence_count, enrichment_results, risk_assessment)
        logger.debug("_draft_canonical prompt: %s", prompt)
        try:
            draft = self._llm_client.generate_structured(prompt, DraftReportCanonical)
        except LLMClientError as exc:
            self._degraded_reasons.append(f"draft report failed: {exc.kind}")
            logger.debug("_draft_canonical failed: %s", exc.kind)
            return DraftReportCanonical(
                alert_summary=fallback_summary,
                rationale=risk_assessment.rationale,
                recommended_actions=[RecommendedAction.ESCALATE_TO_HUMAN_ANALYST],
            )
        logger.debug("_draft_canonical result: %s", draft.model_dump_json())
        return draft
```

Replace `_draft_experimental` with:

```python
    def _draft_experimental(
        self, alert: Alert, pattern_type: PatternType, evidence_count: int,
        enrichment_results: list[EnrichmentResult], risk_assessment: RiskAssessment,
    ) -> DraftReportExperimental | None:
        prompt = build_draft_experimental_prompt(alert, pattern_type, evidence_count, enrichment_results, risk_assessment)
        logger.debug("_draft_experimental prompt: %s", prompt)
        try:
            experimental = self._llm_client.generate_structured(prompt, DraftReportExperimental)
        except LLMClientError:
            logger.debug("_draft_experimental failed")
            return None
        logger.debug("_draft_experimental result: %s", experimental.model_dump_json())
        return experimental
```

Replace `_step_self_check` with:

```python
    def _step_self_check(
        self, alert: Alert, draft: DraftReportCanonical, pattern_type: PatternType, evidence_count: int,
        enrichment_results: list[EnrichmentResult], risk_assessment: RiskAssessment,
        correlate_step: InvestigationStep, model_available: bool,
    ) -> tuple[DraftReportCanonical, str, InvestigationStep]:
        logger.debug("_step_self_check input: draft=%s, model_available=%s", draft.model_dump_json(), model_available)
        if not model_available:
            notes = _compute_uncertainty_notes(alert, enrichment_results, correlate_step, [])
            notes = "self-check skipped: model unavailable" + (f"; {notes}" if notes else "")
            step = InvestigationStep(
                step_name=Step.SELF_CHECK.value, action="skipped", tool_used=None, input=None,
                output_summary="skipped: model unavailable", timestamp=datetime.now(timezone.utc),
            )
            logger.debug("_step_self_check output: skipped, draft unchanged, notes=%r", notes)
            return draft, notes, step

        result, failure_kind = self._run_self_check(draft, pattern_type, evidence_count, enrichment_results, risk_assessment)
        if result is None:
            notes = _compute_uncertainty_notes(alert, enrichment_results, correlate_step, [])
            notes = f"self-check could not run: {failure_kind}" + (f"; {notes}" if notes else "")
            step = InvestigationStep(
                step_name=Step.SELF_CHECK.value, action="degraded", tool_used="llm", input=None,
                output_summary="self-check call failed; corrections not applied", timestamp=datetime.now(timezone.utc),
            )
            logger.debug("_step_self_check output: call failed, draft unchanged, notes=%r", notes)
            return draft, notes, step

        correction_result = _apply_self_check_corrections(draft, result)
        if correction_result is None:
            self._degraded_reasons.append("self-check returned a mismatched audit count")
            notes = _compute_uncertainty_notes(alert, enrichment_results, correlate_step, [])
            notes = "self-check audit count did not match claim count; corrections not applied" + (f"; {notes}" if notes else "")
            step = InvestigationStep(
                step_name=Step.SELF_CHECK.value, action="degraded", tool_used="llm", input=None,
                output_summary=f"self-check returned {len(result.audits)} audit(s) for {len(_claims_for(draft))} claim(s); corrections not applied",
                timestamp=datetime.now(timezone.utc),
            )
            logger.debug(
                "_step_self_check output: mismatched audit count (%s audits, %s claims), draft unchanged, notes=%r",
                len(result.audits), len(_claims_for(draft)), notes,
            )
            return draft, notes, step

        corrected_draft, flagged_claims = correction_result
        if flagged_claims:
            self._degraded_reasons.append(f"self-check flagged {len(flagged_claims)} unsupported claim(s)")
        notes = _compute_uncertainty_notes(alert, enrichment_results, correlate_step, flagged_claims)
        step = InvestigationStep(
            step_name=Step.SELF_CHECK.value, action="completed", tool_used="llm", input=None,
            output_summary=f"audited {len(result.audits)} claim(s), {len(flagged_claims)} flagged",
            timestamp=datetime.now(timezone.utc),
        )
        logger.debug(
            "_step_self_check output: corrected_draft=%s, flagged_claims=%s, notes=%r",
            corrected_draft.model_dump_json(), flagged_claims, notes,
        )
        return corrected_draft, notes, step
```

Replace `_run_self_check` with:

```python
    def _run_self_check(
        self, draft: DraftReportCanonical, pattern_type: PatternType, evidence_count: int,
        enrichment_results: list[EnrichmentResult], risk_assessment: RiskAssessment,
    ) -> tuple[SelfCheckResult | None, str | None]:
        prompt = build_self_check_prompt(draft, pattern_type, evidence_count, enrichment_results, risk_assessment)
        logger.debug("_run_self_check prompt: %s", prompt)
        try:
            result = self._llm_client.generate_structured(prompt, SelfCheckResult)
        except LLMClientError as exc:
            self._degraded_reasons.append(f"self-check failed: {exc.kind}")
            logger.debug("_run_self_check failed: %s", exc.kind)
            return None, exc.kind
        logger.debug("_run_self_check result: %s", result.model_dump_json())
        return result, None
```

Replace `_step_finalize_and_persist` with:

```python
    def _step_finalize_and_persist(self, alert: Alert, report: Report) -> InvestigationStep:
        logger.debug(
            "_step_finalize_and_persist input: report_id=%s, alert_id=%s", report.report_id, alert.alert_id
        )
        try:
            self._alert_store.save_report(report)
            self._alert_store.update_alert_status(str(alert.alert_id), AlertStatus.INVESTIGATED)
        except Exception as exc:
            step = InvestigationStep(
                step_name=Step.FINALIZE_AND_PERSIST.value,
                action="degraded",
                tool_used="alert_store",
                input=None,
                output_summary=f"could not persist report or update alert status: {exc}",
                timestamp=datetime.now(timezone.utc),
            )
            logger.debug("_step_finalize_and_persist output: failed: %s", exc)
            return step
        step = InvestigationStep(
            step_name=Step.FINALIZE_AND_PERSIST.value,
            action="completed",
            tool_used="alert_store",
            input=None,
            output_summary=f"report {report.report_id} persisted, alert marked investigated",
            timestamp=datetime.now(timezone.utc),
        )
        logger.debug("_step_finalize_and_persist output: persisted")
        return step
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_state_graph.py -k test_step_self_check_logs_input_and_output -v`
Expected: PASS.

- [ ] **Step 5: Run the full test suite**

Run: `pytest tests/ -v`
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add app/agent/state_graph.py tests/test_state_graph.py
git commit -m "feat: add debug logging to Draft Report, Self-Check, and Finalize & Persist steps"
```

---

### Task 4: CLI `--verbose`/`--log-file` options

**Files:**
- Modify: `app/cli.py`
- Modify: `tests/test_cli.py`

**Interfaces:**
- Consumes: nothing from Tasks 1-3 directly (this task only wires CLI options to a logging *configuration* function — it never calls `state_graph.py`'s methods itself, since `investigate_all_cmd`/`investigate_one_cmd` already call `analyst.investigate()`, which internally exercises every instrumented method from Tasks 1-3).
- Produces: `_configure_verbose_logging(verbose: bool, log_file: Path | None) -> None` — used only within `app/cli.py`, not consumed by any other module.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_cli.py`:

```python
import logging


def test_configure_verbose_logging_attaches_stream_handler_when_verbose():
    from app.cli import _configure_verbose_logging

    logging.getLogger("app").handlers.clear()
    _configure_verbose_logging(verbose=True, log_file=None)
    app_logger = logging.getLogger("app")

    assert app_logger.level == logging.DEBUG
    assert len(app_logger.handlers) == 1
    assert isinstance(app_logger.handlers[0], logging.StreamHandler)
    assert not isinstance(app_logger.handlers[0], logging.FileHandler)

    logging.getLogger("app").handlers.clear()


def test_configure_verbose_logging_attaches_file_handler_when_log_file_given(tmp_path):
    from app.cli import _configure_verbose_logging

    log_path = tmp_path / "trace.log"
    _configure_verbose_logging(verbose=False, log_file=log_path)
    app_logger = logging.getLogger("app")

    assert app_logger.level == logging.DEBUG
    assert len(app_logger.handlers) == 1
    assert isinstance(app_logger.handlers[0], logging.FileHandler)

    logging.getLogger("app").handlers.clear()


def test_configure_verbose_logging_does_nothing_when_neither_option_given():
    from app.cli import _configure_verbose_logging

    logging.getLogger("app").handlers.clear()
    _configure_verbose_logging(verbose=False, log_file=None)
    app_logger = logging.getLogger("app")

    assert app_logger.handlers == []


def test_configure_verbose_logging_is_idempotent_across_repeated_calls():
    from app.cli import _configure_verbose_logging

    _configure_verbose_logging(verbose=True, log_file=None)
    _configure_verbose_logging(verbose=True, log_file=None)
    app_logger = logging.getLogger("app")

    assert len(app_logger.handlers) == 1

    logging.getLogger("app").handlers.clear()
```

`FileHandler` is a subclass of `StreamHandler` in the standard library, so `test_configure_verbose_logging_attaches_stream_handler_when_verbose` explicitly asserts `not isinstance(..., logging.FileHandler)` in addition to `isinstance(..., logging.StreamHandler)` — otherwise a bug that always creates a `FileHandler` regardless of `log_file` would incorrectly pass the `isinstance(..., StreamHandler)` check alone.

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_cli.py -k configure_verbose_logging -v`
Expected: FAIL with `ImportError: cannot import name '_configure_verbose_logging'`.

- [ ] **Step 3: Write `_configure_verbose_logging` and wire it into both commands**

Add to the top of `app/cli.py`, alongside the existing imports:

```python
import logging
import sys
```

Add the function itself, anywhere before `investigate_all_cmd` (e.g. right after the existing imports, before `app = typer.Typer()`, or right before `investigate_all_cmd` — either is fine, just keep it above its first use):

```python
def _configure_verbose_logging(verbose: bool, log_file: Path | None) -> None:
    app_logger = logging.getLogger("app")
    for handler in list(app_logger.handlers):
        app_logger.removeHandler(handler)
    if not verbose and log_file is None:
        return
    app_logger.setLevel(logging.DEBUG)
    handler = logging.FileHandler(log_file, mode="a") if log_file is not None else logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    app_logger.addHandler(handler)
```

Update `investigate_all_cmd`'s signature and add the configuration call as its first line:

```python
@app.command(name="investigate-all")
def investigate_all_cmd(
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Log each pipeline stage's input/output at DEBUG level."
    ),
    log_file: Path = typer.Option(
        None, "--log-file", help="Write verbose logs to this file instead of stdout. Implies --verbose."
    ),
) -> None:
    _configure_verbose_logging(verbose, log_file)
    settings = get_settings()
    alert_store = build_alert_store(settings)

    alerts = alert_store.list_alerts(status=AlertStatus.NEW)
    if not alerts:
        typer.echo("No new alerts to investigate.")
        return

    try:
        analyst = build_analyst(settings, alert_store=alert_store)
    except RuntimeError as exc:
        typer.echo(f"Cannot investigate: {exc}", err=True)
        raise typer.Exit(code=1)
    reports_dir = Path(settings.reports_dir)

    for alert in alerts:
        try:
            report = _investigate_alert(analyst, alert, reports_dir)
        except OSError as exc:
            typer.echo(f"Failed to write report for alert {alert.alert_id}: {exc}", err=True)
            continue
        typer.echo(_summary_line(report))
```

Update `investigate_one_cmd`'s signature and add the same configuration call as its first line:

```python
@app.command(name="investigate-one")
def investigate_one_cmd(
    alert_id: str = typer.Argument(...),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Log each pipeline stage's input/output at DEBUG level."
    ),
    log_file: Path = typer.Option(
        None, "--log-file", help="Write verbose logs to this file instead of stdout. Implies --verbose."
    ),
) -> None:
    _configure_verbose_logging(verbose, log_file)
    settings = get_settings()
    alert_store = build_alert_store(settings)

    try:
        alert = alert_store.get_alert(alert_id)
    except AlertNotFoundError:
        typer.echo(f"No alert found with id {alert_id}.", err=True)
        raise typer.Exit(code=1)

    try:
        analyst = build_analyst(settings, alert_store=alert_store)
    except RuntimeError as exc:
        typer.echo(f"Cannot investigate: {exc}", err=True)
        raise typer.Exit(code=1)
    reports_dir = Path(settings.reports_dir)

    report = _investigate_alert(analyst, alert, reports_dir)
    typer.echo(_summary_line(report))
```

Only the function signature and the added `_configure_verbose_logging(verbose, log_file)` first line change in each command — the rest of each function body is unchanged from its current state (read the current file to confirm the exact body before editing, since Phase 5's final review fix wave already reordered these — the code shown above already reflects that final, merged state).

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_cli.py -k configure_verbose_logging -v`
Expected: all 4 PASS.

- [ ] **Step 5: Run the full test suite**

Run: `pytest tests/ -v`
Expected: all PASS — existing `investigate-all`/`investigate-one` tests never pass `--verbose`/`--log-file`, so `_configure_verbose_logging(False, None)` runs as their first line and returns immediately without altering any handler state relevant to those tests.

- [ ] **Step 6: Commit**

```bash
git add app/cli.py tests/test_cli.py
git commit -m "feat: add --verbose/--log-file options to investigate-all and investigate-one"
```

---

## Self-Review Notes (for the plan author, not a task)

- **Spec coverage:** §1 (logging instrumentation, all 9 steps + 7 LLM helpers) → Tasks 1-3, split by pipeline-stage grouping matching the original phases' own task boundaries (4b's ingest/enrich/context, 4c's extract/correlate/risk, 4d's draft/self-check/finalize). §2 (CLI options) → Task 4. §3 (testing) → each task's Step 1, plus Task 4's explicit `FileHandler`-is-a-`StreamHandler`-subclass edge case.
- **Type consistency check:** `logger` is defined once in Task 1 and referenced identically (no re-import, no re-definition) in Tasks 2 and 3. `_configure_verbose_logging`'s signature (`verbose: bool, log_file: Path | None`) matches exactly between its definition and both call sites in Task 4.
- **No placeholder scan:** every `logger.debug(...)` call shown is the actual final code to paste, not a description of what to log — each task's code blocks are copy-pasteable in full.
