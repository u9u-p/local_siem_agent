# Model Benchmark Harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a standalone, offline-reproducible benchmark harness that scores local LLM candidates (`gemma4:12b`, `qwen3.5:9b`, `qwen3.6:27b`, `gpt-oss:20b`) against a frozen golden dataset of Wazuh alerts, auditing each of the Agentic Analyst's 7 LLM call sites independently.

**Architecture:** A `scripts/benchmark/` package (fixtures, scorers, structured-output gate, harness, report) driven by a standalone `scripts/benchmark_models.py` CLI — no changes to `app/agent/state_graph.py`. The harness calls `AgenticAnalyst`'s existing private step methods directly against frozen golden inputs (isolated per-step mode) and, separately, runs one full `investigate()` pass per model against fixture-backed fake `SIEMConnector`/`EnrichmentRegistry` (end-to-end composite mode). A one-time capture tool (`scripts/capture_golden_fixture.py`) freezes real alerts/correlation/enrichment data from the live Wazuh stack into `benchmarks/golden/`.

**Tech Stack:** Python 3.11, Pydantic (fixture schemas, scorers), `argparse` (CLI — no new dependency), pytest (existing test suite conventions).

## Global Constraints

- No changes to `app/agent/state_graph.py` — the harness only calls its existing private methods and never modifies production code (per the approved design spec).
- `benchmarks/golden/` is checked into git (fixture data, not runtime output); `data/benchmarks/` (harness run output) is gitignored, matching the existing `data/` convention.
- The harness is a standalone script, not part of the `agent` Typer CLI.
- Every new pure-logic module (`fixtures.py`, `scorers.py`, `gate.py`) is unit-tested with fakes/synthetic data — no live Ollama/Wazuh dependency for its own tests.
- Design reference: `docs/superpowers/specs/2026-08-12-model-benchmark-harness-design.md`.

---

### Task 1: Golden fixture schema + validation

**Files:**
- Create: `scripts/benchmark/__init__.py` (empty)
- Create: `scripts/benchmark/fixtures.py`
- Test: `tests/benchmark/__init__.py` (empty)
- Test: `tests/benchmark/test_fixtures.py`

**Interfaces:**
- Produces: `ExpectedGroundTruth` (Pydantic model), `FixtureValidationError(slug, reason)`, `load_expected(slug, golden_dir) -> ExpectedGroundTruth`, `load_alert(slug, golden_dir) -> Alert`, `load_correlation(slug, golden_dir) -> dict[SearchTemplate, SearchResult]`, `load_enrichment(slug, golden_dir) -> list[EnrichmentResult]`, `list_golden_slugs(golden_dir) -> list[str]`, `validate_all_fixtures(golden_dir)`. All later tasks load fixtures exclusively through these functions.

- [ ] **Step 1: Write the failing tests**

```python
# tests/benchmark/test_fixtures.py
import json
from pathlib import Path

import pytest

from app.agent.schemas import DraftReportCanonical, PatternType, RecommendedAction, TriageVerdict
from app.schemas import AgentRef, Confidence, IndicatorType, Severity
from scripts.benchmark.fixtures import (
    ExpectedGroundTruth,
    FixtureValidationError,
    list_golden_slugs,
    load_alert,
    load_correlation,
    load_enrichment,
    load_expected,
    validate_all_fixtures,
)


def _write_alert_json(path: Path) -> None:
    path.write_text(json.dumps({
        "alert_id": "8b3f1e2a-0000-0000-0000-000000000001",
        "source_alert_id": "1700000000.1",
        "source_system": "wazuh",
        "rule_id": "5710",
        "rule_description": "sshd: Attempt to login using a non-existent user",
        "rule_level": 5,
        "rule_groups": [],
        "mitre": None,
        "timestamp": "2026-07-31T09:14:01+00:00",
        "ingested_at": "2026-07-31T09:14:05+00:00",
        "agent": {"id": "001", "name": "web-prod-01", "ip": "10.0.0.5"},
        "manager_name": "wazuh-manager",
        "location": "/var/log/auth.log",
        "full_log": "Invalid user admin from 185.220.101.45",
        "data": {},
        "raw_json": {},
    }))


def _write_expected_json(path: Path, wrong_claim_index: int = 1) -> None:
    draft = DraftReportCanonical(
        alert_summary="A brute-force SSH login attempt was observed from 185.220.101.45.",
        rationale="This is a known-good rationale grounded in the evidence.",
        recommended_actions=[RecommendedAction.BLOCK_SOURCE_IP],
    )
    payload = {
        "expected_indicators": [{"type": "ip", "value": "185.220.101.45"}],
        "expected_pattern_type": "brute_force",
        "expected_severity": "high",
        "expected_confidence": "high",
        "expected_triage_verdict": "true_positive",
        "key_facts": ["source ip 185.220.101.45", "rule 5710"],
        "poisoned_claim": {"draft": draft.model_dump(mode="json"), "wrong_claim_index": wrong_claim_index},
    }
    path.write_text(json.dumps(payload))


def test_load_expected_parses_valid_fixture(tmp_path):
    slug_dir = tmp_path / "ssh-bruteforce"
    slug_dir.mkdir()
    _write_expected_json(slug_dir / "expected.json")

    ground_truth = load_expected("ssh-bruteforce", tmp_path)

    assert isinstance(ground_truth, ExpectedGroundTruth)
    assert ground_truth.expected_pattern_type == PatternType.BRUTE_FORCE
    assert ground_truth.expected_severity == Severity.HIGH
    assert ground_truth.expected_confidence == Confidence.HIGH
    assert ground_truth.expected_triage_verdict == TriageVerdict.TRUE_POSITIVE
    assert ground_truth.expected_indicators[0].type == IndicatorType.IP


def test_load_expected_raises_on_missing_file(tmp_path):
    with pytest.raises(FixtureValidationError):
        load_expected("does-not-exist", tmp_path)


def test_load_expected_raises_on_out_of_range_wrong_claim_index(tmp_path):
    slug_dir = tmp_path / "bad"
    slug_dir.mkdir()
    _write_expected_json(slug_dir / "expected.json", wrong_claim_index=99)

    with pytest.raises(FixtureValidationError):
        load_expected("bad", tmp_path)


def test_load_alert_round_trips(tmp_path):
    slug_dir = tmp_path / "ssh-bruteforce"
    slug_dir.mkdir()
    _write_alert_json(slug_dir / "alert.json")

    alert = load_alert("ssh-bruteforce", tmp_path)

    assert alert.rule_id == "5710"
    assert alert.agent == AgentRef(id="001", name="web-prod-01", ip="10.0.0.5")


def test_load_correlation_and_enrichment_default_to_empty(tmp_path):
    slug_dir = tmp_path / "ssh-bruteforce"
    slug_dir.mkdir()
    (slug_dir / "correlation.json").write_text("{}")
    (slug_dir / "enrichment.json").write_text("[]")

    assert load_correlation("ssh-bruteforce", tmp_path) == {}
    assert load_enrichment("ssh-bruteforce", tmp_path) == []


def test_list_golden_slugs_returns_sorted_subdirectory_names(tmp_path):
    (tmp_path / "b-slug").mkdir()
    (tmp_path / "a-slug").mkdir()

    assert list_golden_slugs(tmp_path) == ["a-slug", "b-slug"]


def test_validate_all_fixtures_raises_with_slug_context_on_bad_fixture(tmp_path):
    slug_dir = tmp_path / "broken"
    slug_dir.mkdir()
    _write_alert_json(slug_dir / "alert.json")
    (slug_dir / "correlation.json").write_text("{}")
    (slug_dir / "enrichment.json").write_text("[]")
    _write_expected_json(slug_dir / "expected.json", wrong_claim_index=99)

    with pytest.raises(FixtureValidationError) as exc_info:
        validate_all_fixtures(tmp_path)

    assert exc_info.value.slug == "broken"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/benchmark/test_fixtures.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'scripts.benchmark.fixtures'`

- [ ] **Step 3: Write the implementation**

```python
# scripts/benchmark/fixtures.py
from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, ValidationError

from app.agent.schemas import DraftReportCanonical, PatternType, SearchTemplate, TriageVerdict
from app.integration.models import SearchResult
from app.schemas import Alert, Confidence, EnrichmentResult, IndicatorType, Severity

GOLDEN_DIR = Path("benchmarks/golden")


class ExpectedIndicator(BaseModel):
    type: IndicatorType
    value: str


class PoisonedClaim(BaseModel):
    draft: DraftReportCanonical
    wrong_claim_index: int


class ExpectedGroundTruth(BaseModel):
    expected_indicators: list[ExpectedIndicator]
    expected_pattern_type: PatternType
    expected_severity: Severity
    expected_confidence: Confidence
    expected_triage_verdict: TriageVerdict
    key_facts: list[str]
    poisoned_claim: PoisonedClaim


class FixtureValidationError(Exception):
    def __init__(self, slug: str, reason: str) -> None:
        super().__init__(f"golden fixture {slug!r} is invalid: {reason}")
        self.slug = slug
        self.reason = reason


def _poisoned_claim_count(poisoned_claim: PoisonedClaim) -> int:
    draft = poisoned_claim.draft
    return 2 + len(draft.recommended_actions)  # alert_summary, rationale, then one per action


def load_expected(slug: str, golden_dir: Path = GOLDEN_DIR) -> ExpectedGroundTruth:
    path = golden_dir / slug / "expected.json"
    if not path.exists():
        raise FixtureValidationError(slug, f"missing {path}")
    try:
        ground_truth = ExpectedGroundTruth.model_validate_json(path.read_text())
    except ValidationError as exc:
        raise FixtureValidationError(slug, str(exc)) from exc

    claim_count = _poisoned_claim_count(ground_truth.poisoned_claim)
    index = ground_truth.poisoned_claim.wrong_claim_index
    if not (0 <= index < claim_count):
        raise FixtureValidationError(
            slug, f"poisoned_claim.wrong_claim_index {index} out of range for {claim_count} claim(s)"
        )
    return ground_truth


def load_alert(slug: str, golden_dir: Path = GOLDEN_DIR) -> Alert:
    path = golden_dir / slug / "alert.json"
    if not path.exists():
        raise FixtureValidationError(slug, f"missing {path}")
    try:
        return Alert.model_validate_json(path.read_text())
    except ValidationError as exc:
        raise FixtureValidationError(slug, str(exc)) from exc


def load_correlation(slug: str, golden_dir: Path = GOLDEN_DIR) -> dict[SearchTemplate, SearchResult]:
    path = golden_dir / slug / "correlation.json"
    if not path.exists():
        raise FixtureValidationError(slug, f"missing {path}")
    try:
        raw = json.loads(path.read_text())
        return {SearchTemplate(key): SearchResult.model_validate(value) for key, value in raw.items()}
    except (json.JSONDecodeError, ValidationError, ValueError) as exc:
        raise FixtureValidationError(slug, str(exc)) from exc


def load_enrichment(slug: str, golden_dir: Path = GOLDEN_DIR) -> list[EnrichmentResult]:
    path = golden_dir / slug / "enrichment.json"
    if not path.exists():
        raise FixtureValidationError(slug, f"missing {path}")
    try:
        raw = json.loads(path.read_text())
        return [EnrichmentResult.model_validate(item) for item in raw]
    except (json.JSONDecodeError, ValidationError) as exc:
        raise FixtureValidationError(slug, str(exc)) from exc


def list_golden_slugs(golden_dir: Path = GOLDEN_DIR) -> list[str]:
    return sorted(p.name for p in golden_dir.iterdir() if p.is_dir())


def validate_all_fixtures(golden_dir: Path = GOLDEN_DIR) -> None:
    for slug in list_golden_slugs(golden_dir):
        load_expected(slug, golden_dir)
        load_alert(slug, golden_dir)
        load_correlation(slug, golden_dir)
        load_enrichment(slug, golden_dir)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/benchmark/test_fixtures.py -v`
Expected: PASS (7 tests)

- [ ] **Step 5: Commit**

```bash
git add scripts/benchmark/__init__.py scripts/benchmark/fixtures.py tests/benchmark/__init__.py tests/benchmark/test_fixtures.py
git commit -m "feat: add golden fixture schema and validation for the model benchmark harness"
```

---

### Task 2: Scorers

**Files:**
- Create: `scripts/benchmark/scorers.py`
- Test: `tests/benchmark/test_scorers.py`

**Interfaces:**
- Consumes: nothing from Task 1 directly (scorers operate on already-loaded values, not fixture files).
- Produces: `ScoreResult(scorer_name: str, value: float, detail: str)`, `EnumExactMatchScorer`, `IndicatorSetScorer` + `IndicatorSetExpected(indicators: list[tuple[IndicatorType, str]])`, `SelfCheckAuditScorer`, `DeterministicProxyScorer` + `ProxyCheckExpected(key_facts: list[str])`, `LLMJudgeScorer(judge_client: LLMClient)`, `JudgeVerdict` (Pydantic model: `groundedness: int`, `coverage: int`, `contradiction: bool`). Task 6 (CLI) selects which scorers to run per `--scoring` flag.

- [ ] **Step 1: Write the failing tests**

```python
# tests/benchmark/test_scorers.py
from app.agent.schemas import ClaimAudit, SelfCheckResult
from app.schemas import IndicatorType, Severity
from scripts.benchmark.scorers import (
    DeterministicProxyScorer,
    EnumExactMatchScorer,
    IndicatorSetExpected,
    IndicatorSetScorer,
    JudgeVerdict,
    LLMJudgeScorer,
    ProxyCheckExpected,
    SelfCheckAuditScorer,
)


def test_enum_exact_match_scorer_matches():
    result = EnumExactMatchScorer().score(Severity.HIGH, Severity.HIGH)
    assert result.value == 1.0


def test_enum_exact_match_scorer_mismatches():
    result = EnumExactMatchScorer().score(Severity.HIGH, Severity.LOW)
    assert result.value == 0.0
    assert "expected=" in result.detail


def test_indicator_set_scorer_perfect_match():
    expected = IndicatorSetExpected(indicators=[(IndicatorType.IP, "185.220.101.45")])
    result = IndicatorSetScorer().score(expected, [(IndicatorType.IP, "185.220.101.45")])
    assert result.value == 1.0


def test_indicator_set_scorer_partial_match_scores_between_zero_and_one():
    expected = IndicatorSetExpected(indicators=[(IndicatorType.IP, "185.220.101.45"), (IndicatorType.DOMAIN, "evil.example")])
    result = IndicatorSetScorer().score(expected, [(IndicatorType.IP, "185.220.101.45")])
    assert 0.0 < result.value < 1.0
    assert "missing" in result.detail


def test_indicator_set_scorer_empty_expected_and_actual_is_perfect():
    result = IndicatorSetScorer().score(IndicatorSetExpected(indicators=[]), [])
    assert result.value == 1.0


def test_self_check_audit_scorer_rewards_catching_the_injected_error():
    result = SelfCheckResult(audits=[
        ClaimAudit(claim="a", supported=True, correction=None),
        ClaimAudit(claim="b", supported=False, correction="fixed"),
    ])
    scored = SelfCheckAuditScorer().score(wrong_claim_index=1, result=result)
    assert scored.value == 1.0


def test_self_check_audit_scorer_penalizes_false_positive_flags():
    result = SelfCheckResult(audits=[
        ClaimAudit(claim="a", supported=False, correction="oops"),  # wrongly flagged
        ClaimAudit(claim="b", supported=False, correction="fixed"),  # correctly flagged (index 1)
    ])
    scored = SelfCheckAuditScorer().score(wrong_claim_index=1, result=result)
    assert scored.value == 0.0  # caught it, but also 100% false-positive rate on the rest


def test_self_check_audit_scorer_handles_short_audit_list():
    result = SelfCheckResult(audits=[ClaimAudit(claim="a", supported=True, correction=None)])
    scored = SelfCheckAuditScorer().score(wrong_claim_index=1, result=result)
    assert scored.value == 0.0


def test_deterministic_proxy_scorer_rewards_covered_facts():
    expected = ProxyCheckExpected(key_facts=["source ip 185.220.101.45 is involved"])
    result = DeterministicProxyScorer().score(expected, "The source ip 185.220.101.45 is involved in this alert.")
    assert result.value == 1.0


def test_deterministic_proxy_scorer_penalizes_missing_facts():
    expected = ProxyCheckExpected(key_facts=["source ip 185.220.101.45 is involved"])
    result = DeterministicProxyScorer().score(expected, "Nothing relevant here.")
    assert result.value == 0.0


def test_deterministic_proxy_scorer_empty_key_facts_is_perfect():
    result = DeterministicProxyScorer().score(ProxyCheckExpected(key_facts=[]), "anything")
    assert result.value == 1.0


class _FakeJudgeClient:
    def __init__(self, verdict: JudgeVerdict) -> None:
        self._verdict = verdict
        self.prompts: list[str] = []

    def generate_structured(self, prompt, schema):
        self.prompts.append(prompt)
        return self._verdict

    def health_check(self):
        return True

    def model_available(self):
        return True


def test_llm_judge_scorer_combines_groundedness_and_coverage():
    judge = _FakeJudgeClient(JudgeVerdict(groundedness=5, coverage=5, contradiction=False))
    result = LLMJudgeScorer(judge).score(ProxyCheckExpected(key_facts=["fact one"]), "some summary")
    assert result.value == 1.0
    assert "fact one" in judge.prompts[0]


def test_llm_judge_scorer_zeroes_out_on_contradiction():
    judge = _FakeJudgeClient(JudgeVerdict(groundedness=5, coverage=5, contradiction=True))
    result = LLMJudgeScorer(judge).score(ProxyCheckExpected(key_facts=["fact one"]), "some summary")
    assert result.value == 0.0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/benchmark/test_scorers.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'scripts.benchmark.scorers'`

- [ ] **Step 3: Write the implementation**

```python
# scripts/benchmark/scorers.py
from __future__ import annotations

from dataclasses import dataclass

from pydantic import BaseModel

from app.agent.schemas import SelfCheckResult
from app.llm.client import LLMClient
from app.schemas import IndicatorType


@dataclass
class ScoreResult:
    scorer_name: str
    value: float  # 0.0-1.0
    detail: str


class EnumExactMatchScorer:
    name = "enum_exact_match"

    def score(self, expected, actual) -> ScoreResult:
        match = expected == actual
        return ScoreResult(self.name, 1.0 if match else 0.0, f"expected={expected!r} actual={actual!r}")


@dataclass
class IndicatorSetExpected:
    indicators: list[tuple[IndicatorType, str]]


class IndicatorSetScorer:
    name = "indicator_set"

    def score(self, expected: IndicatorSetExpected, actual: list[tuple[IndicatorType, str]]) -> ScoreResult:
        expected_set = set(expected.indicators)
        actual_set = set(actual)
        if not expected_set and not actual_set:
            return ScoreResult(self.name, 1.0, "no indicators expected or found")
        true_positives = expected_set & actual_set
        precision = len(true_positives) / len(actual_set) if actual_set else 1.0
        recall = len(true_positives) / len(expected_set) if expected_set else 1.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
        missing = expected_set - actual_set
        extra = actual_set - expected_set
        return ScoreResult(self.name, f1, f"precision={precision:.2f} recall={recall:.2f} missing={missing} extra={extra}")


class SelfCheckAuditScorer:
    name = "self_check_audit"

    def score(self, wrong_claim_index: int, result: SelfCheckResult) -> ScoreResult:
        audits = result.audits
        if wrong_claim_index >= len(audits):
            return ScoreResult(
                self.name, 0.0,
                f"self-check returned {len(audits)} audit(s), expected at least {wrong_claim_index + 1}",
            )
        caught_injected_error = not audits[wrong_claim_index].supported
        other_audits = [a for i, a in enumerate(audits) if i != wrong_claim_index]
        false_positives = sum(1 for a in other_audits if not a.supported)
        false_positive_rate = false_positives / len(other_audits) if other_audits else 0.0
        value = (1.0 if caught_injected_error else 0.0) * (1.0 - false_positive_rate)
        return ScoreResult(
            self.name, value,
            f"caught_injected_error={caught_injected_error} false_positive_rate={false_positive_rate:.2f}",
        )


@dataclass
class ProxyCheckExpected:
    key_facts: list[str]


def _keywords(text: str) -> set[str]:
    return {w.strip(".,:;()'\"").lower() for w in text.split() if len(w) > 3}


class DeterministicProxyScorer:
    name = "deterministic_proxy"

    def score(self, expected: ProxyCheckExpected, actual_text: str) -> ScoreResult:
        if not expected.key_facts:
            return ScoreResult(self.name, 1.0, "no key facts to check")
        actual_keywords = _keywords(actual_text)
        covered = [fact for fact in expected.key_facts if _keywords(fact) <= actual_keywords]
        coverage = len(covered) / len(expected.key_facts)
        return ScoreResult(self.name, coverage, f"covered {len(covered)}/{len(expected.key_facts)} key fact(s): {covered}")


class JudgeVerdict(BaseModel):
    groundedness: int  # 1-5
    coverage: int  # 1-5
    contradiction: bool


class LLMJudgeScorer:
    name = "llm_judge"

    def __init__(self, judge_client: LLMClient) -> None:
        self._judge_client = judge_client

    def score(self, expected: ProxyCheckExpected, actual_text: str) -> ScoreResult:
        facts = "\n".join(f"- {fact}" for fact in expected.key_facts) or "(none)"
        prompt = (
            "You are grading a security analyst's written text against known facts about an alert.\n\n"
            f"Known facts:\n{facts}\n\n"
            f"Text to grade:\n{actual_text}\n\n"
            "Score groundedness (1-5: does it avoid inventing anything not in the known facts), "
            "coverage (1-5: does it mention the facts that matter), "
            "and whether it contradicts any known fact."
        )
        verdict = self._judge_client.generate_structured(prompt, JudgeVerdict)
        base = (verdict.groundedness + verdict.coverage) / 10.0
        value = 0.0 if verdict.contradiction else base
        return ScoreResult(
            self.name, value,
            f"groundedness={verdict.groundedness} coverage={verdict.coverage} contradiction={verdict.contradiction}",
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/benchmark/test_scorers.py -v`
Expected: PASS (11 tests)

- [ ] **Step 5: Commit**

```bash
git add scripts/benchmark/scorers.py tests/benchmark/test_scorers.py
git commit -m "feat: add pluggable scorers for the model benchmark harness"
```

---

### Task 3: Structured-output compatibility gate

**Files:**
- Create: `scripts/benchmark/gate.py`
- Test: `tests/benchmark/test_gate.py`

**Interfaces:**
- Consumes: `app.llm.client.LLMClient` (existing Protocol), `app.llm.errors.LLMClientError` (existing).
- Produces: `is_structured_output_compatible(client: LLMClient, attempts: int = 3) -> bool`. Task 4/6 call this once per model before running any golden-dataset calls.

- [ ] **Step 1: Write the failing tests**

```python
# tests/benchmark/test_gate.py
from app.llm.errors import LLMClientError
from scripts.benchmark.gate import is_structured_output_compatible


class _FakeClient:
    def __init__(self, available=True, fails_on=None):
        self._available = available
        self._fails_on = fails_on or set()  # set of schema names to fail on
        self.calls = 0

    def model_available(self):
        return self._available

    def health_check(self):
        return True

    def generate_structured(self, prompt, schema):
        self.calls += 1
        if schema.__name__ in self._fails_on:
            raise LLMClientError("validation_failed", "boom")
        return schema.model_construct()


def test_incompatible_when_model_unavailable():
    assert is_structured_output_compatible(_FakeClient(available=False)) is False


def test_compatible_when_every_attempt_succeeds():
    assert is_structured_output_compatible(_FakeClient(), attempts=2) is True


def test_incompatible_when_trivial_schema_fails():
    client = _FakeClient(fails_on={"_TrivialSchema"})
    assert is_structured_output_compatible(client, attempts=2) is False


def test_incompatible_when_nested_schema_fails():
    client = _FakeClient(fails_on={"SelfCheckResult"})
    assert is_structured_output_compatible(client, attempts=2) is False


def test_stops_after_first_failure_without_exhausting_all_attempts():
    client = _FakeClient(fails_on={"_TrivialSchema"})
    is_structured_output_compatible(client, attempts=5)
    assert client.calls == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/benchmark/test_gate.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'scripts.benchmark.gate'`

- [ ] **Step 3: Write the implementation**

```python
# scripts/benchmark/gate.py
from __future__ import annotations

from pydantic import BaseModel

from app.agent.schemas import SelfCheckResult
from app.llm.client import LLMClient
from app.llm.errors import LLMClientError


class _TrivialSchema(BaseModel):
    answer: str


_TRIVIAL_PROMPT = "Respond with a JSON object containing one field, 'answer', set to the string 'ok'."
_NESTED_PROMPT = (
    "Respond with a JSON object with one field 'audits', a list of exactly two objects, each with "
    "'claim' (string), 'supported' (bool), and 'correction' (string or null). Set claim to "
    "'test claim one' and 'test claim two', both supported=true, correction=null."
)


def is_structured_output_compatible(client: LLMClient, attempts: int = 3) -> bool:
    if not client.model_available():
        return False
    for schema, prompt in ((_TrivialSchema, _TRIVIAL_PROMPT), (SelfCheckResult, _NESTED_PROMPT)):
        for _ in range(attempts):
            try:
                client.generate_structured(prompt, schema)
            except LLMClientError:
                return False
    return True
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/benchmark/test_gate.py -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add scripts/benchmark/gate.py tests/benchmark/test_gate.py
git commit -m "feat: add structured-output compatibility gate for the model benchmark harness"
```

---

### Task 4: Isolated per-step harness core

**Files:**
- Create: `scripts/benchmark/harness.py`
- Test: `tests/benchmark/test_harness.py`

**Interfaces:**
- Consumes: `app.agent.state_graph.AgenticAnalyst` (existing, unmodified — this task calls its private `_extract_indicators_via_llm`, `_classify_correlation`, `_run_open_value_search`, `_assess_risk`, `_draft_canonical`, `_draft_experimental`, `_run_self_check` methods directly), `scripts.benchmark.fixtures.load_alert/load_correlation/load_enrichment` (Task 1).
- Produces: `StepCallResult(model: str, slug: str, step: str, run: int, output: Any | None, error: str | None, latency_seconds: float)`, `build_isolated_analyst(llm_client) -> AgenticAnalyst`, one `run_step_<name>(analyst, ...) -> StepCallResult` function per LLM call site, `write_raw_result(result: StepCallResult, base_dir: Path) -> Path`. Task 6 (CLI) calls `run_step_*` in a loop over `(model, alert, run)`.

**Critical implementation detail** (verified by reading `app/agent/state_graph.py` directly — do not assume a uniform error-signaling convention across these 7 methods, they are not consistent):

| Method | Failure signal |
|---|---|
| `_extract_indicators_via_llm(alert)` | returns `(validated, candidate_count, validated_count, error)` — `error` is `None` on success, else the `LLMClientError.kind` string. Use this directly. |
| `_classify_correlation(alert, results, evidence_count)` | never raises; appends to `analyst._degraded_reasons` on failure and returns a fallback `CorrelationDecision`. Reset `analyst._degraded_reasons = []` before calling, check it's non-empty after. |
| `_run_open_value_search(alert, results)` | never raises; returns `""` on failure, always a non-empty string on success. Use `output == ""` as the failure signal. |
| `_assess_risk(alert, pattern_type, evidence_count, enrichment_results)` | never raises; appends to `analyst._degraded_reasons` on failure. Same reset-and-check pattern as `_classify_correlation`. |
| `_draft_canonical(alert, pattern_type, evidence_count, enrichment_results, risk_assessment, fallback_summary)` | never raises; appends to `analyst._degraded_reasons` on failure. Same reset-and-check pattern. |
| `_draft_experimental(alert, pattern_type, evidence_count, enrichment_results, risk_assessment)` | never raises; returns `None` on failure, a real `DraftReportExperimental` on success. Use `output is None`. |
| `_run_self_check(draft, pattern_type, evidence_count, enrichment_results, risk_assessment)` | never raises; returns `(None, failure_kind)` on failure, `(SelfCheckResult, None)` on success. Use the tuple directly. |

- [ ] **Step 1: Write the failing tests**

```python
# tests/benchmark/test_harness.py
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from app.agent.schemas import (
    CorrelationDecision, DraftReportCanonical, DraftReportExperimental, ExtractedIndicators,
    IndicatorCandidate, OpenValueSearchProposal, PatternType, RecommendedAction, SearchTemplate,
    SelfCheckResult, ClaimAudit, TriageVerdict,
)
from app.llm.errors import LLMClientError
from app.schemas import AgentRef, Alert, Confidence, RiskAssessment, Severity
from scripts.benchmark.harness import build_isolated_analyst, run_step_correlate, run_step_extract_indicators


class _FakeLLMClient:
    def __init__(self, responses=None, error=None, available=True):
        self._responses = responses or {}
        self._error = error
        self._available = available

    def generate_structured(self, prompt, schema):
        if self._error is not None:
            raise self._error
        return self._responses[schema]

    def health_check(self):
        return True

    def model_available(self):
        return self._available


def _make_alert() -> Alert:
    return Alert(
        alert_id=uuid4(), source_alert_id="1.1", source_system="wazuh", rule_id="5710",
        rule_description="test", rule_level=5, timestamp=datetime.now(timezone.utc),
        ingested_at=datetime.now(timezone.utc), agent=AgentRef(id="001", name="host", ip="10.0.0.1"),
        manager_name="wazuh-manager", location="/var/log/auth.log", full_log="Invalid user admin from 1.2.3.4",
        raw_json={},
    )


def test_run_step_extract_indicators_reports_success():
    client = _FakeLLMClient(responses={
        ExtractedIndicators: ExtractedIndicators(candidates=[IndicatorCandidate(type="ip", value="1.2.3.4")])
    })
    analyst = build_isolated_analyst(client)

    result = run_step_extract_indicators(analyst, _make_alert(), model="m", slug="s", run=0)

    assert result.error is None
    assert result.output == [("ip", "1.2.3.4")]
    assert result.step == "extract_indicators"


def test_run_step_extract_indicators_reports_llm_failure():
    client = _FakeLLMClient(error=LLMClientError("timeout", "boom"))
    analyst = build_isolated_analyst(client)

    result = run_step_extract_indicators(analyst, _make_alert(), model="m", slug="s", run=0)

    assert result.error == "timeout"
    assert result.output is None


def test_run_step_correlate_reports_success():
    decision = CorrelationDecision(pattern_type=PatternType.BRUTE_FORCE, follow_up_query=SearchTemplate.NONE_NEEDED)
    client = _FakeLLMClient(responses={CorrelationDecision: decision})
    analyst = build_isolated_analyst(client)

    result = run_step_correlate(analyst, _make_alert(), correlation={}, evidence_count=14, model="m", slug="s", run=0)

    assert result.error is None
    assert result.output == decision


def test_run_step_correlate_reports_llm_failure_via_degraded_reasons():
    client = _FakeLLMClient(error=LLMClientError("timeout", "boom"))
    analyst = build_isolated_analyst(client)

    result = run_step_correlate(analyst, _make_alert(), correlation={}, evidence_count=0, model="m", slug="s", run=0)

    assert result.error is not None
    assert "timeout" in result.error


def test_run_step_correlate_resets_degraded_reasons_between_calls():
    client = _FakeLLMClient(error=LLMClientError("timeout", "boom"))
    analyst = build_isolated_analyst(client)
    run_step_correlate(analyst, _make_alert(), correlation={}, evidence_count=0, model="m", slug="s", run=0)

    client_ok = _FakeLLMClient(responses={
        CorrelationDecision: CorrelationDecision(pattern_type=PatternType.NONE, follow_up_query=SearchTemplate.NONE_NEEDED)
    })
    analyst._llm_client = client_ok
    result = run_step_correlate(analyst, _make_alert(), correlation={}, evidence_count=0, model="m", slug="s", run=1)

    assert result.error is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/benchmark/test_harness.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'scripts.benchmark.harness'`

- [ ] **Step 3: Write the implementation**

```python
# scripts/benchmark/harness.py
from __future__ import annotations

import json
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from app.agent.schemas import DraftReportCanonical, PatternType
from app.agent.state_graph import AgenticAnalyst
from app.enrichment.registry import EnrichmentRegistry
from app.integration.models import SearchResult
from app.llm.client import LLMClient
from app.schemas import Alert, EnrichmentResult, RiskAssessment


class _NoopSIEMConnector:
    def health_check(self) -> bool:
        return True

    def pull_alerts(self, since, until=None, limit=500):
        return []

    def search(self, query):
        return SearchResult(alerts=[], total_count=0)

    def get_agent_context(self, agent_id):
        return None

    def get_rule_metadata(self, rule_id):
        return None


class _NoopAlertStore:
    def save_raw_alert(self, alert):
        return str(alert.alert_id)

    def get_alert(self, alert_id):
        raise NotImplementedError

    def list_alerts(self, status=None, since=None, limit=100):
        return []

    def update_alert_status(self, alert_id, status):
        pass

    def save_report(self, report):
        return str(report.report_id)

    def get_report(self, report_id):
        raise NotImplementedError

    def get_report_for_alert(self, alert_id):
        return None

    def list_reports(self, since=None, min_severity=None):
        return []


def build_isolated_analyst(llm_client: LLMClient) -> AgenticAnalyst:
    return AgenticAnalyst(
        siem=_NoopSIEMConnector(),
        alert_store=_NoopAlertStore(),
        enrichment_registry=EnrichmentRegistry(),
        llm_client=llm_client,
    )


@dataclass
class StepCallResult:
    model: str
    slug: str
    step: str
    run: int
    output: Any | None
    error: str | None
    latency_seconds: float


def _timed(fn):
    start = time.monotonic()
    value = fn()
    return value, time.monotonic() - start


def run_step_extract_indicators(analyst: AgenticAnalyst, alert: Alert, model: str, slug: str, run: int) -> StepCallResult:
    (validated, _candidates, _validated_count, error), latency = _timed(
        lambda: analyst._extract_indicators_via_llm(alert)
    )
    output = None if error else [(i.indicator_type.value, i.value) for i in validated]
    return StepCallResult(model, slug, "extract_indicators", run, output, error, latency)


def run_step_correlate(analyst: AgenticAnalyst, alert: Alert, correlation, evidence_count: int, model: str, slug: str, run: int) -> StepCallResult:
    analyst._degraded_reasons = []
    decision, latency = _timed(lambda: analyst._classify_correlation(alert, correlation, evidence_count))
    error = analyst._degraded_reasons[-1] if analyst._degraded_reasons else None
    return StepCallResult(model, slug, "correlate", run, None if error else decision, error, latency)


def run_step_open_value_search(analyst: AgenticAnalyst, alert: Alert, correlation, model: str, slug: str, run: int) -> StepCallResult:
    output, latency = _timed(lambda: analyst._run_open_value_search(alert, correlation))
    error = None if output else "generation_failed"
    return StepCallResult(model, slug, "open_value_search", run, None if error else output, error, latency)


def run_step_risk_assessment(analyst: AgenticAnalyst, alert: Alert, pattern_type: PatternType, evidence_count: int, enrichment_results: list[EnrichmentResult], model: str, slug: str, run: int) -> StepCallResult:
    analyst._degraded_reasons = []
    assessment, latency = _timed(lambda: analyst._assess_risk(alert, pattern_type, evidence_count, enrichment_results))
    error = analyst._degraded_reasons[-1] if analyst._degraded_reasons else None
    return StepCallResult(model, slug, "risk_assessment", run, None if error else assessment, error, latency)


def run_step_draft_canonical(analyst: AgenticAnalyst, alert: Alert, pattern_type: PatternType, evidence_count: int, enrichment_results: list[EnrichmentResult], risk_assessment: RiskAssessment, fallback_summary: str, model: str, slug: str, run: int) -> StepCallResult:
    analyst._degraded_reasons = []
    draft, latency = _timed(
        lambda: analyst._draft_canonical(alert, pattern_type, evidence_count, enrichment_results, risk_assessment, fallback_summary)
    )
    error = analyst._degraded_reasons[-1] if analyst._degraded_reasons else None
    return StepCallResult(model, slug, "draft_canonical", run, None if error else draft, error, latency)


def run_step_draft_experimental(analyst: AgenticAnalyst, alert: Alert, pattern_type: PatternType, evidence_count: int, enrichment_results: list[EnrichmentResult], risk_assessment: RiskAssessment, model: str, slug: str, run: int) -> StepCallResult:
    experimental, latency = _timed(
        lambda: analyst._draft_experimental(alert, pattern_type, evidence_count, enrichment_results, risk_assessment)
    )
    error = None if experimental is not None else "generation_failed"
    return StepCallResult(model, slug, "draft_experimental", run, experimental, error, latency)


def run_step_self_check(analyst: AgenticAnalyst, draft: DraftReportCanonical, pattern_type: PatternType, evidence_count: int, enrichment_results: list[EnrichmentResult], risk_assessment: RiskAssessment, model: str, slug: str, run: int) -> StepCallResult:
    (result, failure_kind), latency = _timed(
        lambda: analyst._run_self_check(draft, pattern_type, evidence_count, enrichment_results, risk_assessment)
    )
    return StepCallResult(model, slug, "self_check", run, result, failure_kind, latency)


def _to_jsonable(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, list):
        return [_to_jsonable(v) for v in value]
    if isinstance(value, tuple):
        return [_to_jsonable(v) for v in value]
    return value


def write_raw_result(result: StepCallResult, base_dir: Path) -> Path:
    out_dir = base_dir / "raw" / result.model / result.slug / result.step
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{result.run}.json"
    payload = asdict(result)
    payload["output"] = _to_jsonable(result.output)
    path.write_text(json.dumps(payload, indent=2))
    return path
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/benchmark/test_harness.py -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add scripts/benchmark/harness.py tests/benchmark/test_harness.py
git commit -m "feat: add isolated per-step harness core for the model benchmark"
```

---

### Task 5: End-to-end composite mode + raw-result round-trip test

**Files:**
- Modify: `scripts/benchmark/harness.py`
- Modify: `tests/benchmark/test_harness.py`

**Interfaces:**
- Consumes: `app.agent.schemas.SearchTemplate`, `app.integration.models.SearchResult` (existing), Task 1's `load_correlation`/`load_enrichment` return shapes.
- Produces: `build_fixture_backed_analyst(llm_client, correlation, enrichment_results) -> AgenticAnalyst`. Task 6 (CLI) calls this once per model for the composite pass, then calls `analyst.investigate(alert)` directly (unmodified production method).

- [ ] **Step 1: Write the failing tests**

```python
# append to tests/benchmark/test_harness.py
from app.agent.schemas import SearchTemplate
from app.integration.models import SearchResult
from app.schemas import EnrichmentResult, EnrichmentVerdict, IndicatorType
from datetime import datetime, timezone
from scripts.benchmark.harness import build_fixture_backed_analyst, write_raw_result


def test_fixture_backed_analyst_returns_frozen_correlation_results():
    correlation = {SearchTemplate.SAME_RULE_ID_HOST: SearchResult(alerts=[], total_count=7)}
    analyst = build_fixture_backed_analyst(_FakeLLMClient(available=False), correlation, [])

    from app.integration.models import SearchClause, SearchQuery
    result = analyst._siem.search(SearchQuery(clauses=[SearchClause(field="rule.id", operator="eq", value="5710")]))

    assert result.total_count == 7


def test_fixture_backed_analyst_falls_back_to_empty_for_unknown_field():
    analyst = build_fixture_backed_analyst(_FakeLLMClient(available=False), {}, [])

    from app.integration.models import SearchClause, SearchQuery
    result = analyst._siem.search(SearchQuery(clauses=[SearchClause(field="data.srcip", operator="eq", value="1.2.3.4")]))

    assert result.total_count == 0


def test_fixture_backed_analyst_enriches_known_indicator_from_frozen_data():
    queried_at = datetime.now(timezone.utc)
    frozen = EnrichmentResult(
        indicator_type=IndicatorType.IP, indicator_value="1.2.3.4", provider_id="abuseipdb",
        queried_at=queried_at, verdict=EnrichmentVerdict.MALICIOUS, score=90.0, cache_expires_at=queried_at,
    )
    analyst = build_fixture_backed_analyst(_FakeLLMClient(available=False), {}, [frozen])

    from app.enrichment.indicators import IPIndicator
    result = analyst._enrichment_registry.enrich(IPIndicator(value="1.2.3.4"))

    assert result.verdict == EnrichmentVerdict.MALICIOUS


def test_fixture_backed_analyst_returns_unknown_for_indicator_not_in_fixture():
    analyst = build_fixture_backed_analyst(_FakeLLMClient(available=False), {}, [])

    from app.enrichment.indicators import IPIndicator
    result = analyst._enrichment_registry.enrich(IPIndicator(value="9.9.9.9"))

    assert result.verdict == EnrichmentVerdict.UNKNOWN
    assert result.error == "not_in_golden_fixture"


def test_write_raw_result_round_trips_to_disk(tmp_path):
    from scripts.benchmark.harness import StepCallResult
    result = StepCallResult(model="m", slug="s", step="correlate", run=0, output={"pattern_type": "brute_force"}, error=None, latency_seconds=1.5)

    path = write_raw_result(result, tmp_path)

    import json
    payload = json.loads(path.read_text())
    assert payload["model"] == "m"
    assert payload["latency_seconds"] == 1.5
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/benchmark/test_harness.py -v`
Expected: FAIL with `ImportError: cannot import name 'build_fixture_backed_analyst'`

- [ ] **Step 3: Write the implementation**

Add to `scripts/benchmark/harness.py`:

```python
from datetime import datetime, timezone

from app.agent.schemas import SearchTemplate
from app.integration.models import SearchQuery

_TEMPLATE_BY_FIELD = {
    "data.srcip": SearchTemplate.SAME_SRC_IP_24H,
    "rule.id": SearchTemplate.SAME_RULE_ID_HOST,
    "data.dstip": SearchTemplate.SAME_DST_HOST,
}


class _FixtureSIEMConnector(_NoopSIEMConnector):
    def __init__(self, correlation: dict[SearchTemplate, SearchResult]) -> None:
        self._correlation = correlation

    def search(self, query: SearchQuery) -> SearchResult:
        field = query.clauses[0].field
        template = _TEMPLATE_BY_FIELD.get(field)
        return self._correlation.get(template, SearchResult(alerts=[], total_count=0))


class _FixtureEnrichmentRegistry:
    def __init__(self, enrichment_results: list[EnrichmentResult]) -> None:
        self._by_value = {r.indicator_value: r for r in enrichment_results}

    def enrich(self, indicator):
        if indicator.value in self._by_value:
            return self._by_value[indicator.value]
        queried_at = datetime.now(timezone.utc)
        from app.schemas import EnrichmentVerdict
        return EnrichmentResult(
            indicator_type=indicator.indicator_type, indicator_value=indicator.value,
            provider_id="fixture", queried_at=queried_at, verdict=EnrichmentVerdict.UNKNOWN,
            score=0.0, cache_expires_at=queried_at, error="not_in_golden_fixture",
        )


def build_fixture_backed_analyst(
    llm_client: LLMClient, correlation: dict[SearchTemplate, SearchResult], enrichment_results: list[EnrichmentResult]
) -> AgenticAnalyst:
    return AgenticAnalyst(
        siem=_FixtureSIEMConnector(correlation),
        alert_store=_NoopAlertStore(),
        enrichment_registry=_FixtureEnrichmentRegistry(enrichment_results),
        llm_client=llm_client,
    )
```

Move the `EnrichmentResult`/`EnrichmentVerdict` import used above to the top-level import block alongside the existing `from app.schemas import Alert, EnrichmentResult, RiskAssessment` line (add `EnrichmentVerdict`) instead of importing inline — inline import shown here only to keep this diff snippet self-contained.

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/benchmark/test_harness.py -v`
Expected: PASS (10 tests total)

- [ ] **Step 5: Commit**

```bash
git add scripts/benchmark/harness.py tests/benchmark/test_harness.py
git commit -m "feat: add fixture-backed end-to-end composite mode to the benchmark harness"
```

---

### Task 6: Report writer + CLI entrypoint

**Files:**
- Create: `scripts/benchmark/report.py`
- Create: `scripts/benchmark_models.py`
- Test: `tests/benchmark/test_report.py`

**Interfaces:**
- Consumes: `scripts.benchmark.fixtures.{validate_all_fixtures, list_golden_slugs, load_alert, load_correlation, load_enrichment, load_expected}` (Task 1), `scripts.benchmark.scorers.*` (Task 2), `scripts.benchmark.gate.is_structured_output_compatible` (Task 3), `scripts.benchmark.harness.*` (Tasks 4-5), `app.wiring.build_llm_client`, `app.config.Settings`.
- Produces: `write_scores_jsonl(rows: list[dict], path: Path)`, `write_summary_md(rows: list[dict], path: Path) -> str`. `scripts/benchmark_models.py` is the executable entrypoint — no other module imports it.

- [ ] **Step 1: Write the failing tests**

```python
# tests/benchmark/test_report.py
import json

from scripts.benchmark.report import write_scores_jsonl, write_summary_md


def _rows():
    return [
        {"model": "gemma4:12b", "slug": "auth", "step": "correlate", "run": 0, "scorer": "enum_exact_match", "value": 1.0, "detail": "ok", "incompatible": False},
        {"model": "gemma4:12b", "slug": "auth", "step": "correlate", "run": 1, "scorer": "enum_exact_match", "value": 0.0, "detail": "miss", "incompatible": False},
        {"model": "qwen3.5:9b", "slug": "auth", "step": "correlate", "run": 0, "scorer": "enum_exact_match", "value": None, "detail": "incompatible", "incompatible": True},
    ]


def test_write_scores_jsonl_writes_one_row_per_line(tmp_path):
    path = tmp_path / "scores.jsonl"
    write_scores_jsonl(_rows(), path)

    lines = path.read_text().strip().splitlines()
    assert len(lines) == 3
    assert json.loads(lines[0])["model"] == "gemma4:12b"


def test_write_summary_md_includes_accuracy_per_model_per_step(tmp_path):
    path = tmp_path / "summary.md"
    content = write_summary_md(_rows(), path)

    assert "gemma4:12b" in content
    assert "correlate" in content
    assert "0.50" in content  # mean of 1.0 and 0.0


def test_write_summary_md_marks_incompatible_models_without_a_numeric_score():
    path = tmp_path = None
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        from pathlib import Path
        content = write_summary_md(_rows(), Path(d) / "summary.md")
    assert "INCOMPATIBLE" in content
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/benchmark/test_report.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'scripts.benchmark.report'`

- [ ] **Step 3: Write the implementation**

```python
# scripts/benchmark/report.py
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path


def write_scores_jsonl(rows: list[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


def write_summary_md(rows: list[dict], path: Path) -> str:
    by_model_step: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for row in rows:
        by_model_step[(row["model"], row["step"])].append(row)

    lines = ["# Benchmark Summary", ""]
    steps = sorted({step for _, step in by_model_step})
    for step in steps:
        lines.append(f"## {step}")
        lines.append("")
        lines.append("| Model | Accuracy | Runs |")
        lines.append("|---|---|---|")
        for (model, s), group in sorted(by_model_step.items()):
            if s != step:
                continue
            if all(r["incompatible"] for r in group):
                lines.append(f"| {model} | INCOMPATIBLE | {len(group)} |")
                continue
            scored = [r["value"] for r in group if r["value"] is not None]
            mean_value = sum(scored) / len(scored) if scored else 0.0
            lines.append(f"| {model} | {mean_value:.2f} | {len(group)} |")
        lines.append("")

    content = "\n".join(lines)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return content
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/benchmark/test_report.py -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Write the CLI entrypoint** (no dedicated unit test — this is a thin orchestration script exercised by the manual smoke test in Step 6; every function it calls is already unit-tested in Tasks 1-6)

```python
# scripts/benchmark_models.py
"""Standalone benchmark harness for comparing local LLM models on the Agentic Analyst pipeline.

Usage:
    python scripts/benchmark_models.py --models gemma4:12b,qwen3.5:9b --runs 3 --scoring enum
"""
from __future__ import annotations

import argparse
from pathlib import Path
from uuid import uuid4

from app.agent.schemas import PatternType
from app.config import Settings
from app.llm.ollama_client import OllamaClient
from scripts.benchmark.fixtures import (
    list_golden_slugs,
    load_alert,
    load_correlation,
    load_enrichment,
    load_expected,
    validate_all_fixtures,
)
from scripts.benchmark.gate import is_structured_output_compatible
from scripts.benchmark.harness import (
    run_step_correlate,
    run_step_draft_canonical,
    run_step_draft_experimental,
    run_step_extract_indicators,
    run_step_open_value_search,
    run_step_risk_assessment,
    run_step_self_check,
    build_isolated_analyst,
    write_raw_result,
)
from scripts.benchmark.report import write_scores_jsonl, write_summary_md
from scripts.benchmark.scorers import (
    DeterministicProxyScorer,
    EnumExactMatchScorer,
    IndicatorSetExpected,
    IndicatorSetScorer,
    LLMJudgeScorer,
    ProxyCheckExpected,
    SelfCheckAuditScorer,
)

DEFAULT_MODELS = ["gemma4:12b", "qwen3.5:9b", "qwen3.6:27b", "gpt-oss:20b"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--models", default=",".join(DEFAULT_MODELS))
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--scoring", default="enum")
    parser.add_argument("--judge-model", default=None)
    parser.add_argument("--alerts", default=None, help="comma-separated slugs; default: all golden alerts")
    parser.add_argument("--golden-dir", default="benchmarks/golden")
    parser.add_argument("--output-dir", default=None, help="default: data/benchmarks/<run-id>")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    golden_dir = Path(args.golden_dir)
    validate_all_fixtures(golden_dir)

    models = args.models.split(",")
    slugs = args.alerts.split(",") if args.alerts else list_golden_slugs(golden_dir)
    run_id = uuid4().hex[:8]
    output_dir = Path(args.output_dir) if args.output_dir else Path("data/benchmarks") / run_id

    settings = Settings()
    enum_scorer = EnumExactMatchScorer()
    indicator_scorer = IndicatorSetScorer()
    self_check_scorer = SelfCheckAuditScorer()

    selected_scoring = set(args.scoring.split(","))
    proxy_scorer = DeterministicProxyScorer() if "proxy" in selected_scoring else None
    judge_scorer = None
    if "judge" in selected_scoring:
        if not args.judge_model:
            raise SystemExit("--judge-model is required when 'judge' is in --scoring")
        judge_client = OllamaClient(base_url=settings.llm_base_url, model=args.judge_model, timeout_seconds=settings.llm_timeout_seconds)
        judge_scorer = LLMJudgeScorer(judge_client)

    rows: list[dict] = []
    for model in models:
        client = OllamaClient(base_url=settings.llm_base_url, model=model, timeout_seconds=settings.llm_timeout_seconds)
        compatible = is_structured_output_compatible(client)
        if not compatible:
            for slug in slugs:
                rows.append({
                    "model": model, "slug": slug, "step": "all", "run": 0,
                    "scorer": "gate", "value": None, "detail": "failed structured-output compatibility gate",
                    "incompatible": True,
                })
            continue

        for slug in slugs:
            alert = load_alert(slug, golden_dir)
            correlation = load_correlation(slug, golden_dir)
            enrichment = load_enrichment(slug, golden_dir)
            expected = load_expected(slug, golden_dir)

            for run in range(args.runs):
                analyst = build_isolated_analyst(client)

                extract_result = run_step_extract_indicators(analyst, alert, model, slug, run)
                write_raw_result(extract_result, output_dir)
                if extract_result.error is None:
                    expected_indicators = IndicatorSetExpected(
                        indicators=[(i.type, i.value) for i in expected.expected_indicators]
                    )
                    score = indicator_scorer.score(expected_indicators, extract_result.output)
                    rows.append({"model": model, "slug": slug, "step": "extract_indicators", "run": run,
                                 "scorer": score.scorer_name, "value": score.value, "detail": score.detail, "incompatible": False})

                evidence_count = sum(r.total_count for r in correlation.values())
                correlate_result = run_step_correlate(analyst, alert, correlation, evidence_count, model, slug, run)
                write_raw_result(correlate_result, output_dir)
                if correlate_result.error is None:
                    score = enum_scorer.score(expected.expected_pattern_type, correlate_result.output.pattern_type)
                    rows.append({"model": model, "slug": slug, "step": "correlate", "run": run,
                                 "scorer": score.scorer_name, "value": score.value, "detail": score.detail, "incompatible": False})

                # Production only runs the open-value search when the closed-menu classification comes back
                # NONE/OTHER (state_graph.py's _step_correlate) — mirror that trigger using the golden
                # expected_pattern_type, since isolated mode never has "this model's own" correlate output
                # to gate on.
                if expected.expected_pattern_type in (PatternType.NONE, PatternType.OTHER):
                    open_value_result = run_step_open_value_search(analyst, alert, correlation, model, slug, run)
                    write_raw_result(open_value_result, output_dir)
                    if open_value_result.error is None:
                        # Grounding check, not a ground-truth match: does the proposed search value's own
                        # keywords actually appear in the alert's raw log, or did the model invent it?
                        grounding = DeterministicProxyScorer().score(
                            ProxyCheckExpected(key_facts=[open_value_result.output]), alert.full_log
                        )
                        rows.append({"model": model, "slug": slug, "step": "open_value_search", "run": run,
                                     "scorer": "grounded_in_full_log", "value": grounding.value,
                                     "detail": grounding.detail, "incompatible": False})

                risk_result = run_step_risk_assessment(analyst, alert, expected.expected_pattern_type, evidence_count, enrichment, model, slug, run)
                write_raw_result(risk_result, output_dir)
                if risk_result.error is None:
                    severity_score = enum_scorer.score(expected.expected_severity, risk_result.output.severity)
                    confidence_score = enum_scorer.score(expected.expected_confidence, risk_result.output.confidence)
                    rows.append({"model": model, "slug": slug, "step": "risk_assessment", "run": run,
                                 "scorer": "severity_" + severity_score.scorer_name, "value": severity_score.value,
                                 "detail": severity_score.detail, "incompatible": False})
                    rows.append({"model": model, "slug": slug, "step": "risk_assessment", "run": run,
                                 "scorer": "confidence_" + confidence_score.scorer_name, "value": confidence_score.value,
                                 "detail": confidence_score.detail, "incompatible": False})

                    fallback_summary = f"Rule {alert.rule_id} ({alert.rule_description}), level {alert.rule_level}."
                    draft_result = run_step_draft_canonical(
                        analyst, alert, expected.expected_pattern_type, evidence_count, enrichment,
                        risk_result.output, fallback_summary, model, slug, run,
                    )
                    write_raw_result(draft_result, output_dir)
                    if draft_result.error is None:
                        proxy_expected = ProxyCheckExpected(key_facts=expected.key_facts)
                        for field_name in ("alert_summary", "rationale"):
                            text = getattr(draft_result.output, field_name)
                            if proxy_scorer is not None:
                                score = proxy_scorer.score(proxy_expected, text)
                                rows.append({"model": model, "slug": slug, "step": "draft_canonical", "run": run,
                                             "scorer": f"{field_name}_{score.scorer_name}", "value": score.value,
                                             "detail": score.detail, "incompatible": False})
                            if judge_scorer is not None:
                                score = judge_scorer.score(proxy_expected, text)
                                rows.append({"model": model, "slug": slug, "step": "draft_canonical", "run": run,
                                             "scorer": f"{field_name}_{score.scorer_name}", "value": score.value,
                                             "detail": score.detail, "incompatible": False})

                    experimental_result = run_step_draft_experimental(
                        analyst, alert, expected.expected_pattern_type, evidence_count, enrichment,
                        risk_result.output, model, slug, run,
                    )
                    write_raw_result(experimental_result, output_dir)
                    if experimental_result.error is None:
                        score = enum_scorer.score(expected.expected_triage_verdict, experimental_result.output.triage_verdict)
                        rows.append({"model": model, "slug": slug, "step": "draft_experimental", "run": run,
                                     "scorer": score.scorer_name, "value": score.value, "detail": score.detail, "incompatible": False})

                    # Self-Check needs a real RiskAssessment (see Task 4's signature table) — only run it
                    # when Risk Assessment itself succeeded, same guard as draft_canonical/draft_experimental above.
                    poisoned = expected.poisoned_claim
                    self_check_result = run_step_self_check(
                        analyst, poisoned.draft, expected.expected_pattern_type, evidence_count, enrichment,
                        risk_result.output, model, slug, run,
                    )
                    write_raw_result(self_check_result, output_dir)
                    if self_check_result.error is None:
                        score = self_check_scorer.score(poisoned.wrong_claim_index, self_check_result.output)
                        rows.append({"model": model, "slug": slug, "step": "self_check", "run": run,
                                     "scorer": score.scorer_name, "value": score.value, "detail": score.detail, "incompatible": False})

    write_scores_jsonl(rows, output_dir / "scores.jsonl")
    summary = write_summary_md(rows, output_dir / "summary.md")
    print(summary)
    print(f"\nFull results in {output_dir}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 6: Manual smoke test against real Ollama**

This step has no automated test — it validates the CLI's actual wiring, which Tasks 1-6's unit tests (using fakes) cannot cover end-to-end.

Run: `python scripts/benchmark_models.py --models gemma4:12b --runs 1 --alerts <any-one-already-captured-slug>`

Expected: no traceback; `summary.md` is printed; `data/benchmarks/<run-id>/scores.jsonl` and `summary.md` exist and are non-empty. (This step can only run once Task 7 has captured at least one real golden fixture — if Task 7 hasn't landed yet, skip this step now and return to it after Task 7.)

- [ ] **Step 7: Commit**

```bash
git add scripts/benchmark/report.py scripts/benchmark_models.py tests/benchmark/test_report.py
git commit -m "feat: add report writer and CLI entrypoint for the model benchmark harness"
```

---

### Task 7: New golden alert content + live capture + hand-authored ground truth

**Files:**
- Create: `scripts/capture_golden_fixture.py`
- Modify: `wazuh_deployment/single-node/sample-logs/auth-fp.log` (append)
- Modify: `wazuh_deployment/single-node/sample-logs/mimecast_sample.log` (append)
- Create: `benchmarks/golden/<slug>/{alert.json,correlation.json,enrichment.json,expected.json}` for 10 slugs (see mapping below)

**Interfaces:**
- Consumes: `app.wiring.build_siem_connector`, `app.wiring.build_enrichment_registry` (existing), `app.agent.correlation_queries.build_canonical_queries` (existing), `app.agent.indicator_extraction.extract_and_validate` (existing), `scripts.benchmark.fixtures.validate_all_fixtures` (Task 1, used as the final acceptance check for this task).
- Produces: 10 populated directories under `benchmarks/golden/`, validated by `validate_all_fixtures("benchmarks/golden")` raising nothing.

**Dataset reconciliation (discovered while reading the actual sample-log content during planning — see rationale below):**

| Slug | Source | Notes |
|---|---|---|
| `auth` | `auth.log` lines 1-17 (Jul 29-31 ordinary logins) | existing content, unmodified |
| `auth-fp` | `auth-fp.log`, existing lines | existing content, unmodified |
| `ssh-mistyped-fp` | **new** lines appended to `auth-fp.log` | new — satisfies "failed/suspicious login, FP" category |
| `ssh-bruteforce` | `auth.log` lines 18-30 (Jul 31 09:14-09:16 failed-login burst + `useradd svc_backup`) | **this content already exists in the repo** — it was not previously captured as its own golden alert. Satisfies "failed/suspicious login, TP" category with zero new log content needed. |
| `windows-security` | `windows_security.json`, existing | existing content, unmodified |
| `windows-security-fp` | `windows_security_fp.json`, existing | existing content, unmodified |
| `vpn` | `vpn.log`, existing | existing content, unmodified |
| `mimecast-phishing` | `mimecast_sample.log` lines 1-4 (existing) | **this is already the "suspected phishing email, TP" scenario** (rule 106011, malicious `.xlsm` attachment) — satisfies that category with zero new log content needed. |
| `vendor-invoice-fp` | **new** lines appended to `mimecast_sample.log` | new — satisfies "suspected phishing email, FP" category |
| `endpoint` | `endpoint_alerts_sample.json`, existing | existing content, unmodified |

This reduces the design spec's originally-estimated "4 new alerts" to 2 genuinely new log-content additions (`ssh-mistyped-fp`, `vendor-invoice-fp`) plus 2 newly-*captured* (but already-*existing*) alerts (`ssh-bruteforce`, `mimecast-phishing` already covers phishing) — 10 total golden alerts, not 11. This is a direct application of this project's own repeatedly-documented lesson (`PROGRESS.md`): verify a claim about existing content against the actual file before building on top of it, rather than assuming.

- [ ] **Step 1: Append new log content**

Append to `wazuh_deployment/single-node/sample-logs/auth-fp.log` (a legitimate user mistyping their password twice, then succeeding — same source IP throughout, no other users targeted, no privilege escalation):

```
Aug 3 10:02:14 web-prod-01 sshd[11201]: Failed password for mrahman from 203.0.113.30 port 52011 ssh2
Aug 3 10:02:21 web-prod-01 sshd[11201]: Failed password for mrahman from 203.0.113.30 port 52011 ssh2
Aug 3 10:02:29 web-prod-01 sshd[11202]: Accepted password for mrahman from 203.0.113.30 port 52012 ssh2
Aug 3 10:02:29 web-prod-01 sshd[11202]: pam_unix(sshd:session): session opened for user mrahman(uid=1010) by (uid=0)
Aug 3 18:00:00 web-prod-01 sshd[11202]: pam_unix(sshd:session): session closed for user mrahman
```

Append to `wazuh_deployment/single-node/sample-logs/mimecast_sample.log` (a legitimate vendor invoice email — plain PDF, clean scan, sender domain matches a real known vendor, no impersonation/reply-mismatch flags):

```
datetime=2026-08-03T11:20:00Z|aCode=aABC9z8y7x6w|acc=VICTC-1|Route=Inbound|Dir=Internal|Sender=billing@trusted-vendor.com|headerFrom=Trusted Vendor Billing <billing@trusted-vendor.com>|Rcpt=raj.kumar@victimcorp.com|Subject=Your August Invoice #48213|MsgId=<b2c3d4e5-77f1-4b21-9c4d-3a4b5c6d7e8f@trusted-vendor.com>|IP=198.51.100.22|Act=Delivered|SenderDomain=trusted-vendor.com
datetime=2026-08-03T11:20:04Z|aCode=aABC9z8y7x6w|acc=VICTC-1|Sender=billing@trusted-vendor.com|Rcpt=raj.kumar@victimcorp.com|Subject=Your August Invoice #48213|MsgId=<b2c3d4e5-77f1-4b21-9c4d-3a4b5c6d7e8f@trusted-vendor.com>|IP=198.51.100.22|fileName=Invoice_48213|fileExt=.pdf|fileMime=application/pdf|sha256=b4c6f8d1e3a29f0e5b8c7d6a5e4f3d2c1b0a9e8d7c6b5a4f3e2d1c0b9a8f7e6d|AttSize=21044|AttCnt=1|ScanResultInfo=Clean
```

Both files already have a matching `<localfile>` block in `config/wazuh_cluster/wazuh_manager.conf` — **no config changes needed**, since these are appended lines in already-wired files, not new files.

- [ ] **Step 2: Re-seed the running Wazuh stack — REQUIRES EXPLICIT USER CONFIRMATION FIRST**

**Stop here and confirm with the user before running this step.** The Wazuh stack has been running for 25+ hours (confirmed via `docker ps`) and may hold real investigation history in its indexer volume. Re-seeding the updated sample logs requires `docker compose down -v && docker compose up -d` (per `wazuh_deployment/single-node/README.md`'s own documented process — `log-pusher` only pushes lines once at container startup, and edited source files are not picked up by a plain restart). `down -v` **destroys the indexer's data volume** — every previously-pulled/indexed alert in Wazuh disappears (this project's own SQLite `alerts.db`/`data/reports/` are unaffected, since they're a separate store, but anything only ever queried live from the indexer is gone). Ask the user explicitly before running this command; do not run it autonomously.

Once confirmed:
```bash
cd wazuh_deployment/single-node
docker compose down -v
docker compose up -d
# wait ~1 minute for first-boot initialization, then:
docker compose logs log-pusher | tail -5   # confirm it ends with "pushed-all"
```

- [ ] **Step 3: Discover real rule IDs for each slug**

Using the already-implemented CLI (`app/cli.py`, Phase 5):

```bash
agent pull-alerts --since 2026-07-28T00:00:00+00:00 --limit 500
agent list-alerts --limit 200
```

Note down, for each of the 10 slugs above, the real `rule_id` and a distinguishing substring of `rule_description` from the listed output — the sample-log content above determines which lines belong to which slug (e.g. `ssh-bruteforce` is whichever alert(s) fall in the `09:14-09:16` window on the `auth.log`/`auth-fp.log` timestamps, `vendor-invoice-fp` is the alert generated by the new `trusted-vendor.com` lines). Where a single sample-log block generates more than one alert (e.g. multiple Mimecast rules firing off the same lines), pick the alert whose rule most specifically matches the slug's intent (e.g. rule `106011` — "Mimecast sandbox has detected a potentially malicious file" — for `mimecast-phishing`, not the more generic `106001`/`106007` also triggered by the same lines).

- [ ] **Step 4: Write the capture tool**

```python
# scripts/capture_golden_fixture.py
"""One-time tool: capture a real Wazuh alert + its deterministic correlation/enrichment
results into a frozen golden fixture under benchmarks/golden/<slug>/.

Usage:
    python scripts/capture_golden_fixture.py --slug ssh-bruteforce --rule-id 5716 \
        --since 2026-07-31T00:00:00+00:00 --until 2026-08-01T00:00:00+00:00
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path

from app.agent.correlation_queries import build_canonical_queries
from app.agent.indicator_extraction import extract_and_validate
from app.config import get_settings
from app.integration.errors import SIEMConnectorError
from app.schemas import Alert
from app.wiring import build_enrichment_registry, build_siem_connector

GOLDEN_DIR = Path("benchmarks/golden")


def find_alert(siem, since: datetime, until: datetime, rule_id: str, description_contains: str | None) -> Alert:
    candidates = [
        a for a in siem.pull_alerts(since=since, until=until, limit=500)
        if a.rule_id == rule_id
        and (description_contains is None or description_contains.lower() in a.rule_description.lower())
    ]
    if len(candidates) != 1:
        raise SystemExit(
            f"expected exactly 1 matching alert (rule_id={rule_id!r}, description_contains={description_contains!r}), "
            f"found {len(candidates)} in [{since}, {until}]"
        )
    return candidates[0]


def capture(slug: str, alert: Alert, siem, enrichment_registry, golden_dir: Path) -> None:
    out_dir = golden_dir / slug
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "alert.json").write_text(alert.model_dump_json(indent=2))

    queries = build_canonical_queries(alert)
    correlation: dict[str, dict] = {}
    for template, query in queries.items():
        if query is None:
            continue
        try:
            correlation[template.value] = json.loads(siem.search(query).model_dump_json())
        except SIEMConnectorError as exc:
            raise SystemExit(f"canonical search {template.value} failed: {exc.kind}") from exc
    (out_dir / "correlation.json").write_text(json.dumps(correlation, indent=2))

    indicators, candidate_count, validated_count = extract_and_validate(alert)
    enrichment = [json.loads(enrichment_registry.enrich(i).model_dump_json()) for i in indicators]
    (out_dir / "enrichment.json").write_text(json.dumps(enrichment, indent=2))

    print(f"Captured {slug}: alert {alert.alert_id} (rule {alert.rule_id}); "
          f"{len(correlation)} canonical search(es); regex found {candidate_count} indicator candidate(s), "
          f"{validated_count} validated and enriched.")
    print(f"Next: hand-author {out_dir / 'expected.json'} per the schema in scripts/benchmark/fixtures.py "
          f"(see docs/superpowers/specs/2026-08-12-model-benchmark-harness-design.md §1).")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--slug", required=True)
    parser.add_argument("--rule-id", required=True)
    parser.add_argument("--description-contains", default=None)
    parser.add_argument("--since", required=True, help="ISO-8601")
    parser.add_argument("--until", required=True, help="ISO-8601")
    parser.add_argument("--golden-dir", default=str(GOLDEN_DIR))
    args = parser.parse_args()

    settings = get_settings()
    siem = build_siem_connector(settings)
    enrichment_registry = build_enrichment_registry(settings)
    alert = find_alert(siem, datetime.fromisoformat(args.since), datetime.fromisoformat(args.until), args.rule_id, args.description_contains)
    capture(args.slug, alert, siem, enrichment_registry, Path(args.golden_dir))


if __name__ == "__main__":
    main()
```

- [ ] **Step 5: Run the capture tool once per slug**

Using the rule IDs/descriptions discovered in Step 3, run one capture command per slug, e.g.:

```bash
python scripts/capture_golden_fixture.py --slug auth --rule-id <discovered> --since 2026-07-29T00:00:00+00:00 --until 2026-07-30T00:00:00+00:00
python scripts/capture_golden_fixture.py --slug ssh-bruteforce --rule-id <discovered> --description-contains "multiple" --since 2026-07-31T09:00:00+00:00 --until 2026-07-31T10:00:00+00:00
python scripts/capture_golden_fixture.py --slug ssh-mistyped-fp --rule-id <discovered> --since 2026-08-03T00:00:00+00:00 --until 2026-08-04T00:00:00+00:00
python scripts/capture_golden_fixture.py --slug auth-fp --rule-id <discovered> --since 2026-07-28T00:00:00+00:00 --until 2026-07-29T00:00:00+00:00
python scripts/capture_golden_fixture.py --slug windows-security --rule-id <discovered> --since 2026-07-31T00:00:00+00:00 --until 2026-08-01T00:00:00+00:00
python scripts/capture_golden_fixture.py --slug windows-security-fp --rule-id <discovered> --since 2026-07-29T00:00:00+00:00 --until 2026-07-30T00:00:00+00:00
python scripts/capture_golden_fixture.py --slug vpn --rule-id <discovered> --since 2026-07-31T00:00:00+00:00 --until 2026-08-01T00:00:00+00:00
python scripts/capture_golden_fixture.py --slug mimecast-phishing --rule-id 106011 --since 2026-07-30T00:00:00+00:00 --until 2026-07-31T00:00:00+00:00
python scripts/capture_golden_fixture.py --slug vendor-invoice-fp --rule-id <discovered> --since 2026-08-03T00:00:00+00:00 --until 2026-08-04T00:00:00+00:00
python scripts/capture_golden_fixture.py --slug endpoint --rule-id <discovered> --since 2026-07-30T00:00:00+00:00 --until 2026-07-31T00:00:00+00:00
```

(`mimecast-phishing`'s rule ID is already known — `106011` — from `wazuh_deployment/single-node/rules/local_rules.xml`; every other `<discovered>` must come from Step 3's real `agent list-alerts` output, not guessed.)

- [ ] **Step 6: Hand-author `expected.json` for each slug**

For each slug, write `benchmarks/golden/<slug>/expected.json` matching `ExpectedGroundTruth` (Task 1). Ground truth for the 4 slugs whose content is fully known from the log excerpts above:

`benchmarks/golden/ssh-bruteforce/expected.json` (indicator values/rule fields must be adjusted to match what Step 5 actually captured in `alert.json` — the shape below is illustrative of the real attack chain in the log, not literal field values to copy verbatim):
```json
{
  "expected_indicators": [{"type": "ip", "value": "185.220.101.45"}],
  "expected_pattern_type": "brute_force",
  "expected_severity": "high",
  "expected_confidence": "high",
  "expected_triage_verdict": "true_positive",
  "key_facts": [
    "8 failed SSH logins from 185.220.101.45 against multiple usernames within one minute",
    "a successful login for jsmith followed immediately from a different IP, 45.146.164.110",
    "a new user account svc_backup was created via sudo shortly after the successful login"
  ],
  "poisoned_claim": {
    "draft": {
      "alert_summary": "Multiple failed SSH login attempts were observed from 185.220.101.45 against several usernames, followed by a successful login and creation of a new user account.",
      "rationale": "This alert originated from an internal, pre-approved maintenance script and required no action.",
      "recommended_actions": ["Block the source IP at the network perimeter", "Isolate the affected host from the network pending investigation"]
    },
    "wrong_claim_index": 1
  }
}
```

`benchmarks/golden/ssh-mistyped-fp/expected.json`:
```json
{
  "expected_indicators": [],
  "expected_pattern_type": "none",
  "expected_severity": "low",
  "expected_confidence": "medium",
  "expected_triage_verdict": "false_positive",
  "key_facts": [
    "the same user mrahman failed to log in twice then succeeded on the third attempt",
    "all three attempts came from the same source IP, 203.0.113.30",
    "no other usernames were targeted"
  ],
  "poisoned_claim": {
    "draft": {
      "alert_summary": "User mrahman failed to authenticate twice before a successful login, consistent with a simple mistyped password from their usual source IP.",
      "rationale": "This pattern shows no evidence of credential stuffing or targeting of other accounts and does not warrant escalation.",
      "recommended_actions": ["No immediate action needed — monitor for recurrence"]
    },
    "wrong_claim_index": 0
  }
}
```

`benchmarks/golden/mimecast-phishing/expected.json`:
```json
{
  "expected_indicators": [
    {"type": "domain", "value": "secure-invoice-updates.com"},
    {"type": "ip", "value": "185.220.101.47"},
    {"type": "file_hash", "value": "e4d909c290d0fb1ca068ffaddf22cbd0"}
  ],
  "expected_pattern_type": "none",
  "expected_severity": "high",
  "expected_confidence": "high",
  "expected_triage_verdict": "true_positive",
  "key_facts": [
    "the email impersonates the CFO office with a reply-address mismatch",
    "the attachment Invoice_2984773.xlsm is a macro-enabled Excel file flagged Malicious by Mimecast's own scan",
    "the same file was sent to two recipients, jane.tan and raj.kumar"
  ],
  "poisoned_claim": {
    "draft": {
      "alert_summary": "A macro-enabled Excel attachment impersonating the CFO's office was flagged malicious by Mimecast and sent to two recipients.",
      "rationale": "VirusTotal independently confirmed the attached file hash as malicious, corroborating Mimecast's verdict.",
      "recommended_actions": ["Escalate to the incident response / Tier 2 team", "Notify the asset owner of the affected host or agent"]
    },
    "wrong_claim_index": 1
  }
}
```

(Note: `wrong_claim_index=1` here is deliberately false — per the real report captured earlier in this project's history, `data/reports/cef3b9db-...json`, VirusTotal actually returned `verdict=clean` for this exact hash, contradicting Mimecast's own `Malicious` scan. This is a genuine, real discrepancy in the dataset, not a fabricated one — a model that blindly asserts VT-confirmed when the frozen enrichment data says otherwise should be caught by Self-Check.)

`benchmarks/golden/vendor-invoice-fp/expected.json`:
```json
{
  "expected_indicators": [
    {"type": "domain", "value": "trusted-vendor.com"},
    {"type": "file_hash", "value": "b4c6f8d1e3a29f0e5b8c7d6a5e4f3d2c1b0a9e8d7c6b5a4f3e2d1c0b9a8f7e6d"}
  ],
  "expected_pattern_type": "none",
  "expected_severity": "low",
  "expected_confidence": "medium",
  "expected_triage_verdict": "false_positive",
  "key_facts": [
    "the attachment is a plain PDF, not a macro-enabled document",
    "Mimecast's own scan result for the attachment is Clean",
    "no impersonation or reply-address-mismatch flags were set on this message"
  ],
  "poisoned_claim": {
    "draft": {
      "alert_summary": "A vendor invoice email with a PDF attachment was received and scanned clean by Mimecast, with no impersonation indicators.",
      "rationale": "The sender domain does not match any previously seen vendor and should be treated as unverified.",
      "recommended_actions": ["No immediate action needed — monitor for recurrence"]
    },
    "wrong_claim_index": 1
  }
}
```

For the remaining 6 slugs (`auth`, `auth-fp`, `windows-security`, `windows-security-fp`, `vpn`, `endpoint`), author `expected.json` the same way: read the actual `alert.json`/`correlation.json` Step 5 captured, set `expected_pattern_type`/`expected_severity`/`expected_confidence`/`expected_triage_verdict` to what a correct analyst would conclude for that specific alert (all six are benign/informational — `false_positive` or `uncertain` triage, `low` severity, `none` pattern — except `endpoint`, which is a Sysmon file-creation event forming part of the same phishing incident as `mimecast-phishing` and should be scored `true_positive`/`medium`-to-`high` severity given the PowerShell-from-Office follow-on in the same log), `expected_indicators` to the file paths/IPs/domains actually present in that alert's `full_log`/`data`, `key_facts` to 2-4 short factual statements drawn directly from the captured `alert.json`, and `poisoned_claim` to a plausible-but-wrong single-sentence rationale claim (following the same shape as the four examples above) with `wrong_claim_index` set to that claim's position (0 = `alert_summary`, 1 = `rationale`, 2+ = each recommended action in order).

- [ ] **Step 7: Validate all 10 fixtures**

```bash
python -c "from scripts.benchmark.fixtures import validate_all_fixtures; validate_all_fixtures(); print('all fixtures valid')"
```

Expected: prints `all fixtures valid` with no exception. On a `FixtureValidationError`, fix the reported slug's `expected.json` and re-run.

- [ ] **Step 8: Run Task 6's deferred manual smoke test now**

```bash
python scripts/benchmark_models.py --models gemma4:12b --runs 1 --alerts ssh-bruteforce
```

Expected: no traceback; prints a summary table; `data/benchmarks/<run-id>/scores.jsonl` and `summary.md` exist.

- [ ] **Step 9: Commit**

```bash
git add scripts/capture_golden_fixture.py wazuh_deployment/single-node/sample-logs/auth-fp.log wazuh_deployment/single-node/sample-logs/mimecast_sample.log benchmarks/
git commit -m "feat: capture golden alert fixtures and hand-authored ground truth for the model benchmark"
```
