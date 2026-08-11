# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project status

This repository currently contains only a requirements document (`app_requirement.md`) — no code, dependency manifests, tests, or build tooling exist yet. There are no commands to build, lint, or test because there is nothing to build, lint, or test. When implementation begins, update this file with the actual commands (e.g. `pytest`, `ruff`, `python -m ...`) and the real module layout.

# Design Document: Local SIEM Alert Investigation Agent

**Date:** 07 Aug 2026
**Source requirements:** `app_requirement.md`

---

## Context

`app_requirement.md` describes a local AI agent that investigates and triages basic SIEM alerts, producing an enriched report with recommended actions for a human security analyst. The hard constraint is that the LLM must run fully on-device on a 24GB MacBook Pro — no cloud LLM calls — which shapes almost every downstream design choice, especially around how much freedom the agent's decision points can safely have. This document expands the four modules named in the requirements (Integration, Alert Tracking & Reporting, Agentic Analyst, Enrichment) into a concrete architecture, informed by the following decisions confirmed with the user:

1. **LLM inference engine** — left open; this document recommends a default but the design abstracts it behind a swappable interface.
2. **Agentic Analyst control flow** — must be a deterministic state graph with a small, fixed menu of allowed actions/tools at each step (not a free-form ReAct-style agent loop), to keep a small local model from hallucinating.
3. **Autonomy level** — strictly read-only investigation and reporting. The agent never takes remediation action; its only output is a report for a human analyst to act on.
4. **Storage** — SQLite plus local files for this demo, designed so it can be swapped for Postgres later.
5. **Deployment topology** — Wazuh (manager + indexer + dashboard, all-in-one) and this agent + its local LLM run **on the same 24GB host**. This makes memory a genuinely shared, contended resource between Wazuh and the model — see §7.1 for the resulting budget.

---

## 1. Module Boundaries and Interfaces

Each module is defined as a `typing.Protocol` (structural typing) so alternate backends satisfy the contract without inheritance. The Agentic Analyst only ever talks to these Protocols — never to a concrete Wazuh/AbuseIPDB class.

### 1.1 Integration module — `SIEMConnector`

```python
class AuthStrategy(Protocol):
    def get_headers(self) -> dict[str, str]: ...
    def refresh(self) -> None: ...   # no-op for static creds; rotates JWT for token-based auth

class SIEMConnector(Protocol):
    def health_check(self) -> bool: ...
    def pull_alerts(self, since: datetime, until: datetime | None, limit: int = 500) -> list[RawAlert]: ...
    def search(self, query: SearchQuery) -> SearchResult: ...
    def get_agent_context(self, agent_id: str) -> AgentContext: ...
    def get_rule_metadata(self, rule_id: str) -> RuleMetadata: ...
```

`SearchQuery` is deliberately a small constrained object (`field`, `operator` from a fixed enum `eq|contains|range|terms`, `value`, `time_range`) rather than a raw query-language string, so any investigation step that constructs a query — including one driven by an LLM decision — can only produce queries every backend is guaranteed to support.

### 1.2 Alert Tracking & Reporting — `AlertStore`

```python
class AlertStore(Protocol):
    def save_raw_alert(self, alert: Alert) -> str: ...
    def get_alert(self, alert_id: str) -> Alert: ...
    def list_alerts(self, status: AlertStatus | None, since: datetime | None, limit: int = 100) -> list[Alert]: ...
    def update_alert_status(self, alert_id: str, status: AlertStatus) -> None: ...
    def save_report(self, report: Report) -> str: ...
    def get_report(self, report_id: str) -> Report: ...
    def get_report_for_alert(self, alert_id: str) -> Report | None: ...
    def list_reports(self, since: datetime | None, min_severity: Severity | None) -> list[Report]: ...
```

`AlertStore` and `EnrichmentCache` (§1.3) are the only two persistence touchpoints in the system — Integration writes raw alerts here, the Agentic Analyst reads alerts and writes reports here, nothing else touches SQLite for alert/report data. That indirection makes a later Postgres swap a one-file change (new `AlertStore` implementation, same Protocol).

### 1.3 Enrichment module — `EnrichmentProvider` + `EnrichmentRegistry` + `EnrichmentCache`

```python
class IndicatorType(str, Enum):
    IP = "ip"; DOMAIN = "domain"; URL = "url"; FILE_HASH = "file_hash"; EMAIL = "email"

class EnrichmentProvider(Protocol):
    provider_id: str
    supported_types: frozenset[IndicatorType]
    def lookup(self, indicator: Indicator) -> EnrichmentResult: ...

class EnrichmentCache(Protocol):
    def get(self, provider_id: str, indicator_type: IndicatorType, indicator_value: str) -> EnrichmentResult | None: ...
    def set(self, result: EnrichmentResult, ttl: timedelta) -> None: ...

class EnrichmentRegistry:
    def providers_for(self, indicator_type: IndicatorType) -> list[EnrichmentProvider]: ...
    # ordered by config priority; the Agentic Analyst never names a provider directly
```

`EnrichmentCache` is owned by the Enrichment module, not `AlertStore` — it's the Enrichment module's own concern (TTL/eviction policy per §5), checked by `EnrichmentRegistry` before any provider call. It gets its own small SQLite table, kept separate from `AlertStore`'s tables so the two persistence concerns stay independently swappable.

### 1.4 Agentic Analyst

Not a swappable interface (it is the orchestration core) but a fixed `StateGraph` of `Step`s, each exposing a closed set of allowed next actions (detailed in §4). It depends only on `SIEMConnector`, `AlertStore`, `EnrichmentRegistry`, and an `LLMClient` Protocol — all injected.

---

## 2. Data Model

Pydantic models (also SQLModel table definitions for persisted ones).

### 2.1 `Alert` (raw, informed by Wazuh's alert JSON shape)

| Field | Type | Notes |
|---|---|---|
| `alert_id` | UUID | internal ID |
| `source_alert_id` | str | native Wazuh ID (`<epoch>.<counter>`) |
| `source_system` | str | `"wazuh"` — lets one store hold multi-SIEM alerts |
| `rule_id`, `rule_description`, `rule_level` | str/str/int | Wazuh rule id, description, severity 0–15 |
| `rule_groups` | list[str] | e.g. `["authentication_failed", "syslog"]` |
| `mitre` | list[MitreRef] \| None | `{tactic, technique_id, technique_name}` if decoder maps it |
| `timestamp` | datetime | event time (from SIEM) |
| `ingested_at` | datetime | when we pulled it |
| `agent` | AgentRef | `{id, name, ip}` |
| `manager_name` | str | |
| `location` | str | log source path/decoder location |
| `full_log` | str | raw log line |
| `source_ip`, `source_port`, `destination_ip`, `destination_port` | str/int | if applicable |
| `src_user`, `dst_user` | str \| None | |
| `data` | dict[str, Any] | decoder-extracted free-form fields |
| `raw_json` | dict | full original alert, stored losslessly for audit |
| `status` | enum | `NEW → IN_PROGRESS → INVESTIGATED → CLOSED` |

### 2.2 `EnrichmentResult`

| Field | Type | Notes |
|---|---|---|
| `indicator_type`, `indicator_value` | enum/str | |
| `provider_id` | str | |
| `queried_at` | datetime | |
| `verdict` | enum | `MALICIOUS \| SUSPICIOUS \| CLEAN \| UNKNOWN` |
| `score` | float 0–100 | normalised across providers |
| `raw_response` | dict | cached provider payload |
| `cache_expires_at` | datetime | |
| `error` | str \| None | rate-limited/timeout/not-found, so a step can degrade gracefully |

### 2.3 `Report`

| Field | Type | Notes |
|---|---|---|
| `report_id`, `alert_id` | UUID | |
| `generated_at` | datetime | |
| `alert_summary` | str | LLM-generated, plain language |
| `investigation_timeline` | list[InvestigationStep] | `{step_name, action, tool_used, input, output_summary, timestamp}` — one entry per state-graph transition, for auditability. Persisted as a single JSON column under SQLModel (not a child table) — it's small, append-only, and always read back whole with its parent `Report` |
| `enrichment_findings` | list[EnrichmentResult] | |
| `risk_assessment` | `{severity, confidence, rationale}` | |
| `recommended_actions` | list[str] | **canonical.** Human-actionable only, never executable — no "do it" tool is ever exposed to the agent. Populated by closed-vocabulary multi-select from a curated per-rule-group action catalog (§4.1 step 7), not free text |
| `recommended_actions_freeform_experimental` | list[str] \| None | **experimental, not vetted.** Free-text actions from a parallel, unconstrained generation call (§4.1 step 7) kept only to evaluate whether the local model can be trusted with open-ended action drafting — never surfaced as canonical guidance and not covered by the Self-Check pass |
| `uncertainty_notes` | str | explicit "what I could not verify / low-confidence areas" — derived by the Self-Check pass from concrete structural gaps (errored/`UNKNOWN` enrichments, unused correlation menu, missing MITRE mapping), not the model's self-assessed confidence (§4.2 rule 3) |
| `status` | enum | `DRAFT \| COMPLETE \| NEEDS_HUMAN_REVIEW` |
| `model_metadata` | `{model_name, model_version, prompt_version}` | for reproducibility/audit |

---

## 3. Wazuh Integration Specifics

Wazuh exposes two distinct backends that should **not** be blended behind one HTTP client:

- **Wazuh Indexer (OpenSearch)** — holds the actual alert corpus (`wazuh-alerts-*` indices). **Use this for both pulling/polling new alerts and ad-hoc search during investigation** — it is the only component with full alert history and a real query DSL (range/term/match/aggregation), which "how many other alerts from this src_ip in the last 24h" style steps need. Auth: HTTP Basic over HTTPS; demo instances typically use self-signed certificates, so the client needs an explicit, flagged `verify=False`/CA-bundle option (tighten before any non-demo use).
- **Wazuh Manager REST API** — does not hold rich alert search in current Wazuh 4.x; it is for operational data: agent metadata (`GET /agents/{id}`), rule/decoder lookups, file-integrity-monitoring and vulnerability-detector output. **Use this for host-context enrichment**, not for alert pulling. Auth: JWT bearer, obtained via a Basic-auth handshake against `/security/user/authenticate`; tokens expire (~900s default) and must be refreshed.

**Auth abstraction implication:** `WazuhConnector` composes two HTTP clients internally — one `BasicAuthStrategy` (indexer), one `JWTBearerAuthStrategy` (manager, wrapping its own basic-auth handshake and implementing `refresh()`) — but exposes a single `SIEMConnector` surface. A different SIEM implementing the same Protocol might need only one auth strategy; the Protocol doesn't care.

---

## 4. Agentic Analyst — State Graph & Prompting Design

The design goal for this section is narrower than "build a good agent": it is to get useful investigation behavior out of a **7–14B, on-device, quantised model** (§6) without relying on that model's judgement for anything open-ended. Every design choice below follows from one rule: **the LLM only ever answers one narrow, schema-constrained question at a time; it never decides control flow, never names a tool, and never sees more context than the specific question requires.** Routing, retries, and looping are all deterministic code.

### 4.1 State sequence

A linear FSM of 9 steps. Steps run in a fixed order; a step may be **skipped** by a deterministic pre-check, but the graph never branches on an LLM decision about *which step to run next* — only on small, schema-constrained choices *within* a step (e.g. "which one follow-up query, if any"). Each step appends one `InvestigationStep` to `Report.investigation_timeline` (§2.3), including skipped steps (logged with `action: "skipped"` and the reason), so the full run is reconstructable end to end.

| # | Step | LLM call(s)? | What happens |
|---|---|---|---|
| 1 | **Ingest & Parse** | — | Validate the raw alert against the `Alert` schema; initialize the timeline |
| 2 | **Extract Indicators** | **Call 1** — indicator candidates | Two sub-steps run concurrently, then merge (see §4.1.1) |
| 3 | **Enrich** *(skipped if the merged indicator set is empty)* | *Conditional call* — verdict reconciliation | `EnrichmentRegistry.providers_for()` invoked per indicator, priority order, cache-checked first (§5) — routing is always deterministic. If 2+ providers return conflicting verdicts for the same indicator, a reconciliation call picks a consolidated `{verdict, confidence}` from the same closed vocab the providers already use; otherwise skipped |
| 4 | **Gather Host/Rule Context** | — | `get_agent_context()` + `get_rule_metadata()` — pure data pull. Host/asset criticality, if used, comes from a config/inventory lookup, **never** an LLM guess (see §4.2 rationale) |
| 5 | **Correlate** | **Call 2** — search decision + pattern | Code always runs 2–3 canonical searches (same `src_ip`/24h, same `rule_id`/host, same `dst_host`). One call then does two things at once, in one schema: picks at most one follow-up `SearchQuery` from a closed menu of 3–4 templates (or "none needed"), and classifies `{pattern_type: enum(brute_force/scanning/lateral_movement/none/other), evidence_count: int}` over the results. If a follow-up was picked, code runs that single templated query and appends the result — capped at exactly one extra hop, never recursive |
| 6 | **Risk Assessment** | **Call 3** — severity + MITRE | LLM sees only the structured findings gathered so far (never `full_log` again past step 2). One schema returns `{severity: enum, confidence: enum, rationale: str}` plus, only if the Wazuh decoder left `mitre` empty, a MITRE technique pick from a **curated closed list** (~30–50 IDs relevant to the alert's `rule_groups`) or "unknown" — never a free-text technique ID |
| 7 | **Draft Report** | **Call 4** (canonical) + **Call 5** (experimental) | Draft-A (canonical): schema-constrained `alert_summary`, `risk_assessment.rationale` expansion, and `recommended_actions` as a closed-vocabulary multi-select from a curated per-rule-group action catalog. Draft-B (experimental, parallel, separate call): the same structured findings, but asked to freely compose action sentences with no catalog constraint, captured only in `recommended_actions_freeform_experimental` — never the canonical field, and not audited by step 8 |
| 8 | **Self-Check** | **Call 6** | Fresh call: given Draft-A's output plus the *same* structured findings (not Draft-A's reasoning, no chat history), audits each claim as `{claim, supported: bool, correction: str \| null}` and derives `uncertainty_notes` from concrete structural gaps (errored/`UNKNOWN` enrichments, unused correlation menu, missing MITRE mapping). Code applies corrections directly — no further free-form editing pass |
| 9 | **Finalize & Persist** | — | Assemble the `Report`, save via `AlertStore.save_report()`, update `Alert.status → INVESTIGATED` |

**Total per alert: 6 fixed LLM calls, plus at most 1 conditional call** (verdict reconciliation, only on provider disagreement). No step recurses; the only variable-length part of the whole graph is the single optional correlation hop in step 5, which is capped at one.

#### 4.1.1 Step 2 in detail — deterministic and LLM extraction, merged behind a validation gate

| Sub-step | LLM? | What happens |
|---|---|---|
| 2a. Regex extraction | No | Fast, precise pattern matching for well-formed indicators |
| 2b. LLM-assisted candidate extraction | Yes (Call 1) | Reads `full_log`/`data` and proposes `list[{type: IndicatorType enum, value: str}]` — catches defanged or non-standard IOC formatting (`185[.]220[.]101[.]1`, `hxxp://`) that regex misses |
| Merge gate | No | Every LLM-proposed candidate is run through the **same** strict per-type validator (`IPIndicator`, `HashIndicator`, etc.) that regex hits already pass through. Anything that fails validation is **discarded**, not corrected or retried. Discard counts are logged in the timeline (`"N proposed, M validated, K discarded"`) for later prompt tuning |

This is the general pattern reused everywhere else the LLM touches structured data in this design: **the LLM proposes inside a closed schema; deterministic code validates or gates before the result can reach an enrichment call, a report field, or anywhere else.** A hallucinated or malformed indicator from step 2b can add recall but can never inject bad data, because it never bypasses the same validator regex hits go through.

### 4.2 Prompting & hallucination-mitigation rules

These apply to every one of the 6–7 calls in §4.1, not just individual steps:

1. **Schema-constrained output, always.** Every call uses Ollama's JSON-schema-constrained generation with a Pydantic model as the schema. On a validation failure, the step retries once with the validation error appended to the prompt; a second failure falls back to a safe default (e.g. `confidence: low`, `Report.status: NEEDS_HUMAN_REVIEW`) rather than blocking the pipeline — no unbounded retries.
2. **Grounding — narrow input windows, not full context.** Only step 2b sees `full_log`/`data`; every call from step 3 onward sees only the typed, already-validated findings gathered so far (enrichment verdicts, correlation counts, rule metadata) — never the raw alert again, never a running transcript of prior LLM outputs. This keeps each prompt small (roughly a few hundred to ~1–2k tokens of structured JSON) and every claim traceable to a small, known input set.
3. **Self-Check is a re-read, not a continuation.** Step 8 gets a fresh prompt with Draft-A's output plus the same structured findings Draft-A saw — never Draft-A's reasoning or chat history — so it can't rubber-stamp its own prior output. `uncertainty_notes` comes from concrete structural gaps it observes, not the model introspecting on its own confidence (which LLMs are unreliable at).
4. **Closed vocabulary everywhere a choice is made.** Severity, confidence, pattern_type, MITRE technique, correlation-search template, verdict, and canonical recommended actions are all enum/catalog selections — never free text — with exactly two deliberately-scoped exceptions: Draft-A's summary/rationale prose, and the Draft-B experimental actions (both still grounded per rule 2).
5. **Prompt versioning.** Each step's prompt template is versioned and recorded in `Report.model_metadata.prompt_version` — a prompt edit is a tracked, diffable change, not a silent behavior shift.
6. **Model/context sizing.** With 6–7 calls per alert, each bounded to structured JSON rather than raw logs or transcripts, `gemma4:12b` (§6) should hold up for most steps; revisit model choice specifically for Risk Assessment and Draft-A if its classification accuracy or prose grounding proves weak in testing. Small, bounded prompts also keep per-call latency low enough that 6–7 sequential calls per alert stay practical on a single MacBook Pro without concurrent generation — measured at ~2.5 minutes/alert with `gemma4:12b` on short probe prompts (see `PROGRESS.md`), not yet with Phase 4c's real, longer per-step prompts.

---

## 5. Enrichment Plugin Architecture

- **Adapters**: `AbuseIPDBProvider`, `VirusTotalProvider` implement `EnrichmentProvider`. Each owns its own `APIKeyAuthStrategy` and its own request/response shape internally; externally both return the same `EnrichmentResult`.
- **Routing is deterministic, never LLM-chosen**: `EnrichmentRegistry` is a static config-driven map, e.g. `IP → [abuseipdb, virustotal]`, `FILE_HASH → [virustotal]`, `DOMAIN → [virustotal]`. The Agentic Analyst's job is only to (1) extract indicators from the alert via deterministic parsing, (2) ask the registry who handles that type, (3) call each candidate in priority order. No step ever asks the LLM to name a tool or provider — that open-ended choice is exactly what causes small-model hallucination, so it is removed from the LLM's responsibility entirely.
- **Rate limiting & caching**: each provider wrapped with a token-bucket rate limiter (config values per provider — e.g. AbuseIPDB ~1000/day, VirusTotal public API ~4/min & 500/day). `EnrichmentRegistry` checks the `EnrichmentCache` (§1.3) — its own SQLite table keyed on `(provider_id, indicator_type, indicator_value)`, separate from `AlertStore`'s tables — before any network call, with a per-type TTL (short, ~24h, for volatile IP reputation; longer, ~7 days, for hashes/domains).
- **Failure handling**: providers raise a typed `EnrichmentError` (`rate_limited | auth_failed | not_found | timeout`); the state-graph step catches this, records `verdict=UNKNOWN` with the error in the timeline, and continues — a provider outage must never abort the investigation.

---

## 6. Tech Stack Recommendation

| Concern | Recommendation | Why |
|---|---|---|
| HTTP clients (SIEM + enrichment) | `httpx` + `tenacity` for retry/backoff | modern sync/async, HTTP/2, clean timeout handling |
| Local LLM inference | **Ollama** as the default, behind an `LLMClient` Protocol | simplest local model lifecycle on Apple Silicon (Metal-accelerated), OpenAI-compatible API, native JSON-schema-constrained output and tool-calling — **confirmed empirically (Phase 4b) that this only holds for GGUF-format models**: Ollama's MLX backend silently ignores `response_format`, so MLX-tagged model builds are not usable for this project regardless of the underlying weights; alternatives (MLX-LM, llama-cpp-python) can implement the same Protocol later |
| Model | `gemma4:12b` (Q4_K_M, **GGUF format required** — see row above) | Empirically validated (Phase 4b) against real per-step-shaped schemas: matched `qwen3.5:9b` on correctness across flat/multi-enum/nested-list schemas, at roughly 4x the speed (~2.5 min vs ~8-9 min per 6-7-call alert investigation) — see `PROGRESS.md`. Supersedes `qwen3.5:9b` (chosen as the Phase 4a implementation target, itself superseding the original Qwen2.5/Llama-3.1 recommendation) as the project default |
| Structured output / "tool calling" | Ollama's JSON-schema-constrained generation, with Pydantic models as the schema, validate-or-retry on parse failure | keeps every LLM decision point returning a typed, closed-vocabulary object rather than free text — **GGUF-backend-only**, see the Local LLM inference row |
| SQLite access | **SQLModel** (SQLAlchemy + Pydantic) with **Alembic** migrations | one model definition serves both persistence and validation; moving `AlertStore` to Postgres later is a connection-string change |
| Config/secrets | `pydantic-settings` for typed env/`.env` loading, `config.yaml` for non-secret structure, with a thin `SecretsProvider` abstraction so the loading mechanism can later move from an env file to macOS Keychain or a proper secrets manager without touching call sites | typed, validated config; credentials never hardcoded or committed — `.env` excluded via `.gitignore`, only `.env.example` (variable names, no values) checked in |
| Deterministic state-graph orchestration | Lightweight custom FSM (enum of `Step`s + dispatcher), not LangGraph | the pipeline is a small fixed sequence (§4.1, 9 steps); a hand-rolled FSM keeps every allowed transition and action-set visible in one place — more auditable than a general agent-graph framework built for open-ended flows |
| Testing | `pytest`, `respx` (mock httpx), `freezegun` (poller timing) | |
| Demo surface | `typer` CLI, optionally a thin `FastAPI` view to browse reports | keeps the demo runnable without a full frontend |

---

## 7. Deployment/Runtime Shape

Single Python process for the demo:
- One process runs an internal poller (simple interval loop or `APScheduler`) calling `SIEMConnector.pull_alerts()`, writing new alerts via `AlertStore.save_raw_alert()`.
- New/pending alerts are handed to the Agentic Analyst via an in-process queue so a slow LLM investigation doesn't block polling.
- The state graph runs synchronously per alert — sequential processing is the right default; a single local model instance can't usefully serve concurrent generations without much more memory/compute headroom.
- **Ollama runs as its own local daemon** (`ollama serve`), accessed over `localhost` HTTP — the one process boundary in the system.
- SQLite file(s) on local disk (`./data/alerts.db`, `./data/cache.db`); report artefacts also written as files under `./data/reports/` for easy sharing.
- Optional thin FastAPI/CLI on top to trigger runs and browse reports, still inside the same process — no separate services or containers needed for the demo.

### 7.1 Resource budget (colocated Wazuh + local LLM on a 24GB host)

Per the Context section's deployment-topology decision, Wazuh (manager + indexer + dashboard, all-in-one) and this agent + Ollama share one 24GB machine, so memory is a genuinely contended resource. SQLite is not a factor here — it's an in-process library with a default page cache of only a few MB, not a competing daemon. The real budget:

| Component | Typical range | Notes |
|---|---|---|
| macOS baseline | ~4–6GB | OS + background processes, before anything else starts |
| Wazuh Manager | ~0.5–1GB | Moderate, not the concern |
| Wazuh Indexer (OpenSearch, JVM-based) | ~2–4GB+ | **The actual pressure point.** Its JVM heap defaults to auto-sizing against available host RAM — this must be explicitly capped for a colocated deployment, not left on its default |
| Wazuh Dashboard | ~0.5–1GB | Kept running per the deployment-topology decision above |
| Ollama + loaded model (idle) | ~8GB | `gemma4:12b` (Q4_K_M) is ~7.6GB of weights per §6, plus Ollama's own overhead and KV cache on top |
| This app (Python process) | ~0.2–0.5GB | Negligible |

These are planning-only ranges, not guarantees — validate actual resident memory with Activity Monitor or `ps` once Wazuh is installed on the target host, and adjust from there.

**Guidance, not a mandated number:** explicitly set the OpenSearch JVM heap (`-Xms`/`-Xmx`) to a fixed value sized for a single-analyst POC's alert volume rather than letting it auto-size to ~50% of host RAM (its usual default) — that default assumes the indexer owns the whole machine, which isn't true here. On a 24GB host, all-in-one Wazuh (~4–6GB) plus `gemma4:12b` under Ollama (~8GB) plus OS (~5GB) leaves a workable margin — comfortable enough for the POC, but still worth watching once real alert volume is flowing.

---

## 8. Open Questions and Assumptions (consolidated)

- **LLM model** is now decided: `gemma4:12b` (Q4_K_M, GGUF format), per Phase 4b's real-model probes (matched `qwen3.5:9b` on correctness at ~4x the speed; MLX-format builds of either model are unusable — see §6) — validate against real step prompts (§4) as Phase 4c builds them; revisit if classification accuracy or prose grounding proves weak.
- Assumes a single-node/all-in-one Wazuh install (manager + indexer + dashboard together); a distributed Wazuh cluster would need indexer-node-specific connection details.
- Assumes self-signed TLS is acceptable for the demo — must be tightened before any non-demo use.
- Assumes sequential (not concurrent) alert investigation is acceptable for demo throughput.
- This is a prototype/POC and is not connected to production SIEM data or used to act on real customer-impacting alerts; data classification, PDPA interpretation, retention, and IR-process alignment are out of scope until that changes.

---

## 9. Critical Files for Implementation (once approved)

- `app/integration/siem_connector.py` — `SIEMConnector`/`AuthStrategy` Protocols and the `WazuhConnector` implementation (dual indexer/manager auth)
- `app/storage/alert_store.py` — `AlertStore` Protocol and `SQLiteAlertStore` (SQLModel models + repository)
- `app/agent/state_graph.py` — the deterministic `Step` enum, allowed-action tables, and FSM dispatcher for the Agentic Analyst
- `app/llm/` — `LLMClient` Protocol (`client.py`), the Ollama-backed implementation with schema-constrained generation and retry-once (`ollama_client.py`), and the typed `LLMClientError` boundary (`errors.py`); a dependency of `app/agent/state_graph.py`
- `app/enrichment/registry.py` — `EnrichmentProvider` Protocol, `IndicatorType`→provider routing, rate-limit wrapper
- `app/enrichment/cache.py` — `EnrichmentCache` Protocol and its SQLite-backed implementation (§1.3)
- `app/schemas.py` — shared Pydantic models for `Alert`, `EnrichmentResult`, `Report`
- `app/config.py` — `pydantic-settings`-based typed config/secrets loader (§6)
- `.env.example` — placeholder documenting required secret variable names, no real values

## Verification

This is a design document, not code — "verification" here means review, not test execution:
1. Confirm §4 (Agentic Analyst state graph) is complete and consistent with the read-only/constrained-choice decisions, and that every LLM call point stays within a closed schema per the §4.2 rules.
2. Walk the four module Protocols in §1 against the requirements doc's modularity goal: confirm a second SIEM and a third enrichment provider could each be added by writing one new class, with zero changes to the Agentic Analyst.
