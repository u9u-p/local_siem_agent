# Implementation Roadmap

Master roadmap for the Local SIEM Alert Investigation Agent (see `CLAUDE.md` for the full design). This is a coarse-grained sequencing document, not a task-by-task implementation plan — each phase below gets its own brainstorm → spec → plan cycle (`docs/superpowers/specs/` and `docs/superpowers/plans/`) when it's actually started. See `PROGRESS.md` for current status.

Phases are ordered by dependency, per CLAUDE.md §1.4: the Agentic Analyst depends on `SIEMConnector`, `AlertStore`, `EnrichmentRegistry`, and an `LLMClient` — so Integration must exist before the Agentic Analyst can be built, even though Enrichment was built first (it had no such dependency).

---

## Phase 1: Foundation — ✅ Complete

**Goal:** Domain schemas, typed config, SQLite-backed `AlertStore`.
**Key files:** `app/schemas.py`, `app/config.py`, `app/storage/*`.
**Depends on:** nothing.

---

## Phase 2: Enrichment (core) — ✅ Complete

**Goal:** Typed indicators, typed errors, rate limiting, one live provider (AbuseIPDB), and the registry that routes/gates them.
**Key files:** `app/enrichment/*`.
**Depends on:** Phase 1 (`app/schemas.py`).
**Explicitly deferred out of this phase** (see Phase 6): `EnrichmentCache`.

---

## Phase 2b: VirusTotal Provider + Multi-Type Indicators — ✅ Complete

**Goal:** A second Enrichment provider (`VirusTotalProvider`) covering `DOMAIN`/`FILE_HASH`/`URL` indicator types, alongside three new Pydantic indicator models (`HashIndicator`, `DomainIndicator`, `URLIndicator`), so one alert's extracted indicators route by type to their own dedicated provider (IP → AbuseIPDB, everything else → VirusTotal) — one provider per indicator type, not multiple competing providers per type.
**Key files:** `app/enrichment/indicators.py` (extended), `app/enrichment/providers/virustotal.py` (new), `app/enrichment/registry.py` (one config-line addition, no dispatch-logic changes).
**Depends on:** Phase 2 (`EnrichmentRegistry`, `EnrichmentError`, `AbuseIPDBProvider` as the pattern to mirror).

Inserted between Phase 2 and Phase 3/4b once it became clear the Agentic Analyst's Correlate/Enrich steps (CLAUDE.md §4.1) need real multi-type indicator coverage to be worth building a state graph around — not deferred to Phase 6 after all. `EnrichmentRegistry` needed zero dispatch-logic changes (confirmed by design-phase code audit before implementation started): `register()` already loops a provider's `supported_types`, so a second, differently-typed provider slots in for free.

---

## Phase 3: Integration — SIEMConnector — ✅ Complete

**Goal:** `SIEMConnector` Protocol + `WazuhConnector` implementation, per CLAUDE.md §1.1 and §3.
**Key files (per CLAUDE.md §9):** `app/integration/siem_connector.py`.
**Depends on:** Phase 1 (`app/schemas.py` for `Alert`/`RawAlert`-shaped data).

Known design points already settled in CLAUDE.md, to carry into that phase's spec rather than re-litigate:
- Two backends, two auth strategies, one Protocol surface: `BasicAuthStrategy` for the Indexer (OpenSearch, pull/search), `JWTBearerAuthStrategy` for the Manager (agent/rule metadata) — CLAUDE.md §3.
- `SearchQuery` is a small constrained object (`field`, `operator` from `eq|contains|range|terms`, `value`, `time_range`), never a raw query string — CLAUDE.md §1.1.
- Self-signed TLS needs an explicit, flagged `verify=False`/CA-bundle option (CLAUDE.md §3, §8 assumption) — this is a demo-only affordance, not a default to leave on silently.

Resolved during that phase's brainstorming: mocked-first (respx) test suite plus a skippable real-instance smoke test — later run successfully against a real Wazuh 4.14.x Docker deployment, confirming both the API research and the one previously-open item (the alert timestamp field is `timestamp`, not `@timestamp`). JWT refresh is reactive (401 → refresh → retry once → propagate on second 401), not proactive.

---

## Phase 4: Agentic Analyst — State Graph — ✅ Complete (4a, 4b, 4c, 4d)

The largest, most novel phase (6 fixed LLM calls + 1 conditional per alert, per CLAUDE.md §4.1) and the one with the most undecided design surface — split into 4 sub-phases, each with its own brainstorm → spec → plan cycle, built in this order:

**Carry forward from Enrichment's final review, applying to every sub-phase below:** the "a provider outage must never abort the investigation" pattern (catch broadly, degrade to a synthetic result, never let an unexpected exception escape a module boundary) is exactly the shape CLAUDE.md §4.2 rule 1 asks for at each LLM call site (schema-validation retry, safe fallback default). Budget an explicit final-review check for "does any step's failure path actually degrade gracefully, or does it just look like it does" — this is precisely the class of bug that per-task review has caught in every subsystem so far (Foundation's datetime serialization, Enrichment's exception handling, Integration's bare `IndexError` and MITRE mispairing) because it only becomes visible at composition time.

### Phase 4a: `LLMClient` Protocol + Ollama implementation

**Goal:** Resolve the gap CLAUDE.md §1.4 requires but §9's critical-files list never names a home for — an `LLMClient` Protocol wrapping Ollama's JSON-schema-constrained generation, independently testable (mockable) with no state graph needed yet.
**Key files:** not yet named in CLAUDE.md §9 — likely `app/agent/llm_client.py` or `app/llm/client.py`, decided during this sub-phase's brainstorming.
**Depends on:** nothing (self-contained).

### Phase 4b: Deterministic pipeline skeleton — ✅ Complete

**Goal:** The FSM dispatcher itself (`app/agent/state_graph.py`'s `Step` enum + `AgenticAnalyst` dispatcher), steps 1/4/9 (Ingest & Parse, Gather Host/Rule Context, Finalize & Persist — no LLM), the deterministic half of steps 2/3 (regex extraction in `app/agent/indicator_extraction.py`; enrichment routing via the existing `EnrichmentRegistry`), skip-condition logic, and `InvestigationStep` timeline logging. LLM-calling steps (2b, Correlate, Risk Assessment, Draft Report, Self-Check) are wired in as inert stubs — no `generate_structured()` calls, no per-step schemas yet.
**Key files:** `app/agent/state_graph.py`, `app/agent/indicator_extraction.py`, `app/llm/client.py`/`app/llm/ollama_client.py` (gained `model_available()`).
**Depends on:** Phase 4a (`LLMClient` Protocol shape), Phase 1 (`AlertStore`, schemas), Phase 2/2b (`EnrichmentRegistry`, indicator validators), Phase 3 (`SIEMConnector`).

Decided during that phase's brainstorming: CLAUDE.md §4.1 step 3's verdict-reconciliation conditional call is **dropped entirely, not stubbed** — Phase 2b's one-provider-per-indicator-type architecture means two providers can never disagree on the same indicator, so the branch is structurally unreachable, not merely unbuilt. `LLMClient` gained `model_available()` (distinct from the existing reachability-only `health_check()`) so the pipeline can honestly distinguish "not yet implemented" from "model unavailable" in its stub steps' logged reasons — this has no behavioral effect yet in 4b (no step calls the LLM either way) but establishes the exact contract 4c's real steps need.

**Carried into 4c but NOT addressed there — still open for 4d or a dedicated fix:** the domain-regex extractor in `app/agent/indicator_extraction.py` over-extracts more than intended — its final-review found it matches common filenames (`setup.exe`, `invoice.pdf`, `auth.log`) as DOMAIN candidates, which then route to `VirusTotalProvider` and consume its shared 500/day quota while polluting `Report.enrichment_findings` with misleading "domain: setup.exe" rows. 4c's plan didn't touch `indicator_extraction.py`'s regex at all, so this remains exactly as flagged in 4b — the plan's "over-extraction is harmless" justification still doesn't hold once a real, rate-limited provider and a real analyst-facing report are both involved. **Resolved in 4d** — see below.

### Phase 4c: LLM-calling classification steps — ✅ Complete

**Goal:** Step 2b (indicator candidate extraction), step 5 (Correlate decision + pattern), step 6 (Risk Assessment) — all closed-vocabulary decision calls per CLAUDE.md §4.2. MITRE technique selection (originally part of step 6) is tabled for a future feature — `Alert.mitre` (Wazuh's own decoder-provided mapping, from Phase 3) is still passed to Risk Assessment as passive, non-LLM context, but there is no LLM-driven gap-filling or curated MITRE catalog. (Step 3's verdict-reconciliation call is out of scope — see Phase 4b's note above; it was dropped, not deferred to this phase.)
**Key files:** `app/agent/schemas.py` (new), `app/agent/prompts.py` (new), `app/agent/correlation_queries.py` (new), `app/agent/state_graph.py` (extended), `app/integration/models.py`/`app/integration/wazuh_connector.py` (`SearchQuery` redesigned to compound ANDed clauses).
**Depends on:** Phase 4a, Phase 4b (slots into the skeleton's stubs), Phase 2 (`EnrichmentRegistry`), Phase 3 (`SIEMConnector`).

Decided during that phase's brainstorming, beyond what CLAUDE.md §4.1 originally specified: `evidence_count` is computed by code (summed `SearchResult.total_count`), never LLM-returned. An **open-value search** was added as a genuine extension beyond CLAUDE.md's original closed-menu design — a separate, conditionally-triggered LLM call (only when the closed-menu classification comes back `NONE`/`OTHER`) that proposes a free-text search *value* only (never a field name), executed as a fixed `field="full_log", operator="contains"` query and flagged `"noisier, unstructured match"` in the timeline.

Final review caught two Critical, plan-level defects invisible to any single task's diff-scoped review, both fixed before merge: (1) the three SIEM `search()` calls inside Correlate (canonical searches, follow-up, open-value) were completely unguarded — unlike every other external-dependency call site in this codebase, an indexer outage would have crashed the whole investigation; (2) the canonical query field names (`source_ip`, `rule_id`, `destination_ip`) were Python `Alert` attribute names, not real Wazuh OpenSearch index paths (`data.srcip`, `rule.id`, `data.dstip`, confirmed against Phase 3's already-verified `wazuh_source_to_alert` mapper) — every canonical search would have silently returned zero evidence against a real Wazuh instance, making the phase's largest feature a no-op in production while reporting "completed" throughout. See `PROGRESS.md` for the full list, including two Important findings parked as real design questions for Phase 4d rather than fixed here (the follow-up menu currently just re-runs a canonical search verbatim; the open-value search's result is informational-only, not folded into `evidence_count` — both consistent with the design as discussed, not clearly bugs).

### Phase 4d: Report drafting + Self-Check — ✅ Complete

**Goal:** Step 7 (Draft-A canonical / Draft-B experimental) and step 8 (Self-Check) — the report-generation half, and arguably the hardest part: the two-pass draft+critique loop, and the one place in the whole design with deliberately free-text (not closed-vocabulary) output.
**Key files:** `app/agent/schemas.py` (`RecommendedAction`, `TriageVerdict`, `DraftReportCanonical`, `DraftReportExperimental`, `ClaimAudit`, `SelfCheckResult`), `app/agent/prompts.py` (Draft-A/B and Self-Check prompt builders), `app/agent/state_graph.py` (steps 7-8 implemented, `self._degraded_reasons` accumulator wired through the whole pipeline), `app/enrichment/indicators.py` (domain-regex fix), `app/schemas.py` (`Report.triage_verdict_experimental`/`triage_rationale_experimental`).
**Depends on:** Phase 4a, Phase 4b, Phase 4c (Self-Check audits claims against the structured findings 4c produced).

Carried the two items forward from 4c, both resolved in this phase: (1) the domain-regex over-extraction bug — `DomainIndicator`'s validator now rejects candidates whose final dotted segment is a common file extension (`exe`, `log`, `pdf`, `json`, ~45 more), with `com` deliberately excluded (the most common malicious TLD, worth the occasional filename false-positive to never silently drop a real malicious `.com` domain); (2) a prompt-capturing fake `LLMClient` test double (`_FakeLLMClient.calls: list[tuple[str, type]]`), used by new tests to prove cross-step data (e.g. Draft-A's `alert_summary`) actually reaches Self-Check's prompt text, not just its call signature.

Genuine extension beyond CLAUDE.md's original design, confirmed during brainstorming: an **experimental FP/TP triage verdict** (`TriageVerdict.TRUE_POSITIVE`/`FALSE_POSITIVE`/`UNCERTAIN` + a rationale), bundled into the existing Draft-B experimental call rather than a new 7th LLM call — surfaced only via `Report.triage_verdict_experimental`/`triage_rationale_experimental`, never touching the canonical `risk_assessment` or `recommended_actions` fields, and explicitly never audited by Self-Check (same non-canonical treatment as the freeform actions).

`recommended_actions` is a global, fixed 16-member `RecommendedAction` enum (not narrowed per alert's `rule_groups`) — Pydantic's own enum validation makes the field closed-vocabulary with no extra code-side gate needed. Self-Check audits Draft-A's output as exactly 3 claim types (`alert_summary`, `rationale`, each selected action), matched positionally; corrections apply asymmetrically — free-text fields get replaced by a correction string, but an unsupported action is only ever **dropped**, never replaced with free text (preserving the closed-vocabulary invariant), falling back to `ESCALATE_TO_HUMAN_ANALYST` if dropping empties the list. `uncertainty_notes` is computed deterministically in code from structural gaps (errored/`UNKNOWN` enrichments, unused correlation menu, missing MITRE mapping), never an LLM output field. `Report.status` is now genuinely computed (`COMPLETE` vs `NEEDS_HUMAN_REVIEW`) from a `self._degraded_reasons` accumulator threaded through the entire pipeline — not just this phase's own steps, but retrofitted into every earlier degradation source (SIEM context failures, correlation search failures, all LLM-call fallbacks) so a pre-existing SIEM-unavailable test kept passing under real logic instead of a hardcoded default.

Final whole-branch review found 1 Critical and 2 Important findings, all fixed before merge: (1) Self-Check returning a mismatched audit count (a plausible small-model failure — asked for N claims, got fewer back) silently fell through to `Report.status = COMPLETE` with an unaudited draft, defeating step 8's entire safety purpose without any trace; now treated as a degradation like any other self-check failure. (2) The domain-regex blocklist itself (fix carried in from 4c) initially included six real, currently-delegated TLDs (`so`, `sh`, `py`, `pl`, `rs`, and the 2023 gTLD `zip`) alongside genuine file extensions — repeating exactly the mistake the deliberate `com` exclusion was designed to avoid, and silently dropping real malicious domains like `invoice.zip` or `login-verify.pl`; all six removed from the blocklist. (3) A successful step-6 risk-assessment rationale was being unconditionally overwritten by Draft-A's fallback error string when Draft-A failed (even though Risk Assessment itself succeeded) — fixed so both Draft-A fallback paths preserve the original `risk_assessment.rationale` instead of destroying it. One Minor test-coverage gap was parked (not blocking): `test_step_draft_report_skips_when_model_unavailable` doesn't directly assert the model-unavailable fallback preserves `risk_assessment.rationale`, though the fix is correct by inspection and exercised by the test.

---

## Phase 5: Deployment / Runtime Glue — ✅ Complete

**Goal:** Wire everything into a runnable process, per CLAUDE.md §7.
**Key files:** `app/wiring.py` (new — builds real `SIEMConnector`/`AlertStore`/`EnrichmentRegistry`/`LLMClient`/`AgenticAnalyst` instances from `Settings`), `app/cli.py` (new — the `typer` CLI), `app/report_export.py` (new — file-based report artefacts), `app/config.py` (`Settings.reports_dir`).
**Depends on:** Phases 1–4 (needs a working state graph to hand alerts to).

**Deliberate scope reduction from CLAUDE.md §7's original design, decided during brainstorming:** this phase builds **one-shot CLI commands**, not the continuous poller-thread + in-process-queue + worker-thread daemon CLAUDE.md originally describes. Seven `typer` commands instead: `pull-alerts`, `add-alert` (manually inject a raw Wazuh-shaped alert from a file — no live Wazuh needed for demos), `investigate-all`, `investigate-one`, `list-alerts`, `list-reports`, `show-report`. Each does its one job and exits; meant to be invoked manually or via an external scheduler (cron/launchd). CLI only — no FastAPI viewer (CLAUDE.md's "optionally"). `wazuh_deployment/`'s docker-compose config was left untouched — the §7.1 JVM-heap-capping guidance remains a documented operational note (below), not a coded task.

**Known limitation, confirmed and deliberately left unfixed at final review:** `pull-alerts`'s duplicate-alert detection does not actually work. `wazuh_source_to_alert()` (Phase 3) assigns a fresh random `alert_id` on every mapping, so the same Wazuh alert re-pulled twice gets two different primary keys and never collides — `DuplicateAlertError`/the unique-constraint mechanism the design assumed is unreachable in practice. Since `WazuhConnector.pull_alerts`'s `since` filter is inclusive (`gte`), **every `pull-alerts` run re-fetches and duplicates the newest already-stored alert**, and `investigate-all` then re-investigates that duplicate (~2.5 minutes of local LLM time per run, unbounded growth). Two real fixes exist — making `alert_id` deterministic (a hash of `source_alert_id`) so the existing mechanism works, or adding a `get_alert_by_source_id`-style lookup to the `AlertStore` Protocol — but both touch already-merged code from earlier phases (Phase 3's `wazuh_source_to_alert`, or Phase 1's `AlertStore` Protocol) rather than this phase's own new code, so the user explicitly chose to document this rather than fix it now. **Do not run `pull-alerts` unattended/on a schedule until this is fixed** — for now, treat it as safe only for deliberate, manually-checked one-off pulls, and expect at least one duplicate row per invocation.

Carries the §7.1 resource-budget guidance (cap the Wazuh indexer JVM heap, pick 7B vs 14B based on measured headroom) — not yet applied to `wazuh_deployment/`'s docker-compose config; still an outstanding operational step before any sustained real-alert-volume use.

---

## Phase 6: Deferred / Future Work

Not scheduled — pick up opportunistically or when a concrete need arises:

- **`EnrichmentCache`** — deferred during Phase 2 for prototype-scoping reasons (see `docs/superpowers/specs/2026-08-09-enrichment-module-design.md`'s Non-Goals). CLAUDE.md §1.3 already defines the Protocol shape; slots into `EnrichmentRegistry.enrich()` as a cache-check-then-cache-write pair. **Do this before any sustained/production use** — repeated lookups currently cost real third-party API quota every time (both AbuseIPDB and, since Phase 2b, VirusTotal).
- **Postgres swap for `AlertStore`** — CLAUDE.md's Context §4 designs for this ("a new `AlertStore` implementation, same Protocol") but it's not needed until the demo needs to scale past SQLite.
- **Alembic migrations** — deferred in the Foundation plan's Global Constraints until the schema actually needs to evolve post-deployment.
- **§6.7-style Risk/Compliance/Legal sign-off** — not applicable to this POC per CLAUDE.md §8, but the trigger condition (connecting to production SIEM data or acting on real customer-impacting alerts) should be watched for explicitly, not assumed away.
- **`pull-alerts`'s duplicate-alert-detection gap** — see Phase 5's note above. Fix by either making `wazuh_source_to_alert()`'s `alert_id` deterministic (hash of `source_alert_id`) or adding an `AlertStore` lookup-by-`source_alert_id` capability. **Do this before running `pull-alerts` unattended/on a schedule** — every run currently duplicates the newest stored alert and re-investigates it.
- **Continuous poller daemon** — CLAUDE.md §7's original design (poller thread + in-process queue + worker thread), deliberately not built in Phase 5 in favor of one-shot commands. Would build on top of Phase 5's existing `_pull_alerts`/`_investigate_all` logic functions (a scheduler loop calling them on an interval) rather than requiring a rewrite.
- **FastAPI report viewer** — deferred per Phase 5's "CLI only" decision; a natural candidate if browsing via `list-alerts`/`list-reports`/`show-report`'s terminal tables proves insufficient.
