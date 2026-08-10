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

## Phase 4: Agentic Analyst — State Graph — Next

The largest, most novel phase (6 fixed LLM calls + 1 conditional per alert, per CLAUDE.md §4.1) and the one with the most undecided design surface — split into 4 sub-phases, each with its own brainstorm → spec → plan cycle, built in this order:

**Carry forward from Enrichment's final review, applying to every sub-phase below:** the "a provider outage must never abort the investigation" pattern (catch broadly, degrade to a synthetic result, never let an unexpected exception escape a module boundary) is exactly the shape CLAUDE.md §4.2 rule 1 asks for at each LLM call site (schema-validation retry, safe fallback default). Budget an explicit final-review check for "does any step's failure path actually degrade gracefully, or does it just look like it does" — this is precisely the class of bug that per-task review has caught in every subsystem so far (Foundation's datetime serialization, Enrichment's exception handling, Integration's bare `IndexError` and MITRE mispairing) because it only becomes visible at composition time.

### Phase 4a: `LLMClient` Protocol + Ollama implementation

**Goal:** Resolve the gap CLAUDE.md §1.4 requires but §9's critical-files list never names a home for — an `LLMClient` Protocol wrapping Ollama's JSON-schema-constrained generation, independently testable (mockable) with no state graph needed yet.
**Key files:** not yet named in CLAUDE.md §9 — likely `app/agent/llm_client.py` or `app/llm/client.py`, decided during this sub-phase's brainstorming.
**Depends on:** nothing (self-contained).

### Phase 4b: Deterministic pipeline skeleton

**Goal:** The FSM dispatcher itself (`app/agent/state_graph.py`'s `Step` enum + dispatcher), steps 1/4/9 (Ingest & Parse, Gather Host/Rule Context, Finalize & Persist — no LLM), the deterministic half of steps 2/3 (regex extraction; enrichment routing, already built in Phase 2), skip-condition logic, and `InvestigationStep` timeline logging. LLM-calling steps are wired in as stubs here, against a fake `LLMClient`.
**Key files:** `app/agent/state_graph.py`.
**Depends on:** Phase 4a (even a stub needs the real `LLMClient` Protocol shape), Phase 1 (`AlertStore`, schemas), Phase 3 (`SIEMConnector`).

### Phase 4c: LLM-calling classification steps

**Goal:** Step 2b (indicator candidate extraction), step 3's conditional verdict reconciliation, step 5 (Correlate decision + pattern), step 6 (Risk Assessment + MITRE) — all closed-vocabulary decision calls per CLAUDE.md §4.2.
**Depends on:** Phase 4a, Phase 4b (slots into the skeleton's stubs), Phase 2 (`EnrichmentRegistry`).

### Phase 4d: Report drafting + Self-Check

**Goal:** Step 7 (Draft-A canonical / Draft-B experimental) and step 8 (Self-Check) — the report-generation half, and arguably the hardest part: the two-pass draft+critique loop, and the one place in the whole design with deliberately free-text (not closed-vocabulary) output.
**Depends on:** Phase 4a, Phase 4b, Phase 4c (Self-Check audits claims against the structured findings 4c produced).

---

## Phase 5: Deployment / Runtime Glue

**Goal:** Wire everything into a runnable process — poller, in-process queue, CLI/FastAPI surface, per CLAUDE.md §7.
**Key files:** not yet named in CLAUDE.md §9 — add them when this phase is scoped (likely `app/main.py` / `app/poller.py` plus a `typer` CLI entry point).
**Depends on:** Phases 1–4 (needs a working state graph to hand alerts to).

Carries the §7.1 resource-budget guidance (cap the Wazuh indexer JVM heap, pick 7B vs 14B based on measured headroom) — this is where that guidance actually gets exercised for the first time.

---

## Phase 6: Deferred / Future Work

Not scheduled — pick up opportunistically or when a concrete need arises:

- **`EnrichmentCache`** — deferred during Phase 2 for prototype-scoping reasons (see `docs/superpowers/specs/2026-08-09-enrichment-module-design.md`'s Non-Goals). CLAUDE.md §1.3 already defines the Protocol shape; slots into `EnrichmentRegistry.enrich()` as a cache-check-then-cache-write pair. **Do this before any sustained/production use** — repeated lookups currently cost real third-party API quota every time (both AbuseIPDB and, since Phase 2b, VirusTotal).
- **Postgres swap for `AlertStore`** — CLAUDE.md's Context §4 designs for this ("a new `AlertStore` implementation, same Protocol") but it's not needed until the demo needs to scale past SQLite.
- **Alembic migrations** — deferred in the Foundation plan's Global Constraints until the schema actually needs to evolve post-deployment.
- **§6.7-style Risk/Compliance/Legal sign-off** — not applicable to this POC per CLAUDE.md §8, but the trigger condition (connecting to production SIEM data or acting on real customer-impacting alerts) should be watched for explicitly, not assumed away.
