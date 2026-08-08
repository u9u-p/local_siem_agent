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
**Explicitly deferred out of this phase** (see Phase 6): `EnrichmentCache`, a second provider (VirusTotal).

---

## Phase 3: Integration — SIEMConnector — Next

**Goal:** `SIEMConnector` Protocol + `WazuhConnector` implementation, per CLAUDE.md §1.1 and §3.
**Key files (per CLAUDE.md §9):** `app/integration/siem_connector.py`.
**Depends on:** Phase 1 (`app/schemas.py` for `Alert`/`RawAlert`-shaped data).

Known design points already settled in CLAUDE.md, to carry into that phase's spec rather than re-litigate:
- Two backends, two auth strategies, one Protocol surface: `BasicAuthStrategy` for the Indexer (OpenSearch, pull/search), `JWTBearerAuthStrategy` for the Manager (agent/rule metadata) — CLAUDE.md §3.
- `SearchQuery` is a small constrained object (`field`, `operator` from `eq|contains|range|terms`, `value`, `time_range`), never a raw query string — CLAUDE.md §1.1.
- Self-signed TLS needs an explicit, flagged `verify=False`/CA-bundle option (CLAUDE.md §3, §8 assumption) — this is a demo-only affordance, not a default to leave on silently.

Open items for that phase's brainstorming (not yet decided):
- Whether to build against a real Wazuh instance or mock the Indexer/Manager HTTP APIs (`respx`, following the Enrichment phase's pattern) — likely mocked-first, same as AbuseIPDB, with a real-instance smoke test as a stretch goal.
- JWT refresh timing/retry policy for the Manager's ~900s token expiry.

---

## Phase 4: Agentic Analyst — State Graph

**Goal:** The 9-step deterministic FSM from CLAUDE.md §4 — the orchestration core that ties Integration, Enrichment, and an LLM together into investigation reports.
**Key files (per CLAUDE.md §9):** `app/agent/state_graph.py`.
**Depends on:** Phase 1 (`AlertStore`, `Report`/`Alert` schemas), Phase 2 (`EnrichmentRegistry`), Phase 3 (`SIEMConnector`), and an `LLMClient` Protocol.

**Gap to resolve before/during that phase's brainstorming:** CLAUDE.md §1.4 requires an `LLMClient` Protocol, but §9's critical-files list never names where it lives (no `llm_client.py` entry). Decide its home (likely `app/agent/llm_client.py` or `app/llm/client.py`) and whether it's built as part of this phase or as a small Phase 3.5 on its own — probably its own short phase, since it's independently testable (Ollama's JSON-schema-constrained generation, mockable) and several state-graph steps depend on it existing first.

This is the largest, most novel phase (6 fixed LLM calls + 1 conditional per alert, per CLAUDE.md §4.1) — expect it to be split into its own sub-phases during brainstorming (e.g. steps 1-4 deterministic pipeline first, then the LLM-calling steps, then Self-Check), rather than one flat 8-task plan like Foundation/Enrichment.

**Carry forward from Enrichment's final review:** the "a provider outage must never abort the investigation" pattern (catch broadly, degrade to a synthetic result, never let an unexpected exception escape a module boundary) is exactly the shape CLAUDE.md §4.2 rule 1 asks for at each LLM call site (schema-validation retry, safe fallback default). Budget an explicit final-review check for "does any step's failure path actually degrade gracefully, or does it just look like it does" — this is precisely the class of bug that per-task review missed twice now (Foundation's datetime serialization, Enrichment's exception handling) because it only becomes visible at composition time.

---

## Phase 5: Deployment / Runtime Glue

**Goal:** Wire everything into a runnable process — poller, in-process queue, CLI/FastAPI surface, per CLAUDE.md §7.
**Key files:** not yet named in CLAUDE.md §9 — add them when this phase is scoped (likely `app/main.py` / `app/poller.py` plus a `typer` CLI entry point).
**Depends on:** Phases 1–4 (needs a working state graph to hand alerts to).

Carries the §7.1 resource-budget guidance (cap the Wazuh indexer JVM heap, pick 7B vs 14B based on measured headroom) — this is where that guidance actually gets exercised for the first time.

---

## Phase 6: Deferred / Future Work

Not scheduled — pick up opportunistically or when a concrete need arises:

- **`EnrichmentCache`** — deferred during Phase 2 for prototype-scoping reasons (see `docs/superpowers/specs/2026-08-09-enrichment-module-design.md`'s Non-Goals). CLAUDE.md §1.3 already defines the Protocol shape; slots into `EnrichmentRegistry.enrich()` as a cache-check-then-cache-write pair. **Do this before any sustained/production use** — repeated lookups currently cost real third-party API quota every time.
- **Second Enrichment provider (VirusTotal)** — CLAUDE.md §5 names it as a second adapter; exercises the multi-provider fallback logic `EnrichmentRegistry` deliberately doesn't implement yet (currently always uses `providers[0]`).
- **Postgres swap for `AlertStore`** — CLAUDE.md's Context §4 designs for this ("a new `AlertStore` implementation, same Protocol") but it's not needed until the demo needs to scale past SQLite.
- **Alembic migrations** — deferred in the Foundation plan's Global Constraints until the schema actually needs to evolve post-deployment.
- **§6.7-style Risk/Compliance/Legal sign-off** — not applicable to this POC per CLAUDE.md §8, but the trigger condition (connecting to production SIEM data or acting on real customer-impacting alerts) should be watched for explicitly, not assumed away.
