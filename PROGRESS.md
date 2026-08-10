# Progress

Living status tracker for the Local SIEM Alert Investigation Agent. See `ROADMAP.md` for phase descriptions and dependencies, `CLAUDE.md` for the full design. Update this file whenever a phase's status changes — this is the one thing meant to survive across sessions (unlike the per-plan SDD ledgers under `.superpowers/sdd/`, which are deleted once each plan's final review is clean).

| Phase | Status | Spec | Plan | Tests |
|---|---|---|---|---|
| 1. Foundation | ✅ Complete | *(none — built directly from `CLAUDE.md` via writing-plans)* | [`2026-08-08-foundation-implementation.md`](docs/superpowers/plans/2026-08-08-foundation-implementation.md) | 29 |
| 2. Enrichment (core) | ✅ Complete | [`2026-08-09-enrichment-module-design.md`](docs/superpowers/specs/2026-08-09-enrichment-module-design.md) | [`2026-08-09-enrichment-module-implementation.md`](docs/superpowers/plans/2026-08-09-enrichment-module-implementation.md) | 62 (cumulative) |
| 3. Integration (SIEMConnector) | ✅ Complete | [`2026-08-10-integration-siemconnector-design.md`](docs/superpowers/specs/2026-08-10-integration-siemconnector-design.md) | [`2026-08-10-integration-siemconnector-implementation.md`](docs/superpowers/plans/2026-08-10-integration-siemconnector-implementation.md) | 108 (cumulative), +3 skippable live |
| 4a. LLMClient Protocol + Ollama | ✅ Complete | [`2026-08-10-llm-client-design.md`](docs/superpowers/specs/2026-08-10-llm-client-design.md) | [`2026-08-10-llm-client-implementation.md`](docs/superpowers/plans/2026-08-10-llm-client-implementation.md) | 127 (cumulative), +1 skippable live |
| 4b. Deterministic pipeline skeleton | ⬜ Not started | — | — | — |
| 4c. LLM-calling classification steps | ⬜ Not started | — | — | — |
| 4d. Report drafting + Self-Check | ⬜ Not started | — | — | — |
| 5. Deployment / runtime glue | ⬜ Not started | — | — | — |
| 6a. EnrichmentCache | ⬜ Deferred (see Roadmap Phase 6) | — | — | — |
| 6b. Second Enrichment provider (VirusTotal) | ⬜ Deferred | — | — | — |

**Current test count:** 130 passing + 1 skipped on `main` with real `WAZUH_*` credentials configured in `.env` (the 3 Wazuh live tests run for real; the 1 LLM live test still skips — see below); 127 passing + 4 skipped without Wazuh credentials. Run `pytest -v` from repo root after `pip install -e ".[dev]"`.

**Resolved:** the Integration module's alert-timestamp field name question (`timestamp` vs `@timestamp`, open since the design spec) is now empirically confirmed — `test_live_alert_documents_use_the_timestamp_field_name` passed against a real instance. `pull_alerts`/`search`'s use of `"timestamp"` is correct; no further action needed.

**Discovered during Phase 4a:** this dev host has a real `ollama serve` daemon actually running and reachable — it just doesn't have `qwen3.5:9b` pulled (other Qwen models are present). The LLM live test (`tests/test_ollama_client_live.py`) correctly skips with a clear reason rather than failing. **Pull `qwen3.5:9b` (`ollama pull qwen3.5:9b`) to get real end-to-end validation of `OllamaClient`**, the same way the real Wazuh instance validated Integration.

**Open item carried into Phase 4b:** `LLMClient.health_check()` is reachability-only — it does NOT verify the configured model is actually pulled (confirmed by the discovery above: `health_check()` returns `True` on this host even though `qwen3.5:9b` isn't available, so `generate_structured()` would still fail with `model_not_found`). This was deliberately left alone rather than silently widened (an earlier attempt to do exactly that was caught and reverted during Phase 4a's review — see the plan's ledger history). **Phase 4b must decide explicitly**: either perform its own model-availability preflight before starting the state graph, or give `LLMClient` a separate `model_available() -> bool` method — don't let this surface implicitly mid-investigation on the first LLM-calling step.

## Notes carried forward

- Every subsystem's **final whole-branch review** (not the per-task reviews) has caught at least one Critical/Important bug invisible at task scale — Foundation's datetime-JSON-serialization crash, Enrichment's incomplete exception handling, Integration's bare `IndexError` on Wazuh's normal "not found" response plus a genuine MITRE-array mispairing bug that had been sitting in the design spec/plan itself. Keep budgeting for that final review + one fix round on every phase; don't skip it because per-task reviews were clean.
- `app/schemas.py` and `app/config.py` are shared foundations every later phase extends (Enrichment added `abuseipdb_api_key`, Integration added six `wazuh_*` fields to `Settings`) — expect the Agentic Analyst to do the same rather than inventing a parallel config module.
- Integration established a typed-error convention `LLMClient` now follows a third time: `LLMClientError(kind, message)` in `app/llm/errors.py`, same pattern as `EnrichmentError`/`SIEMConnectorError` — a single class with a `.kind` discriminator, never raising past the module boundary as a raw vendor exception. Kinds: `unreachable | model_not_found | generation_failed | validation_failed | timeout`. Phase 4b/4c/4d should keep using this convention rather than inventing a fourth shape.
- **Process lesson from Phase 4a's Task 9:** an implementer bundled an unauthorized production-code change into a task explicitly scoped as test-only, and silently rewrote an already-approved prior task's test to match. A re-reviewer caught it by explicitly checking "did this task touch files outside its stated scope" — not just correctness. Worth keeping that as a standing check for any test-only task going forward.
- Phase 4a chose the `openai` SDK (pointed at Ollama's OpenAI-compatible endpoint) over Ollama's native API — verified against Ollama's actual documented behavior, not assumed. `OllamaClient` is generically typed (`TypeVar` bound to `BaseModel`) so callers get their concrete Pydantic type back, not the `BaseModel` base class — Phase 4b's steps should follow the same generic pattern when they build their own typed call sites.
- Phase 4b is next — see Roadmap Phase 4a-4d for the full sub-phase breakdown. It needs to resolve the `health_check()` model-availability open item (above) as one of its first decisions.
