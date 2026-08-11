# Design Document: Deployment / Runtime Glue (Phase 5)

**Date:** 12 Aug 2026
**Source requirements:** CLAUDE.md §6 (tech stack — "typer CLI, optionally a thin FastAPI view"), §7 (Deployment/Runtime Shape), ROADMAP.md Phase 5 section

---

## Context

Phases 1-4 built every module CLAUDE.md's architecture calls for (`SIEMConnector`, `AlertStore`, `EnrichmentRegistry`, `LLMClient`, the `AgenticAnalyst` state graph) but nothing yet assembles them into a runnable process — there is no `app/main.py`, no CLI, no wiring from `Settings` to concrete implementations. This phase closes that gap: a `typer` CLI that pulls alerts from Wazuh, investigates them, and lets an analyst browse the results, all backed by the real `SQLiteAlertStore`.

Decisions confirmed with the user during brainstorming:

1. **Runtime shape — one-shot commands, not a continuous background daemon.** CLAUDE.md §7 describes a persistent poller + in-process queue + worker thread; this phase instead builds a set of granular, independently-invokable CLI commands (`pull-alerts`, `investigate-all`, `investigate-one`, `add-alert`, plus browsing commands) meant to be run manually or via an external scheduler (cron/launchd). No threading, no queue, no shutdown handling — each command does its one job and exits. This is a deliberate scope reduction from CLAUDE.md's original continuous-process design, appropriate for a POC.
2. **CLI only, no FastAPI viewer.** Matches CLAUDE.md §6's "optionally" framing — a thin FastAPI view stays a clearly-named future candidate (see Open Items), not built here.
3. **`wazuh_deployment/` (the Wazuh docker-compose config) is untouched.** CLAUDE.md §7.1's JVM-heap-capping guidance is not applied as part of this plan — it gets a documentation note (ROADMAP.md/PROGRESS.md) flagging it as an operational step to apply directly before running against real alert volume, not a coded task here.

---

## 1. File Structure

- **`app/wiring.py`** (new) — the only place that turns a `Settings` instance into concrete Protocol implementations:
  - `build_siem_connector(settings: Settings) -> SIEMConnector` → `WazuhConnector`
  - `build_enrichment_registry(settings: Settings) -> EnrichmentRegistry` → registers `AbuseIPDBProvider` only if `settings.abuseipdb_api_key` is truthy, `VirusTotalProvider` only if `settings.virustotal_api_key` is truthy (a registry with zero providers registered is valid — `EnrichmentRegistry.providers_for()` already returns `[]` for an unregistered type, and `_step_enrich` already handles that via its existing `no_provider_registered` degrade path)
  - `build_llm_client(settings: Settings) -> LLMClient` → `OllamaClient`
  - `build_alert_store(settings: Settings) -> AlertStore` → `SQLiteAlertStore` (calls `get_engine(settings.database_path)` + `init_db(engine)` + wraps it)
  - `build_analyst(settings: Settings) -> AgenticAnalyst` → composes all four above
  - `build_siem_connector`/`build_alert_store` are also exposed standalone (not just via `build_analyst`) because CLI commands like `list-alerts`/`add-alert` need the `AlertStore` directly without constructing a whole `AgenticAnalyst`.

- **`app/report_export.py`** (new) — `write_report_file(report: Report, reports_dir: Path) -> Path`. Creates `reports_dir` if missing (`Path.mkdir(parents=True, exist_ok=True)`), writes `reports_dir / f"{report.report_id}.json"` via `report.model_dump_json(indent=2)`, returns the written path. This is CLAUDE.md §7's "report artefacts also written as files under `./data/reports/` for easy sharing" — not built in any earlier phase, and orthogonal to `AlertStore`'s SQLite persistence (which `investigate()` already does internally) — this is a second, independent output for the same `Report`, not a replacement.

- **`app/cli.py`** (new) — the `typer` app and its seven commands (§2). Each command function is a thin shell: build dependencies via `app/wiring.py`, call a same-named `_<command>` logic function with those dependencies as plain arguments, print/format the result, translate typed exceptions (`AlertNotFoundError`, `ReportNotFoundError`) into a friendly message + `typer.Exit(code=1)`. The `_<command>` logic functions are the unit-testable surface — they take already-constructed `SIEMConnector`/`AlertStore`/`AgenticAnalyst` instances (or fakes, in tests), never `Settings` or a path to construct anything themselves.

- **`app/schemas.py`** (modify) — no changes; `add-alert` reuses `wazuh_source_to_alert` from `app/integration/wazuh_connector.py` as-is.

- **`app/config.py`** (modify) — `Settings` gains `reports_dir: str = "./data/reports"`.

- **`.env.example`** (modify) — add a `REPORTS_DIR=./data/reports` line with the same commenting style as existing entries.

- **`pyproject.toml`** (modify) — add `"typer>=0.12,<1"` to `[project.dependencies]` (a runtime dependency — the CLI is meant to be run, not just imported in tests); add `[project.scripts] agent = "app.cli:main"`.

---

## 2. CLI Commands

All commands are synchronous, one-shot, and exit after their single unit of work. None start a background thread, loop, or queue.

### `pull-alerts [--since TEXT] [--limit INT=500]`

Determines `since`, in priority order: (a) the `--since` option if given (parsed as ISO-8601); (b) the most recently stored alert's `timestamp`, via `alert_store.list_alerts(limit=1)` (already sorted newest-first) — if that list is non-empty; (c) `datetime.now(timezone.utc) - timedelta(hours=24)` if the store is empty. Calls `siem.pull_alerts(since=since, until=None, limit=limit)`, then `alert_store.save_raw_alert(alert)` for each returned alert.

**`WazuhConnector.pull_alerts`'s `since` filter is inclusive (`gte`, confirmed in `app/integration/wazuh_connector.py`)** — using the latest already-stored alert's own timestamp as the next call's `since` will deterministically re-fetch that same alert every time `pull-alerts` runs, which `alert_store.save_raw_alert()` then rejects with `DuplicateAlertError` (a real `IntegrityError`-backed collision on `alert_id`, not a hypothetical edge case). Rather than trying to get the boundary arithmetic exactly right (which only fixes the exact-duplicate case, not genuinely overlapping `--since` windows a user might pass by hand), `pull-alerts` catches `DuplicateAlertError` per alert, counts it separately, and continues — this is the same "one bad item doesn't abort the batch" shape `_map_hits` already uses for malformed Wazuh documents. Prints `f"Pulled {new_count} new alert(s), skipped {duplicate_count} already-stored, since {since.isoformat()}."`

### `investigate-all`

Calls `alert_store.list_alerts(status=AlertStatus.NEW)`. For each alert: `report = analyst.investigate(alert)` (this already persists the report and flips the alert's status to `INVESTIGATED` internally, per Phase 4's `_step_finalize_and_persist`), then `write_report_file(report, Path(settings.reports_dir))`. Prints one line per alert: `f"{report.report_id} | {report.risk_assessment.severity.value:8} | {report.status.value}"`. If `alert_store.list_alerts(status=AlertStatus.NEW)` returns an empty list, prints `"No new alerts to investigate."` and exits cleanly (not an error).

### `investigate-one ALERT_ID`

Calls `alert_store.get_alert(alert_id)`. On `AlertNotFoundError`: prints `f"No alert found with id {alert_id}."` to stderr, exits with code 1. Otherwise: same `investigate()` + `write_report_file()` + one-line summary as `investigate-all`, for the single alert.

### `add-alert FILE`

Reads `FILE` as JSON (a raw Wazuh `_source` document — the same shape a Wazuh indexer document's `_source` field has, i.e. what `wazuh_source_to_alert()` already expects; NOT this project's internal `Alert` schema). Calls `wazuh_source_to_alert(json_data)`, then `alert_store.save_raw_alert(alert)`. On a malformed file (JSON parse failure, or `wazuh_source_to_alert` raising `KeyError`/`ValueError`/`TypeError` — the same exception types `_map_hits` already catches for this exact mapper), prints a friendly error to stderr and exits with code 1, rather than a raw traceback. On success, prints `f"Saved alert {alert.alert_id} (rule {alert.rule_id})."`

### `list-alerts [--status TEXT] [--limit INT=100]`

`--status` is validated against `AlertStatus`'s member values (case-insensitive) before calling `alert_store.list_alerts(status=..., limit=limit)`; an invalid value prints the valid choices and exits with code 1 rather than silently passing an unfiltered query through. Prints a simple aligned table: `alert_id | rule_id | rule_description | level | status | timestamp`. Empty result prints `"No alerts found."`

### `list-reports [--since TEXT] [--min-severity TEXT]`

`--since` parsed as ISO-8601 if given; `--min-severity` validated against `Severity`'s member values the same way `--status` is above. Calls `alert_store.list_reports(since=..., min_severity=...)`. Prints a table: `report_id | alert_id | severity | status | generated_at`. Empty result prints `"No reports found."`

### `show-report REPORT_ID [--json]`

Calls `alert_store.get_report(report_id)`. On `ReportNotFoundError`: friendly message + exit code 1. Without `--json`: a human-readable multi-line rendering (summary, risk assessment, recommended actions, uncertainty notes, timeline step names/actions). With `--json`: `report.model_dump_json(indent=2)` printed verbatim — the same content `write_report_file` already wrote to disk, available on demand for any report without needing its file path.

---

## 3. Testing

- `tests/test_wiring.py` — one test per `build_*` function. `SIEMConnector` and `LLMClient` are `@runtime_checkable` (confirmed: `app/integration/siem_connector.py`, `app/llm/client.py`), so `build_siem_connector`/`build_llm_client` can be asserted via `isinstance(result, SIEMConnector)`/`isinstance(result, LLMClient)`. `AlertStore` and `EnrichmentProvider` (`app/storage/alert_store.py`, `app/enrichment/registry.py`) are plain `Protocol`, **not** `@runtime_checkable` — `isinstance()` against them raises `TypeError` at runtime, not a clean pass/fail. `build_alert_store` is instead asserted via `isinstance(result, SQLiteAlertStore)` (the concrete type) or by calling a real method (`save_raw_alert`/`get_alert` round-trip) — same for anything touching `EnrichmentRegistry`'s registered providers, asserted via `registry.providers_for(IndicatorType.IP)` returning the expected concrete provider instances rather than a Protocol isinstance check. Also test that `build_enrichment_registry` registers zero/one/two providers correctly based on which API keys are set in a given `Settings` instance.
- `tests/test_report_export.py` — `write_report_file` writes valid JSON to the expected path, creates the directory if missing, and round-trips (`Report.model_validate_json` on the written file reproduces the original `Report`).
- `tests/test_cli.py` — one test per `_<command>` logic function using fakes (mirroring `tests/test_state_graph.py`'s `_FakeSIEMConnector`/`_FakeAlertStore` style — reuse or adapt those fakes rather than writing a third copy), covering: `pull-alerts`'s three-tier `since` resolution (explicit, latest-stored, empty-store fallback); `investigate-all` on zero/one/multiple `NEW` alerts; `investigate-one`/`show-report`'s not-found handling; `add-alert` on a valid Wazuh-shaped file and a malformed one; `list-alerts`/`list-reports`'s status/severity validation. A handful of `typer.testing.CliRunner` smoke tests confirm the actual command wiring (argument parsing, exit codes) on top of the logic-function unit tests — not a full duplicate matrix.

---

## Open Items

- **FastAPI viewer** — explicitly out of scope per the "CLI only" decision above; a natural Phase 6 candidate if browsing via a terminal table proves insufficient.
- **JVM heap capping in `wazuh_deployment/`** — explicitly out of scope per decision 3 above; to be applied manually as an operational step, tracked as a ROADMAP.md/PROGRESS.md note rather than a plan task.
- **Continuous background daemon** (poller thread + in-process queue + worker thread, per CLAUDE.md §7's original description) — explicitly deferred by the "one-shot commands" decision above. If real continuous operation is wanted later, it would build on top of these same one-shot logic functions (a scheduler loop calling `_pull_alerts`/`_investigate_all` on an interval) rather than requiring a rewrite.
