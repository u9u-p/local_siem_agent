# Session Handoff — 12 Aug 2026

Written at the end of a session on a MacBook Air M2 (8GB), for a fresh session continuing on a Mac Studio.

**How to use this:** read this file first, then `CLAUDE.md` (design doc), `ROADMAP.md` (what's built), `PROGRESS.md` (empirical findings and known risks). This document does not replace them — it records the state at handoff, what was found, and what to do next. Anything below marked *unverified* was established by reading code, not by running it.

---

## 1. Context

`local_siem_agent` is the demo for a HITCON 2026 talk:

> **Your First Agentic SOC Without the GPU Bill: Local LLM Triage on Apple Silicon**
> Tommy Wong, Ke Li Yam — HACKING 101 track, English, Day 1 (Fri 21 Aug 2026)
> https://hitcon.org/2026/en-US/agenda/9b7b1cd7-56da-4247-a0c9-2e2a23bc4c9e/

Handoff date is 12 Aug 2026 — **nine days before the talk**. That deadline is the prioritisation principle for everything below: what breaks the demo, then what makes it land, then what is merely correct. This is conference-demo software, not production software.

The previous machine (M2 Air, 8GB) could not run the stack at all — `gemma4:12b` Q4_K_M is ~7.6GB of weights, plus ~4–6GB for the Wazuh containers. Work and the demo now both happen on the Mac Studio.

---

## 2. Repo state at handoff

- Branch `main`, HEAD `cda9eb3` ("added wazuh deployent"), working tree clean.
- Phases 1–5 complete per `ROADMAP.md`. Phase 6 items are all deferred.
- `PROGRESS.md` claims **299 tests passing, 0 skipped**. **This was NOT verified** — the previous machine had no venv and no installed dependencies, so the suite was never run. Treat 299 as a claim to confirm, not a fact.
- `wazuh_deployment/` arrived in the final commit and is present.

---

## 3. Architecture map

Enough to orient; read the code for detail.

**Four Protocols, one implementation each, injected via `app/wiring.py`:**

| Protocol | Implementation | Notes |
|---|---|---|
| `SIEMConnector` | `app/integration/wazuh_connector.py` | Two backends behind one surface — indexer (Basic auth, alert search/pull) and manager (JWT, agent/rule metadata). JWT refresh is reactive: 401 → refresh → retry once. |
| `AlertStore` | `app/storage/sqlite_alert_store.py` | SQLModel, JSON columns for nested data, hand-written mappers both directions. |
| `EnrichmentProvider` | `app/enrichment/providers/{abuseipdb,virustotal}.py` | Static routing by `IndicatorType`, exactly one provider per type. |
| `LLMClient` | `app/llm/ollama_client.py` | OpenAI-compat `.parse()` with a Pydantic schema, `temperature=0`, retry-once then raise. |

**The pipeline** — `AgenticAnalyst.investigate()` in `app/agent/state_graph.py` is a straight line of 9 steps, no branching on LLM output. Six LLM calls: indicator extraction (2b), correlation classify (5), risk (6), draft-A + draft-B (7), self-check (8), plus one conditional open-value search.

The invariant that makes it work with a small local model: **the LLM proposes inside a closed schema, deterministic code validates and routes.** Concretely —

- Regex and LLM indicator extraction both pass through the *same* per-type Pydantic validators (`app/enrichment/indicators.py`); failures are discarded, never corrected.
- Correlation queries are built in code from real Wazuh field paths (`data.srcip`, `rule.id`, `data.dstip`); the LLM only picks a pattern type and at most one follow-up from a 4-member enum. `evidence_count` is summed by code.
- Canonical recommended actions are a 16-member enum, so Pydantic itself is the gate. Free text exists in exactly two places: the summary/rationale prose, and the explicitly-experimental draft-B.
- Self-check corrections apply asymmetrically (`_apply_self_check_corrections`): prose gets replaced, but an unsupported *action* is only ever dropped, never rewritten — that is what keeps the vocabulary closed.
- Every failure path appends to `self._degraded_reasons`, and that accumulator alone decides `COMPLETE` vs `NEEDS_HUMAN_REVIEW`. Nothing aborts an investigation.

**The demo data** — `wazuh_deployment/single-node/sample-logs/` is a designed incident, not filler:

- *True positive*, 2026-07-30 over ~8 minutes: Mimecast holds an impersonation email from `cfo.support@secure-invoice-updates.com` (IP `185.220.101.47`) → malicious `Invoice_2984773.xlsm` attachment with md5/sha1/sha256 → Sysmon sees Outlook write that file → EXCEL.EXE spawns `powershell -Enc` → that powershell connects to `185.220.101.47:443`, the same IP as the sender. Plus a separate 4625 password spray from `185.220.101.45` on 07-31.
- *False positives*: `mrahman` logs into Windows from `100.72.44.19`, an IP he has never used — which looks like compromise until you see `vpn.log` assign exactly that address as his ocserv NAT egress IP four minutes earlier, MFA approved. **Resolvable only by correlating across two log sources.** That is the most interesting demo case and also the most fragile (see finding 5).
- Custom decoders/rules: ocserv `100050`–`100054`, Mimecast `106000`–`106015` with real MITRE mappings and frequency-based escalation.

Log seeding uses two helper containers (`seed-sample-logs` creates empty files, `log-pusher` appends lines one at a time with a delay) because bind-mounting didn't reliably trigger `logcollector`.

---

## 4. Findings from the previous session

Established by reading code. None are in `PROGRESS.md`'s known-risks list — they are new.

1. **Step 4's gathered context is dead data.** `get_agent_context()` / `get_rule_metadata()` are called and logged, then bound to `_agent_context` / `_rule_metadata` at `state_graph.py:727` and never read again. No prompt builder accepts them. `CLAUDE.md` §4.2 rule 2 says calls from step 3 onward see "rule metadata" — they do not. Risk Assessment uses `alert.rule_groups` / `alert.mitre` off the raw alert instead. *Verified by grep: the only use sites are the call and the debug log.*

2. **Experimental triage fields are dropped on persist.** `Report.triage_verdict_experimental` / `triage_rationale_experimental` are set in `_assemble_report` (`state_graph.py:674`), but `ReportRecord` has no columns for them and neither `_report_to_record` nor `_record_to_report` touches them. They survive in the exported JSON file and vanish through SQLite, so `agent show-report --json` reads them as null. Existing tests assert only on the in-memory report, which is why the suite is green. *Verified: field-by-field diff of `Report` vs `ReportRecord` — exactly these two are missing.*

3. **`CLAUDE.md`'s "Project status" section is stale.** It states the repo contains only a requirements document with no code, tests or build tooling. Everything below that section (the design doc proper) is accurate. It is the file loaded into context every session.

4. **Key material is committed.** `wazuh_deployment/single-node/config/wazuh_indexer_ssl_certs/` contains `root-ca.key`, `root-ca-manager.key`, `admin-key.pem`, and the indexer/manager/dashboard private keys; `config/wazuh_indexer/internal_users.yml` carries six bcrypt hashes. `git check-ignore` confirms none are ignored. They are generated demo certs and the README calls the passwords demo defaults — but if `u9u-p/local_siem_agent` is public, treat that material as burned: don't reuse it, and regenerate before the stack is reachable from anything but localhost. Relatedly, `wazuh_deployment/single-node/README.md:17` describes that directory as a "gitignored payload, tracked dir", which is now false.

5. **UNVERIFIED — Windows alerts may not be able to pivot on source IP.** Stock Wazuh rules put the logon IP at `data.win.eventdata.ipAddress`, but `wazuh_source_to_alert` (`wazuh_connector.py:56`) reads `data.get("srcip")` only. If the stock decoder doesn't also emit `data.srcip`, then `Alert.source_ip` is `None` for every 4624/4625 → `SAME_SRC_IP_24H` is built as `None` and skipped (`correlation_queries.py:20`) → the password spray correlates only by `rule.id`+`agent.id`, **and the mrahman false positive cannot be resolved at all**, because resolving it requires pivoting on `100.72.44.19`. The only remaining path would be the open-value search, which by design fires only when the classifier already returned `none`/`other`. **Settle this by inspecting one real Windows alert document from the indexer before relying on that demo case.**

Already documented in `PROGRESS.md`/`ROADMAP.md`, not re-litigated here: the `pull-alerts` duplication gap, the missing `EnrichmentCache`, and the MLX-vs-GGUF constraint.

---

## 5. Task list, prioritised

### P0 — nothing else is real until these are done

1. **Verify the whole thing runs from a clean clone on the Mac Studio.** venv, `pip install -e ".[dev]"`, `pytest -q` (expect 299), bring up the Wazuh stack, confirm seeded alerts reach the indexer, `ollama pull gemma4:12b`, then one `investigate-one` end to end with a stopwatch. Nothing below is trustworthy until this is green.
2. **Fix `pull-alerts` duplication.** Make `alert_id` deterministic (`uuid5` over `source_system` + `source_alert_id`) in `wazuh_source_to_alert` so the existing `DuplicateAlertError` path actually fires. Every rehearsal run currently duplicates the newest alert, and `investigate-all` then burns ~2.5 min re-investigating it. One function plus tests.
3. **Decide the run mode and time it against the slot.** Fully live, or one live investigation plus pre-generated reports. This decision drives tasks 5–7.

### P1 — the demo's substance

4. **Add a step event hook.** Optional `on_step: Callable[[InvestigationStep], None]` on `AgenticAnalyst`, called at each `timeline.append`. `investigate()` is currently a blocking call that returns a finished `Report` with no progress stream — this is the prerequisite for any frontend. ~10 lines plus a test.
5. **Live pipeline view using `rich`.** Nine steps with status, current LLM call showing which schema is being enforced and elapsed time, enrichment verdicts and correlation counts landing as they resolve. Depends on 4. (`ratatui` was considered and rejected — Rust means a second toolchain, a second build and an IPC boundary, for no gain over `rich`/`textual` this close to the date.)
6. **Make the self-check visible.** Surface a claim being flagged and dropped in `_apply_self_check_corrections`. "The model proposed this, the code rejected it" is the talk's thesis in one frame. Needs a demo alert that reliably triggers a flag — find one during rehearsal. Depends on 5.
7. **Script the demo alerts and confirm actual output.** Run the TP chain and the mrahman FP several times each and record what the agent really concludes. Local model output varies; don't meet a surprise verdict on stage.

### P2 — gaps that invite awkward questions

8. **Settle finding 5** (Windows `source_ip`). Inspect a real alert document; if `data.srcip` is absent, either normalise it in the custom decoder or add a fallback in `wazuh_source_to_alert`. Do this *before* task 7.
9. **Step 4's discarded context** (finding 1). Either feed host/rule context into the risk/draft prompts or stop calling it. Saying "we gather host context" on stage while it goes nowhere is a question waiting to happen.
10. **Triage fields dropped on persist** (finding 2). Two columns plus both mappers, and a round-trip test — the current tests would not catch a regression.

### P3 — before anyone clones the repo off a slide

11. **Committed key material** (finding 4). Regenerate and gitignore, or accept as demo-only and fix the sub-README line.
12. **`CLAUDE.md`'s stale Project status** (finding 3). First thing a post-talk cloner reads.

### Explicitly not now

`ratatui`, `EnrichmentCache`, Postgres, the poller daemon, the FastAPI viewer. None change what happens on stage.

---

## 6. Setup on the Mac Studio

```bash
git clone https://github.com/u9u-p/local_siem_agent.git
cd local_siem_agent
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -q                      # expect 299 passing — confirm, don't assume
cp .env.example .env           # then fill in, see README.md's table
```

Wazuh stack:

```bash
cd wazuh_deployment/single-node
docker compose -f generate-indexer-certs.yml run --rm generator
docker compose up -d
```

Model — **GGUF only**:

```bash
ollama pull gemma4:12b
```

---

## 7. Gotchas

- **Never configure an MLX-tagged model.** `gemma4:12b-mlx` silently ignores `response_format` — Ollama's MLX backend does no grammar-constrained decoding, so the model markdown-wraps its JSON and every structured call fails. Same weights in GGUF work perfectly. `PROGRESS.md` has the full diagnosis. This is talk material, not just an implementation note.
- **~2.5 minutes per alert** with `gemma4:12b` across 6–7 calls. Budget stage time accordingly.
- **`pull-alerts` duplicates on every run** until task 2 lands. Don't schedule it; don't run it twice while rehearsing.
- **`WAZUH_VERIFY_SSL=false`** is correct for the demo stack's self-signed certs and must not survive contact with anything else.
- The config is fully env-driven, so `LLM_BASE_URL` / `WAZUH_*_URL` can point at another machine over the LAN with zero code changes — useful if a second person wants to develop against the Studio's stack. Ollama needs `OLLAMA_HOST=0.0.0.0` to accept non-local connections. Trusted networks only; it's plain HTTP.

---

## 8. Further reading in-repo

- `CLAUDE.md` — full design document (architecture, data model, hallucination-mitigation rules, tech-stack rationale). Ignore its "Project status" section, see finding 3.
- `ROADMAP.md` — phase-by-phase, what's built vs deferred, and *why* each design decision went the way it did. Unusually good; read before proposing changes.
- `PROGRESS.md` — empirical findings, known risks, per-phase review lessons.
- `docs/superpowers/specs/` and `docs/superpowers/plans/` — one design/implementation pair per phase.
- `wazuh_deployment/single-node/README.md` — stack credentials, demo log scenario, troubleshooting.
