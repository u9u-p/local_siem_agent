# Wazuh Local Agent

A local AI agent that investigates and triages Wazuh SIEM alerts and produces an enriched report — summary, risk assessment, recommended actions, and an explicit uncertainty note — for a human security analyst to review. The agent is **strictly read-only**: it never takes remediation action, and its only output is a report. The LLM runs entirely on-device (Ollama) — no alert data or logs are sent to any cloud LLM API.

This is a prototype/POC, not connected to production SIEM data. See `CLAUDE.md` for the full design document and rationale, `ROADMAP.md` for what's built vs. planned, and `PROGRESS.md` for current status, test counts, and known issues.

## How it works, in brief

A deterministic 9-step pipeline (the "Agentic Analyst") investigates one alert at a time:

1. Ingest & parse the alert
2. Extract indicators (IPs, hashes, domains, URLs) via regex + LLM assistance
3. Enrich indicators against AbuseIPDB / VirusTotal (if configured)
4. Gather host/rule context from Wazuh
5. Correlate against recent related alerts
6. Assess risk (severity, confidence, rationale)
7. Draft the report (canonical + an experimental FP/TP triage verdict)
8. Self-check the draft against the evidence gathered
9. Finalize and persist the report

At every point the LLM makes a decision, it's constrained to a closed schema (an enum, a fixed set of options) — never a free-form choice — so a small local model can't hallucinate its way into bad output. See `CLAUDE.md` §4 for the full design.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| **Python 3.11+** | |
| **Ollama**, running locally (`ollama serve`) | Must serve a **GGUF-format** model — MLX-tagged builds silently ignore structured-output constraints and will produce garbage results (confirmed empirically, see `PROGRESS.md`). |
| A **GGUF chat model** pulled into Ollama | Project default: `gemma4:12b` (Q4_K_M). Run `ollama pull gemma4:12b` (not `gemma4:12b-mlx`). |
| **A Wazuh deployment** (manager + indexer), reachable over HTTPS | For local development, `wazuh_deployment/single-node/` in this repo brings up a full Docker Compose stack with seeded demo alerts — see [Setting up Wazuh](#setting-up-wazuh-local-demo-stack) below. Any Wazuh 4.x install works, provided you have indexer and manager credentials. |
| **Docker with Compose v2** | Only needed if using the bundled demo Wazuh stack. |
| AbuseIPDB / VirusTotal API keys | Optional. Without them, indicator enrichment is skipped gracefully (no crash) — alerts are still investigated, just without third-party reputation lookups. |

Approximate memory budget if Wazuh and Ollama run on the same machine (see `CLAUDE.md` §7.1): ~4–6GB OS baseline, ~3–6GB for the Wazuh stack (indexer JVM heap is capped at 1GB in the bundled demo compose file), ~8GB for `gemma4:12b` under Ollama. 24GB total is comfortable for this POC's scale.

---

## Installation

```bash
git clone <this-repo>
cd local-agent

python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Copy the environment template and fill in real values:

```bash
cp .env.example .env
```

| Variable | Default | Notes |
|---|---|---|
| `DATABASE_PATH` | `./data/alerts.db` | SQLite file — created automatically on first use. |
| `REPORTS_DIR` | `./data/reports` | Each investigated alert's report is also written here as JSON, alongside the SQLite copy. |
| `LOG_LEVEL` | `INFO` | |
| `ABUSEIPDB_API_KEY` | *(empty)* | Optional — enables IP reputation enrichment. |
| `VIRUSTOTAL_API_KEY` | *(empty)* | Optional — enables domain/hash/URL reputation enrichment. |
| `WAZUH_INDEXER_URL` | *(empty)* | e.g. `https://localhost:9200`. **Required** for `pull-alerts`/`investigate-all`/`investigate-one`. |
| `WAZUH_INDEXER_USERNAME` / `WAZUH_INDEXER_PASSWORD` | *(empty)* | |
| `WAZUH_MANAGER_URL` | *(empty)* | e.g. `https://localhost:55000`. |
| `WAZUH_MANAGER_USERNAME` / `WAZUH_MANAGER_PASSWORD` | *(empty)* | |
| `WAZUH_VERIFY_SSL` | `false` | Demo Wazuh deployments use self-signed certs — leave `false` for local use, set `true` before pointing at anything else. |
| `LLM_BASE_URL` | `http://localhost:11434/v1/` | Ollama's OpenAI-compatible endpoint. |
| `LLM_MODEL` | `gemma4:12b` | Must be a GGUF build, see Prerequisites. |
| `LLM_TIMEOUT_SECONDS` | `120` | |

`.env` is gitignored — never commit real credentials.

---

## Setting up Wazuh (local demo stack)

The repo includes a ready-to-run Wazuh Docker Compose stack under `wazuh_deployment/single-node/`, pre-seeded with synthetic demo alerts (SSH auth, VPN, Windows Security events, Mimecast email security, Sysmon) — including deliberate false-positive/true-positive pairs, useful for exercising the agent's investigation logic. Full details, credentials, and troubleshooting are in **`wazuh_deployment/single-node/README.md`** — the short version:

```bash
cd wazuh_deployment/single-node

# One-time (or whenever config/certs.yml changes): generate TLS certs
docker compose -f generate-indexer-certs.yml run --rm generator

# Start the stack (first boot takes ~1 minute)
docker compose up -d
```

Then point `.env`'s `WAZUH_*` variables at `https://localhost:9200` (indexer) and `https://localhost:55000` (manager) using the credentials documented in that sub-README.

If you already have a Wazuh deployment elsewhere, skip this section entirely and just fill in `.env` with its real indexer/manager URLs and credentials.

---

## Usage

Once `ollama serve` is running with the configured model pulled, and `.env` is filled in, the CLI is available either as `agent <command>` (after `pip install -e .`) or `python -m app.cli <command>`.

### Pull alerts from Wazuh

```bash
agent pull-alerts                                  # since the latest stored alert, or 24h ago if empty
agent pull-alerts --since 2026-08-01T00:00:00+00:00 --limit 200
```

> **Known limitation:** `pull-alerts` does not currently de-duplicate re-pulled alerts reliably — running it repeatedly (or with overlapping `--since` windows) will re-insert and re-investigate the newest already-stored alert each time. **Don't run this unattended or on a schedule yet.** See `PROGRESS.md`'s Phase 5 Known Risks for the root cause and planned fix.

### Add an alert manually (no live Wazuh needed)

Useful for testing or demos — reads a raw Wazuh `_source`-shaped JSON document (the same shape a real Wazuh indexer document has), not this project's internal schema:

```bash
agent add-alert path/to/alert.json
```

### Investigate alerts

```bash
agent investigate-all                 # every alert currently in NEW status
agent investigate-one <alert-id>      # one specific alert, regardless of its current status
```

Each investigation takes a few minutes (local LLM inference, ~2.5 minutes per alert with `gemma4:12b` per `PROGRESS.md`'s measurements) and produces a report, persisted both to SQLite and as a JSON file under `REPORTS_DIR`.

### Browse alerts and reports

```bash
agent list-alerts                           # all alerts, most recent first
agent list-alerts --status new --limit 20
agent list-reports
agent list-reports --min-severity high
agent show-report <report-id>               # human-readable
agent show-report <report-id> --json        # raw JSON
```

Run `agent --help` or `agent <command> --help` for the full option list on any command.

---

## Running tests

```bash
pytest -v
```

Most tests are pure unit/fake-based and always run. A handful of **live** tests (tagged, skippable) exercise the real Wazuh connection and the real Ollama model — they run automatically when `.env` has working `WAZUH_*` credentials and `LLM_MODEL` is reachable via `ollama serve`; otherwise they skip cleanly rather than failing.

---

## Project structure

```
app/
├── agent/        # the deterministic state-graph ("Agentic Analyst") and its LLM prompts/schemas
├── enrichment/    # AbuseIPDB / VirusTotal providers, rate limiting, indicator validation
├── integration/   # WazuhConnector (indexer + manager), auth strategies
├── llm/           # LLMClient Protocol + Ollama implementation
├── storage/       # SQLite-backed AlertStore
├── wiring.py      # builds real dependencies from Settings
├── report_export.py
├── cli.py         # the typer CLI
└── config.py      # Settings (pydantic-settings, reads .env)
tests/             # pytest suite, mirrors the app/ layout
wazuh_deployment/  # local demo Wazuh Docker Compose stack (see its own README)
docs/superpowers/  # design specs and implementation plans, one pair per phase
```

## Further reading

- **`CLAUDE.md`** — the full design document (architecture, data model, hallucination-mitigation rules, tech stack rationale).
- **`ROADMAP.md`** — phase-by-phase plan, what's built vs. deferred.
- **`PROGRESS.md`** — current test counts, known risks, and lessons carried forward from each phase's review.
