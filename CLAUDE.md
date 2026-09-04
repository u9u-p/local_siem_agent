# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project status

Phases 1–5 are implemented; Phase 6 items are deferred. See `ROADMAP.md` for what is built and why, and `docs/PROGRESS.md` for empirical findings and known risks — including measured per-alert latency and the currently-known-wrong verdict on the VPN false positive.

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -q          # 465 passing, 0 skipped with the Wazuh stack up and gemma4:12b pulled
```

The CLI entry point is `agent` (`app/cli.py`): `pull-alerts`, `list-alerts`, `investigate-one`, `investigate-all`, `show-report`. Live tests skip unless `WAZUH_*` is configured in `.env` and `LLM_MODEL` is pulled and reachable. The demo Wazuh stack lives in `wazuh_deployment/single-node/` (`docker compose up -d`). There is no linter configured.

The full design document (module Protocols, data model, the 9-step state graph, prompting rules, resource budget) is `ARCHITECTURE.md`. Read it before changing anything under `app/agent/` or `app/llm/`. Product requirements are in `docs/app_requirement.md`; per-phase design specs and implementation plans are under `docs/superpowers/`.
