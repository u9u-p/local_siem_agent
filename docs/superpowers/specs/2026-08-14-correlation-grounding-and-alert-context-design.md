# Design Document: Correlation Grounding & Alert-Class Context

**Date:** 14 Aug 2026
**Source requirements:** CLAUDE.md §1.1 (`SearchQuery` Protocol), §4.1 step 5 (Correlate), §4.2 rules 2 and 4
**Supersedes:** `2026-08-14-value-based-indicator-correlation-design.md` (folded in as Phase 3)
**Evidence:** `PROGRESS.md` → "Correlate grounding & search precision (14 Aug 2026)". Every figure here was measured against the live single-node stack and `gemma4:12b`, not inferred.

---

## Context

The investigation started from one observation — `pattern_type` is frequently wrong — and the search for its cause turned up a set of related defects that share a root: **the pipeline has exactly one channel for alert content, the step 2 indicator vocabulary (IP / domain / hash / URL), and anything not expressible in it reaches no prompt at all.**

Measured field coverage across the live 71-alert corpus:

| Field | Coverage | Template it drives |
|---|---|---|
| `data.srcip` | 23/71 | `same_src_ip_24h` |
| `data.dstip` | **0/71** | `same_dst_host` |
| `data.dstuser` | 49/71 | — |
| `full_log` | **71/71** | none |

The field present on every alert drives no template; one template has never executed against real data. For Mimecast alerts the effect is total: sender IP lives in `data.mimecast.IP` and recipient in `data.mimecast.Rcpt`, while the mapper reads only `data.srcip`/`win_eventdata.ipAddress` — so `source_ip` is `None`, `same_src_ip_24h` never runs, and the cardinality grounding renders as an empty string. Correlation for that class is inert while the timeline still reports `action="completed"`.

Two findings constrain everything below.

**Direction is real and costly to lose.** For an IP that *is* typed, `term data.srcip` returns 8 and value-based returns 14. The extra 6 are the IP in other positions. Since direction is what separates scanning (one source, many destinations) from repeated attempts on one target, value-based search is **additive, never a replacement**.

**Shape does not imply intent.** A newsletter to 40 inboxes and a phishing campaign to 40 inboxes have identical cardinality. `vendor-invoice-fp` is already over-escalated to `high`/`high` against a golden `low`/`medium`. Cardinality signals — and burst/time-distribution signals, which behave the same way — must be scoped by alert class rather than asserted universally.

---

## 0. Already landed this session (context, not work)

Merged into the working tree, all TDD'd, 388 tests passing:

- **`contains` → `match_phrase`** ([wazuh_connector.py](../../../app/integration/wazuh_connector.py)). `match` ORs over tokens, so decoy domains `other-invoice-updates.com` and `secure-invoice-updates.net` each matched the same 4 alerts as the real `secure-invoice-updates.com`. Its one production caller is `_run_open_value_search`, fed LLM free text. `match_phrase` keeps recall, drops the false positives, and needs no escaping — `query_string` was rejected because a bare `"` in an LLM-supplied value returns HTTP 400.
- **Enrichment verdicts + distinct-value cardinality** in the correlation prompt.
- **Post-follow-up reclassification — built, then removed on review.** It was added to fix an apparent timing bug (`pattern_type` decided before `evidence_count` was updated). Review established the premise was false: every `follow_up_query` member is *also* a canonical template, so the follow-up re-runs a query whose hits the classification call already saw. There was no real drift — only the double-count creating the appearance of one. The call was removed, restoring the 6-fixed-plus-1-conditional budget. **The double-count remains, and Phase 3's dedupe is now its fix**, since re-running a query returns alerts that dedupe to the same set.
- **Enrichment failures no longer render as `score 0`** — an errored lookup now shows `(lookup failed: rate_limited)` rather than a number that reads as an all-clear on a 0–100 malice scale.
- **Partial cardinality is labelled** — `(over first N of M)` when the ≤500 alert bodies don't cover `total_count`.
- **`distinct_value_counts` aligned on truthiness**, so it and `_lacks_typed_context` agree that a blank decoder field means absent.
- **`_spread_guidance` made conditional** on a non-empty breakdown.
- **`raw_log` threaded** into Risk / Draft-A / Draft-B / Self-Check — **currently ungated; Phase 1 adds the gate.**

---

## 1. Phase 1 — gate `raw_log` on decoder starvation

### Why gated rather than always-on or reverted

A/B against `gemma4:12b`, 6 scenarios × 2–3 trials, `raw_log` the only variable: **every severity/confidence pair identical**. That includes `vpn`, separately re-run at 3 trials because it is the project's known-wrong verdict and the gate fires on it — `low`/`high` before and after, against a golden `low`/`medium`. Latency, 5 trials on the Risk call: median **23.81s → 29.24s (+23%)**, or ~+21.6s per alert across the four calls, ~14% of a ~150s baseline. The cost is output length, not prefill.

**So the justification is not verdict quality — there is no measured verdict gain anywhere.** It is solely that an unmapped decoder currently reaches the model through *no channel at all* while its timeline still reports `action="completed"`. The gate buys visibility for that case at ~2% aggregate latency, and nothing else. If Phase 4 lands promptly, Phase 1 can reasonably be skipped entirely.

Always-on therefore charges 14% for no measured verdict gain and spends §4.2 rule 2's traceability guarantee on every alert. Reverting outright loses the one property worth keeping: a decoder nobody has mapped yet is **silently invisible**, and that is the failure this whole investigation started from.

### The predicate

```python
def _lacks_typed_context(alert: Alert) -> bool:
    """True when nothing but the raw log describes this alert.

    command_context is None for every non-Sysmon alert, so it cannot gate alone —
    the typed-field conjunction is what narrows this to genuinely unmapped decoders.
    """
    return alert.process is None and not any(
        (alert.source_ip, alert.destination_ip, alert.src_user, alert.dst_user)
    )
```

**Measured selection: 10/71 live alerts (14%)**, spread across six rule groups — not mail alone, as first assumed:

| Rule group | Gated | Of |
|---|---|---|
| `mimecast` | 4 | 4 |
| `ocserv,vpn` | 2 | 6 |
| `syslog,sshd,authentication_failed` | 1 | 8 |
| `windows,windows_security,account_change` | 1 | 1 |
| `windows,sysmon,sysmon_event11` | 1 | 1 |
| `ossec` | 1 | 1 |
| everything else (pam, sshd success, Windows auth, sudo, sysmon_event1/3) | 0 | 49 |

Each of these is genuinely starved rather than a misfire. `sysmon_event11` (FileCreate) is caught because the Sysmon mapping covers Event ID 1 only, so `alert.process` is `None` for other event IDs — an unmapped decoder shape, exactly what the gate is for. A new decoder is picked up automatically and stops paying the moment someone maps it.

**Aggregate latency cost: ~2%**, not the 14% of always-on — 14% of alerts paying ~14% each. This is the number §7's re-measurement should confirm.

`raw_log` stays capped at `_COMMAND_CONTEXT_CHAR_CAP` (500) via the existing `_truncate`, and stays labelled `(unvalidated, context only)` so the model is told it is ungated evidence.

### Self-Check symmetry is mandatory

Step 8 audits Draft-A's claims against the same findings Draft-A saw. If Risk and Draft can see `raw_log` and Self-Check cannot, Self-Check flags well-grounded claims as unsupported. The gate must evaluate identically for all four calls — it is a property of the alert, not of the step.

---

## 2. Phase 2 — correlation grounding corrections

**Suppress tautological cardinality fields.** `same_src_ip_24h` pins `source_ip`; `same_dst_host` pins `destination_ip`. A distinct count of a pinned field is always 1, and a 1 beside a real count reads as evidence of concentration. Each template declares the fields it pins; those are dropped from its own breakdown.

**Scope the spread guidance by alert class.** It is already conditional on a non-empty breakdown (landed); it must additionally not fire for mail-class alerts, where one-to-many is the ordinary shape of legitimate bulk mail.

**Surface template-skip coverage.** When a template is skipped for a missing field, record it in the timeline with the reason. This is what makes a dead template like `same_dst_host` (0/71) visible instead of invisible.

---

## 3. Phase 3 — value-based indicator correlation

### `SearchQuery` Protocol change

`SearchClause.operator` gains `any_field_phrase`, with a validator requiring `field == "*"` so the intent is explicit rather than a magic string. It translates to:

```python
{"multi_match": {"query": clause.value, "type": "phrase", "fields": ["*"]}}
```

Measured, against the alternatives:

| Primitive | Real IP | Real domain | Decoy domain | `foo"` |
|---|---|---|---|---|
| `match` (pre-fix `contains`) | 4 | 4 | **4** ✗ | 0 |
| `query_string` phrase | 4 | 4 | 0 | **HTTP 400** ✗ |
| `match_phrase` (single field) | 4 | 4 | 0 | 0 |
| **`multi_match` phrase, `fields:["*"]`** | **4** | **4** | **0** | **0** |

A backend that cannot express all-fields phrase search must reject the operator at construction, loudly. Silently returning zero hits is the Phase 4c failure mode and must not recur.

### New template

`SearchTemplate.SAME_INDICATOR_ANY_FIELD`, driven by step 2's already-validated indicators — no new extraction, no new LLM call. For the Mimecast sender IP: `term data.srcip` → 0, `term data.mimecast.IP` → 3, value-based → **4**, spanning 2 recipients and 3 rule IDs. It beats even a hand-maintained per-decoder field list.

Selection is fully deterministic (§4.2 rule 4):

1. **Type priority** `IP → FILE_HASH → DOMAIN`. `URL` and `EMAIL` excluded — URLs rarely repeat verbatim and their tokens overlap their own domain; emails are near-always the alert's own subject rather than a pivot.
2. **Skip indicators already covered by a typed template.** If the value equals `alert.source_ip`, `same_src_ip_24h` already counts it. This is the defect Phase 4c Known Risk #5(a) records for the follow-up menu — not to be reproduced.
3. **Cap at 3**, recording the dropped count in the timeline. A silent cap reads as "covered everything".

Its results MUST NOT feed the cardinality breakdown — "this IP appears somewhere" carries no source/destination role.

### `evidence_count` deduplication

Replace the sum of `total_count` across templates with a count of distinct `source_alert_id` over every `SearchResult.alerts` gathered, follow-up included. This fixes the pre-existing double-count and prevents the new overlapping template from making it worse.

**Accuracy boundary:** `alerts` is capped at `_SEARCH_DEFAULT_SIZE = 500` while `total_count` comes from `hits.total.value`. Dedup is exact only while every contributing search is under 500 hits; above that the figure is a **floor**, and both prompt and timeline must say so. (`hits.total.value` is itself capped at 10,000 by OpenSearch default — pre-existing, out of scope.)

---

## 4. Phase 4 — config-driven alert-class context (supersedes Phase 1)

Phase 1 is a stopgap: it hands over the whole raw log because we cannot say which fields matter. The durable fix is to say which fields matter, declaratively.

The Sysmon work predicted this. Its decision 5 states field mapping stays "static and Sysmon-only for now… Config-driven mapping is a possible future evolution, not built now (YAGNI)." Mail is the second instance, which is where that deferral expires.

**Separate selection from transformation.** *Selection* ("which fields of this decoder matter") is declarative and generalises — a map from rule group / decoder to field paths and labels, needing no code for a new decoder. *Transformation* (base64/hex/PowerShell decoding) is real logic that differs per class and stays as code, only where decoding is actually needed. Mail needs selection only; Sysmon needs both.

A generic bounded passthrough of `data` was considered and rejected: Mimecast carries 16 fields of which roughly half are noise (`aCode`, `MsgId`, `acc`, `AttSize`), and letting prompt content vary with raw decoder output fights prompt versioning (§4.2 rule 5) and makes graded runs incomparable.

Whatever lands must note in the timeline when an alert carries `data` fields no rule surfaces — otherwise Phase 4 reintroduces exactly the silent invisibility Phase 1 exists to prevent.

Phase 1's gate and block are removed once a class is covered here.

---

## 5. Explicitly out of scope

- **Mapping `data.mimecast.*` into typed `Alert` fields.** Deliberate: value-based search already beats a per-decoder field list, and populating `source_ip`/`dst_user` for mail would *activate* the one-to-many cardinality trap rather than fix it.
- **Time-distribution / burst signal.** Strong for SSH and auth, actively misleading for mail — a newsletter blast is a tight burst too. Needs the same alert-class scoping as §2 before it is worth adding.
- **Baseline / denominator** ("is 5 alerts unusual for this host?"). The most invasive, and the root of the known-wrong VPN verdict.
- **`PatternType` enum coverage.** No member fits a mail campaign; `mimecast-phishing`'s own golden `expected_pattern_type` is `none`. No amount of added context improves a classification whose vocabulary excludes the phenomenon — tracked separately.
- **Uniform overconfidence.** `confidence: high` on all 6 scenarios where 4 goldens expect `medium`. Unrelated to this work, worth its own investigation.
- **Nested `data` scanning.** `extract_and_validate` reads only top-level `data` values, so `data.mimecast.*` is never scanned — only `full_log` saved us. General, benefits every decoder, independent of this spec.
- **Replacing the redundant follow-up templates** (Phase 4c Known Risk #5(a)).

---

## 6. Testing

Unit:
- `_lacks_typed_context` selects mail and rejects SSH/VPN/Windows Security fixtures; the gate evaluates identically for all four call sites.
- `any_field_phrase` with `field != "*"` raises at construction; the connector emits `multi_match`/`phrase`/`fields:["*"]` (respx).
- Indicator selection: type priority, typed-template overlap skip, cap-at-3 with the dropped count recorded.
- Dedup: an alert matching two templates counts once; a truncated search marks the count a floor.
- Cardinality: a template's pinned field is absent from its own breakdown; spread guidance omitted for mail-class alerts.

Live (skipped without `WAZUH_*` and a pulled model):
- A Mimecast alert yields non-zero value-based correlation where typed templates yield zero.
- Re-run the 6-scenario severity A/B and confirm no regression against the goldens in §0's baseline.

**Expect prompt-text breakage.** `_FakeLLMClient` captures `(prompt, schema)` and several tests assert on prompt *text*; changing what Correlate or Risk renders trips assertions that look unrelated. Known, not a surprise.

---

## 7. Verification

1. Value-based correlation is additive: typed templates still drive cardinality, and direction-dependent classification is unchanged for alerts with populated typed fields.
2. No new LLM call — the 6-fixed-plus-2-conditional budget is unchanged, and every selection step is deterministic per §4.2 rule 4.
3. Every skip path (missing field, no eligible indicator, cap truncation, search failure, uncovered `data` fields) appears in the timeline with its reason.
4. Latency re-measured after Phase 1's gate: the ~14% cost should fall to near-zero in aggregate, since the gate fires only for mail.
5. **Freeze `pattern_type` before grading.** It feeds the Risk, Draft and Self-Check prompts for every alert, so a second change mid-sweep invalidates the graded set.

---

*Internal — Ryt Bank*
