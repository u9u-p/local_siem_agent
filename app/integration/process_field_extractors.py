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
