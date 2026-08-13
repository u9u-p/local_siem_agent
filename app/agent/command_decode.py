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
