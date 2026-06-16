"""Raw HTTP/1.1 request parsing helpers (byte-offset based).

Shared by A1 (``pos``) and A2 (``fuzz``). HTTP/1.1, CRLF; LF-only tolerated.
All functions operate on ``bytes`` and return byte offsets.
"""

from __future__ import annotations

from collections.abc import Iterator


def line_end(raw: bytes, start: int, limit: int) -> tuple[int, int]:
    """Return (index_of_line_terminator, terminator_len) for the line at ``start``."""
    i = raw.find(b"\r\n", start, limit)
    if i != -1:
        return i, 2
    i = raw.find(b"\n", start, limit)
    if i != -1:
        return i, 1
    return limit, 0


def request_target_span(raw: bytes) -> tuple[int, int]:
    """Byte span of the request-target (2nd token of the request line)."""
    end, _ = line_end(raw, 0, len(raw))
    sp1 = raw.find(b" ", 0, end)
    if sp1 == -1:
        raise ValueError("malformed request line")
    sp2 = raw.find(b" ", sp1 + 1, end)
    if sp2 == -1:
        raise ValueError("malformed request line")
    return sp1 + 1, sp2


def header_region(raw: bytes) -> tuple[int, int]:
    """Byte span of the header block (after the request line, before the blank line)."""
    end, nl = line_end(raw, 0, len(raw))
    start = end + nl
    b = raw.find(b"\r\n\r\n")
    if b != -1:
        return start, b
    b = raw.find(b"\n\n")
    if b != -1:
        return start, b
    return start, len(raw)


def iter_headers(raw: bytes) -> Iterator[tuple[bytes, int, int]]:
    """Yield (name, value_start, value_end) per header; value is OWS-trimmed."""
    start, end = header_region(raw)
    i = start
    while i < end:
        le, nl = line_end(raw, i, end)
        colon = raw.find(b":", i, le)
        if colon != -1:
            name = raw[i:colon]
            v_start = colon + 1
            while v_start < le and raw[v_start] in (0x20, 0x09):
                v_start += 1
            v_end = le
            while v_end > v_start and raw[v_end - 1] in (0x20, 0x09):
                v_end -= 1
            yield name, v_start, v_end
        i = le + nl if nl else end


def body_start(raw: bytes) -> int:
    """Byte offset where the body begins (after the blank line); ``len(raw)`` if none."""
    b = raw.find(b"\r\n\r\n")
    if b != -1:
        return b + 4
    b = raw.find(b"\n\n")
    if b != -1:
        return b + 2
    return len(raw)


def content_type(raw: bytes) -> bytes:
    """Lowercased Content-Type header value, or empty bytes if absent."""
    for name, v_start, v_end in iter_headers(raw):
        if name.lower() == b"content-type":
            return raw[v_start:v_end].lower()
    return b""
