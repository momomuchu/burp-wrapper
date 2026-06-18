"""RED tests for A1 — the --pos semantic→byte-offset resolver (docs/ALGORITHMS.md A1).

`resolve_pos(raw, selector)` returns a Position{start,end,name} such that
`raw[start:end]` is exactly the value to fuzz.
"""

import pytest

from bp.pos import Position, PosError, resolve_pos

# Fixture request from ALGORITHMS.md A1 (CRLF, HTTP/1.1).
REQ: bytes = (
    b"POST /api/v2/users/42?redirect=/home HTTP/1.1\r\n"
    b"Host: t.example.com\r\n"
    b"Authorization: Bearer abc123\r\n"
    b"Cookie: sid=XYZ; role=user\r\n"
    b"Content-Type: application/json\r\n"
    b"\r\n"
    b'{"id":42,"name":"bob"}'
)


@pytest.mark.parametrize(
    ("selector", "expected"),
    [
        ("header:Authorization", b"Bearer abc123"),
        ("cookie:role", b"user"),
        ("cookie:sid", b"XYZ"),
        ("query:redirect", b"/home"),
        ("path:1", b"api"),  # convention: 1-based, first non-empty segment
        ("path:4", b"42"),
        ("body:id", b"42"),  # JSON number literal
        ("body:name", b"bob"),  # inside the quotes
        ("offset:0-4", b"POST"),
    ],
)
def test_resolve_pos_value(selector: str, expected: bytes) -> None:
    p = resolve_pos(REQ, selector)
    assert isinstance(p, Position)
    assert REQ[p.start : p.end] == expected
    assert p.name == selector


def test_header_match_is_case_insensitive() -> None:
    p = resolve_pos(REQ, "header:authorization")
    assert REQ[p.start : p.end] == b"Bearer abc123"


def test_resolve_pos_not_found() -> None:
    with pytest.raises(PosError) as ei:
        resolve_pos(REQ, "header:Nope")
    assert ei.value.code == "POS_NOT_FOUND"


def test_unsupported_selector_kind() -> None:
    with pytest.raises(PosError):
        resolve_pos(REQ, "bogus:thing")


# --- discovery UltraQA: resolver correctness edge cases ---


def test_cookie_found_in_second_cookie_header() -> None:
    """HIGH: a cookie present only in a later Cookie header must still be found."""
    req = b"GET / HTTP/1.1\r\nCookie: a=1\r\nCookie: target=found\r\n\r\n"
    p = resolve_pos(req, "cookie:target")
    assert req[p.start : p.end] == b"found"


def test_cookie_absent_in_all_headers_raises_not_found() -> None:
    req = b"GET / HTTP/1.1\r\nCookie: a=1\r\nCookie: b=2\r\n\r\n"
    with pytest.raises(PosError) as ei:
        resolve_pos(req, "cookie:missing")
    assert ei.value.code == "POS_NOT_FOUND"


def test_json_value_with_escaped_quote_spans_full_value() -> None:
    r"""HIGH: a JSON string value containing \" must not be truncated at the escaped quote."""
    body = b'{"key":"ab\\"cd"}'
    req = b"POST /api HTTP/1.1\r\nContent-Type: application/json\r\n\r\n" + body
    p = resolve_pos(req, "body:key")
    assert req[p.start : p.end] == b'ab\\"cd'


def test_reversed_offset_is_bad_selector() -> None:
    with pytest.raises(PosError) as ei:
        resolve_pos(REQ, "offset:5-3")
    assert ei.value.code == "BAD_SELECTOR"


def test_negative_offset_is_bad_selector() -> None:
    with pytest.raises(PosError) as ei:
        resolve_pos(REQ, "offset:0--5")
    assert ei.value.code == "BAD_SELECTOR"


def test_offset_beyond_length_is_pos_not_found() -> None:
    with pytest.raises(PosError) as ei:
        resolve_pos(REQ, "offset:0-99999")
    assert ei.value.code == "POS_NOT_FOUND"
