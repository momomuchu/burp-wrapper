"""Tests for bp.config — load() precedence and redact() masking.

TDD protocol: RED tests are committed first; GREEN follows in config.py.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from bp.config import load, redact


# ---------------------------------------------------------------------------
# redact() — existing coverage (regression lock)
# ---------------------------------------------------------------------------


class TestRedactBearer:
    """Bearer token redaction — header-line and JSON-embedded forms."""

    def test_bearer_header_line(self) -> None:
        line = "Authorization: Bearer eyABCDEFGHIJKLMN"
        result = redact(line)
        assert "eyABCDEFGHIJKLMN" not in result
        assert "***" in result

    def test_bearer_json_embedded(self) -> None:
        blob = '{"name":"Authorization","value":"Bearer eyABCDEFGHIJKLMN"}'
        result = redact(blob)
        assert "eyABCDEFGHIJKLMN" not in result
        assert "***" in result

    def test_jwt_segments_masked(self) -> None:
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        result = redact(jwt)
        # The payload and signature segments should be masked
        assert "eyJzdWIiOiJ1c2VyIn0" not in result


class TestRedactCookieHeaderLine:
    """Cookie header-line form — existing pattern regression lock."""

    def test_cookie_header_line_masked(self) -> None:
        line = "Cookie: session=SECRETSESSIONTOKEN; path=/"
        result = redact(line)
        assert "SECRETSESSIONTOKEN" not in result
        assert "***" in result

    def test_set_cookie_header_line(self) -> None:
        line = "Set-Cookie: session=SECRETSESSIONTOKEN; HttpOnly"
        result = redact(line)
        assert "SECRETSESSIONTOKEN" not in result
        assert "***" in result


# ---------------------------------------------------------------------------
# [10] Cookie JSON-embedded form — NEW RED TESTS
# ---------------------------------------------------------------------------


class TestRedactCookieJsonEmbedded:
    """Cookie values embedded in JSON must be masked.

    When headers are serialized to JSON (e.g. --format json), a Cookie header
    appears as {"name":"Cookie","value":"session=SECRETSESSIONTOKEN"}.
    The value field must be masked; the key 'Cookie' may remain visible.
    """

    def test_cookie_json_value_masked(self) -> None:
        blob = '{"name":"Cookie","value":"session=SECRETSESSIONTOKEN"}'
        result = redact(blob)
        assert "SECRETSESSIONTOKEN" not in result, (
            "Cookie value in JSON blob must be masked"
        )
        assert "***" in result

    def test_set_cookie_json_value_masked(self) -> None:
        blob = '{"name":"Set-Cookie","value":"session=SECRETSESSIONTOKEN; HttpOnly; Path=/"}'
        result = redact(blob)
        assert "SECRETSESSIONTOKEN" not in result, (
            "Set-Cookie value in JSON blob must be masked"
        )
        assert "***" in result

    def test_cookie_json_name_preserved(self) -> None:
        """The cookie NAME (key before '=') may be preserved; value must be masked."""
        blob = '{"name":"Cookie","value":"session=SECRETSESSIONTOKEN"}'
        result = redact(blob)
        # The word 'Cookie' (field name) and 'session' (cookie name) may survive —
        # what must NOT survive is the secret value.
        assert "SECRETSESSIONTOKEN" not in result

    def test_cookie_json_multiple_cookies(self) -> None:
        blob = '{"name":"Cookie","value":"a=FIRST_SECRET; b=SECOND_SECRET"}'
        result = redact(blob)
        assert "FIRST_SECRET" not in result
        assert "SECOND_SECRET" not in result

    def test_cookie_json_authorization_key_form(self) -> None:
        """Flat JSON where Cookie is a key: {"Cookie":"session=SECRET"}."""
        blob = '{"Cookie":"session=SECRETSESSIONTOKEN"}'
        result = redact(blob)
        assert "SECRETSESSIONTOKEN" not in result

    def test_cookie_non_secret_text_unaffected(self) -> None:
        """Plain text without credential patterns is untouched."""
        plain = "no secrets here, just regular text"
        assert redact(plain) == plain


# ---------------------------------------------------------------------------
# [11] Authorization Basic / Token / Digest — NEW RED TESTS
# ---------------------------------------------------------------------------


class TestRedactAuthBasicTokenDigest:
    """Basic, Token and Digest credentials must be masked in both forms.

    Header-line form:   Authorization: Basic dXNlcjpwYXNzd29yZA==
    JSON-embedded form: {"name":"Authorization","value":"Basic dXNlcjpwYXNzd29yZA=="}
                        {"Authorization":"Basic dXNlcjpwYXNzd29yZA=="}
    """

    BASIC_TOKEN = "dXNlcjpwYXNzd29yZA=="   # base64("user:password")
    TOKEN_VALUE = "myapitokenvalue123"
    DIGEST_CRED = 'username="user", realm="example", nonce="abc123", uri="/", response="deadbeef"'

    # --- Basic ---

    def test_basic_header_line_masked(self) -> None:
        line = f"Authorization: Basic {self.BASIC_TOKEN}"
        result = redact(line)
        assert self.BASIC_TOKEN not in result, "Basic token in header line must be masked"
        assert "***" in result

    def test_basic_json_value_field_masked(self) -> None:
        blob = f'{{"name":"Authorization","value":"Basic {self.BASIC_TOKEN}"}}'
        result = redact(blob)
        assert self.BASIC_TOKEN not in result, (
            "Basic token in JSON value field must be masked"
        )
        assert "***" in result

    def test_basic_json_flat_key_masked(self) -> None:
        blob = f'{{"Authorization":"Basic {self.BASIC_TOKEN}"}}'
        result = redact(blob)
        assert self.BASIC_TOKEN not in result, (
            "Basic token in flat JSON key must be masked"
        )
        assert "***" in result

    def test_basic_standalone_masked(self) -> None:
        """'Basic <token>' appearing anywhere (not just as a header line) is masked."""
        text = f"creds: Basic {self.BASIC_TOKEN}"
        result = redact(text)
        assert self.BASIC_TOKEN not in result

    # --- Token ---

    def test_token_header_line_masked(self) -> None:
        line = f"Authorization: Token {self.TOKEN_VALUE}"
        result = redact(line)
        assert self.TOKEN_VALUE not in result, "Token in header line must be masked"
        assert "***" in result

    def test_token_json_value_field_masked(self) -> None:
        blob = f'{{"name":"Authorization","value":"Token {self.TOKEN_VALUE}"}}'
        result = redact(blob)
        assert self.TOKEN_VALUE not in result, (
            "Token credential in JSON value field must be masked"
        )
        assert "***" in result

    def test_token_standalone_masked(self) -> None:
        text = f"Token {self.TOKEN_VALUE}"
        result = redact(text)
        assert self.TOKEN_VALUE not in result

    # --- Digest ---

    def test_digest_header_line_masked(self) -> None:
        line = f"Authorization: Digest {self.DIGEST_CRED}"
        result = redact(line)
        assert "response=\"deadbeef\"" not in result, "Digest cred in header line must be masked"
        assert "***" in result

    def test_digest_json_value_field_masked(self) -> None:
        blob = f'{{"name":"Authorization","value":"Digest {self.DIGEST_CRED}"}}'
        result = redact(blob)
        assert "response=\"deadbeef\"" not in result, (
            "Digest credential in JSON value field must be masked"
        )
        assert "***" in result

    # --- Regression: Bearer still works after adding Basic/Token/Digest ---

    def test_bearer_unaffected_by_new_patterns(self) -> None:
        line = "Authorization: Bearer supersecretbearertokenXYZ"
        result = redact(line)
        assert "supersecretbearertokenXYZ" not in result
        assert "***" in result


# ---------------------------------------------------------------------------
# load() — precedence and boolean parsing
# ---------------------------------------------------------------------------


class TestLoadDefaults:
    def test_default_url(self) -> None:
        cfg = load()
        assert cfg.burp_rest_url == "http://127.0.0.1:8089"

    def test_redact_on_by_default(self) -> None:
        cfg = load()
        assert cfg.redact is True

    def test_ledger_on_by_default(self) -> None:
        cfg = load()
        assert cfg.ledger is True


class TestLoadFlagPrecedence:
    def test_flag_overrides_default_url(self) -> None:
        cfg = load(burp_rest_url="http://example.com:9999")
        assert cfg.burp_rest_url == "http://example.com:9999"

    def test_flag_disables_redact(self) -> None:
        cfg = load(redact=False)
        assert cfg.redact is False

    def test_flag_disables_ledger(self) -> None:
        cfg = load(ledger=False)
        assert cfg.ledger is False


class TestLoadEnvPrecedence:
    def test_env_url(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("BURP_REST_URL", "http://env-host:1234")
        cfg = load()
        assert cfg.burp_rest_url == "http://env-host:1234"

    def test_bp_no_ledger_disables_ledger(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("BP_NO_LEDGER", "1")
        cfg = load()
        assert cfg.ledger is False

    def test_invalid_bool_env_falls_through_to_default(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """BP_REDACT=junk should not silently disable redact — default (on) wins."""
        monkeypatch.setenv("BP_REDACT", "junk")
        cfg = load()
        assert cfg.redact is True


class TestLoadConfigFile:
    def test_file_sets_url(self, tmp_path: Path) -> None:
        cfg_file = tmp_path / "config"
        cfg_file.write_text("burp_rest_url=http://file-host:8000\n")
        cfg = load(config_path=cfg_file)
        assert cfg.burp_rest_url == "http://file-host:8000"

    def test_ledger_on_in_file(self, tmp_path: Path) -> None:
        cfg_file = tmp_path / "config"
        cfg_file.write_text("ledger=on\n")
        cfg = load(config_path=cfg_file)
        assert cfg.ledger is True

    def test_invalid_bool_in_file_keeps_default(self, tmp_path: Path) -> None:
        """ledger=ye in config file must not silently disable ledger."""
        cfg_file = tmp_path / "config"
        cfg_file.write_text("ledger=ye\n")
        cfg = load(config_path=cfg_file)
        assert cfg.ledger is True
