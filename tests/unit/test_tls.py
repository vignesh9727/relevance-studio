# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""
Unit tests for TLS configuration loader.
"""

# Standard packages
import os

# Third-party packages
import pytest

# App packages
from server.tls import _parse_bool, _strip_env, get_tls_config, log_tls_status


class TestTlsConfig:
    """Tests for get_tls_config()."""

    def test_default_enabled(self, monkeypatch):
        """TLS_ENABLED defaults to true when unset."""
        monkeypatch.delenv("TLS_ENABLED", raising=False)
        monkeypatch.delenv("TLS_CERT_FILE", raising=False)
        monkeypatch.delenv("TLS_KEY_FILE", raising=False)
        cfg = get_tls_config()
        assert cfg["enabled"] is True
        assert cfg["error"] is not None
        assert "TLS_CERT_FILE" in cfg["error"]

    def test_disabled_explicit(self, monkeypatch):
        """TLS_ENABLED=false disables TLS."""
        monkeypatch.setenv("TLS_ENABLED", "false")
        monkeypatch.delenv("TLS_CERT_FILE", raising=False)
        monkeypatch.delenv("TLS_KEY_FILE", raising=False)
        cfg = get_tls_config()
        assert cfg["enabled"] is False
        assert cfg["ssl_context"] is None
        assert cfg["uvicorn_config"] is None
        assert cfg["error"] is None

    def test_disabled_variants(self, monkeypatch):
        """TLS_ENABLED accepts various false values."""
        for val in ("0", "False", "no", "off"):
            monkeypatch.setenv("TLS_ENABLED", val)
            monkeypatch.delenv("TLS_CERT_FILE", raising=False)
            monkeypatch.delenv("TLS_KEY_FILE", raising=False)
            cfg = get_tls_config()
            assert cfg["enabled"] is False
            assert cfg["error"] is None

    def test_missing_cert_var(self, monkeypatch):
        """When enabled, missing TLS_CERT_FILE yields clear error."""
        monkeypatch.setenv("TLS_ENABLED", "true")
        monkeypatch.delenv("TLS_CERT_FILE", raising=False)
        monkeypatch.setenv("TLS_KEY_FILE", "/tmp/key.pem")
        cfg = get_tls_config()
        assert cfg["enabled"] is True
        assert cfg["error"] is not None
        assert "TLS_CERT_FILE" in cfg["error"]
        assert cfg["ssl_context"] is None

    def test_missing_key_var(self, monkeypatch):
        """When enabled, missing TLS_KEY_FILE yields clear error."""
        monkeypatch.setenv("TLS_ENABLED", "true")
        monkeypatch.setenv("TLS_CERT_FILE", "/tmp/cert.pem")
        monkeypatch.delenv("TLS_KEY_FILE", raising=False)
        cfg = get_tls_config()
        assert cfg["enabled"] is True
        assert cfg["error"] is not None
        assert "TLS_KEY_FILE" in cfg["error"]
        assert cfg["ssl_context"] is None

    def test_missing_cert_file(self, monkeypatch, tmp_path):
        """When enabled, non-existent cert file yields clear error."""
        cert = tmp_path / "cert.pem"
        key = tmp_path / "key.pem"
        key.write_text("")
        monkeypatch.setenv("TLS_ENABLED", "true")
        monkeypatch.setenv("TLS_CERT_FILE", str(cert))
        monkeypatch.setenv("TLS_KEY_FILE", str(key))
        cfg = get_tls_config()
        assert cfg["enabled"] is True
        assert cfg["error"] is not None
        assert "does not exist" in cfg["error"]
        assert cfg["ssl_context"] is None

    def test_missing_key_file(self, monkeypatch, tmp_path):
        """When enabled, non-existent key file yields clear error."""
        cert = tmp_path / "cert.pem"
        key = tmp_path / "key.pem"
        cert.write_text("")
        monkeypatch.setenv("TLS_ENABLED", "true")
        monkeypatch.setenv("TLS_CERT_FILE", str(cert))
        monkeypatch.setenv("TLS_KEY_FILE", str(key))
        cfg = get_tls_config()
        assert cfg["enabled"] is True
        assert cfg["error"] is not None
        assert "does not exist" in cfg["error"]
        assert cfg["ssl_context"] is None

    def test_valid_files(self, monkeypatch, tmp_path):
        """When enabled with valid cert and key files, returns ssl_context tuple."""
        cert = tmp_path / "cert.pem"
        key = tmp_path / "key.pem"
        cert.write_text("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----")
        key.write_text("-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----")
        monkeypatch.setenv("TLS_ENABLED", "true")
        monkeypatch.setenv("TLS_CERT_FILE", str(cert))
        monkeypatch.setenv("TLS_KEY_FILE", str(key))
        cfg = get_tls_config()
        assert cfg["enabled"] is True
        assert cfg["error"] is None
        assert cfg["ssl_context"] == (str(cert), str(key))
        assert cfg["uvicorn_config"] == {
            "ssl_certfile": str(cert),
            "ssl_keyfile": str(key),
        }

    def test_ssl_context_tuple(self, monkeypatch, tmp_path):
        """ssl_context is a tuple of (cert_path, key_path) for Flask."""
        cert = tmp_path / "cert.pem"
        key = tmp_path / "key.pem"
        cert.write_text("")
        key.write_text("")
        monkeypatch.setenv("TLS_ENABLED", "true")
        monkeypatch.setenv("TLS_CERT_FILE", str(cert))
        monkeypatch.setenv("TLS_KEY_FILE", str(key))
        cfg = get_tls_config()
        assert isinstance(cfg["ssl_context"], tuple)
        assert len(cfg["ssl_context"]) == 2
        assert cfg["ssl_context"][0] == str(cert)
        assert cfg["ssl_context"][1] == str(key)

    def test_quoted_tls_enabled_treated_as_true(self, monkeypatch, tmp_path):
        """Surrounding quotes around TLS_ENABLED must not silently disable TLS."""
        cert = tmp_path / "cert.pem"
        key = tmp_path / "key.pem"
        cert.write_text("")
        key.write_text("")
        for raw in ('"true"', "'true'", '  "true"  '):
            monkeypatch.setenv("TLS_ENABLED", raw)
            monkeypatch.setenv("TLS_CERT_FILE", str(cert))
            monkeypatch.setenv("TLS_KEY_FILE", str(key))
            cfg = get_tls_config()
            assert cfg["enabled"] is True, f"failed for raw={raw!r}"
            assert cfg["error"] is None, f"failed for raw={raw!r}"
            assert cfg["uvicorn_config"] == {
                "ssl_certfile": str(cert),
                "ssl_keyfile": str(key),
            }

    def test_quoted_tls_paths_stripped(self, monkeypatch, tmp_path):
        """Surrounding quotes around cert/key paths must be stripped."""
        cert = tmp_path / "cert.pem"
        key = tmp_path / "key.pem"
        cert.write_text("")
        key.write_text("")
        monkeypatch.setenv("TLS_ENABLED", "true")
        monkeypatch.setenv("TLS_CERT_FILE", f'"{cert}"')
        monkeypatch.setenv("TLS_KEY_FILE", f"'{key}'")
        cfg = get_tls_config()
        assert cfg["error"] is None
        assert cfg["ssl_context"] == (str(cert), str(key))


class TestStripEnv:
    """Tests for _strip_env()."""

    def test_none_returns_empty(self):
        assert _strip_env(None) == ""

    def test_strips_whitespace(self):
        assert _strip_env("  hello  ") == "hello"

    def test_strips_double_quotes(self):
        assert _strip_env('"hello"') == "hello"

    def test_strips_single_quotes(self):
        assert _strip_env("'hello'") == "hello"

    def test_strips_quotes_with_outer_whitespace(self):
        assert _strip_env('  "hello"  ') == "hello"

    def test_unmatched_quotes_kept(self):
        assert _strip_env('"hello') == '"hello'
        assert _strip_env("hello'") == "hello'"

    def test_mismatched_quotes_kept(self):
        assert _strip_env("'hello\"") == "'hello\""

    def test_only_strips_one_pair(self):
        assert _strip_env("\"'hello'\"") == "'hello'"


class TestParseBool:
    """Tests for _parse_bool()."""

    @pytest.mark.parametrize("raw", ["true", "True", "TRUE", "1", "yes", "on", '"true"', "'true'", "  true  "])
    def test_truthy(self, raw):
        assert _parse_bool(raw, default=False) is True

    @pytest.mark.parametrize("raw", ["false", "False", "0", "no", "off", '"false"', "'false'"])
    def test_falsy(self, raw):
        assert _parse_bool(raw, default=True) is False

    def test_empty_uses_default(self):
        assert _parse_bool("", default=True) is True
        assert _parse_bool("   ", default=False) is False

    def test_none_uses_default(self):
        assert _parse_bool(None, default=True) is True
        assert _parse_bool(None, default=False) is False


class TestLogTlsStatus:
    """Tests for log_tls_status()."""

    def test_https_when_enabled_with_context(self, capsys, monkeypatch):
        monkeypatch.setenv("TLS_ENABLED", "true")
        tls = {"enabled": True, "ssl_context": ("/c.pem", "/k.pem")}
        log_tls_status("svc", "0.0.0.0", 4200, tls)
        err = capsys.readouterr().err
        assert "https://0.0.0.0:4200" in err
        assert "[svc]" in err
        assert "cert=/c.pem" in err
        assert "key=/k.pem" in err

    def test_http_when_disabled(self, capsys, monkeypatch):
        monkeypatch.setenv("TLS_ENABLED", "false")
        tls = {"enabled": False, "ssl_context": None}
        log_tls_status("svc", "0.0.0.0", 4200, tls)
        err = capsys.readouterr().err
        assert "http://0.0.0.0:4200" in err
        assert "https://" not in err

    def test_unset_marks_default(self, capsys, monkeypatch):
        monkeypatch.delenv("TLS_ENABLED", raising=False)
        tls = {"enabled": True, "ssl_context": ("/c.pem", "/k.pem")}
        log_tls_status("svc", "0.0.0.0", 4200, tls)
        err = capsys.readouterr().err
        assert "unset" in err
        assert "default: true" in err
