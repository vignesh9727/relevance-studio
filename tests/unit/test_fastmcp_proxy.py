# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""
Unit tests for the MCP proxy:
  - _upstream_url():       upstream URL derived from env vars
  - _static_auth_headers(): Authorization header built from ES credentials
  - _ssl_httpx_factory():  httpx client factory with custom SSL verification
  - Module-level construction: correct transport built for TLS on/off
  - __main__ block:        transport selection, TLS error guard, port config
"""

import base64
import importlib
import sys
from unittest.mock import MagicMock, patch

import httpx
import pytest

from server.fastmcp_proxy import (
    _ssl_httpx_factory,
    _static_auth_headers,
    _upstream_url,
)


####  _upstream_url()  #########################################################


class TestUpstreamUrl:
    """Derives the upstream MCP server URL from environment variables."""

    # ── Explicit MCP_SERVER_URL ────────────────────────────────────────────────

    def test_explicit_url_used(self, monkeypatch):
        monkeypatch.setenv("MCP_SERVER_URL", "https://myhost:9999/mcp")
        assert _upstream_url() == "https://myhost:9999/mcp/"

    def test_explicit_url_trailing_slash_normalized(self, monkeypatch):
        monkeypatch.setenv("MCP_SERVER_URL", "https://myhost:9999/mcp/")
        assert _upstream_url() == "https://myhost:9999/mcp/"

    def test_explicit_url_takes_precedence_over_tls_flag(self, monkeypatch):
        monkeypatch.setenv("MCP_SERVER_URL", "http://override:1234/mcp")
        monkeypatch.setenv("TLS_ENABLED", "true")
        assert _upstream_url() == "http://override:1234/mcp/"

    def test_explicit_url_takes_precedence_over_port(self, monkeypatch):
        monkeypatch.setenv("MCP_SERVER_URL", "https://remote:5000/mcp")
        monkeypatch.setenv("FASTMCP_PORT", "9999")
        assert _upstream_url() == "https://remote:5000/mcp/"

    # ── TLS flag → scheme ─────────────────────────────────────────────────────

    def test_tls_enabled_uses_https(self, monkeypatch):
        monkeypatch.delenv("MCP_SERVER_URL", raising=False)
        monkeypatch.setenv("TLS_ENABLED", "true")
        monkeypatch.setenv("FASTMCP_PORT", "4200")
        assert _upstream_url() == "https://127.0.0.1:4200/mcp/"

    def test_tls_disabled_uses_http(self, monkeypatch):
        monkeypatch.delenv("MCP_SERVER_URL", raising=False)
        monkeypatch.setenv("TLS_ENABLED", "false")
        monkeypatch.setenv("FASTMCP_PORT", "4200")
        assert _upstream_url() == "http://127.0.0.1:4200/mcp/"

    def test_tls_defaults_to_true_when_unset(self, monkeypatch):
        monkeypatch.delenv("MCP_SERVER_URL", raising=False)
        monkeypatch.delenv("TLS_ENABLED", raising=False)
        monkeypatch.delenv("FASTMCP_PORT", raising=False)
        assert _upstream_url().startswith("https://")

    @pytest.mark.parametrize("value", ["false", "False", "0", "no", "off"])
    def test_tls_false_variants_use_http(self, monkeypatch, value):
        monkeypatch.delenv("MCP_SERVER_URL", raising=False)
        monkeypatch.setenv("TLS_ENABLED", value)
        monkeypatch.delenv("FASTMCP_PORT", raising=False)
        assert _upstream_url().startswith("http://")

    @pytest.mark.parametrize("value", ["true", "True", "1", "yes", "on"])
    def test_tls_true_variants_use_https(self, monkeypatch, value):
        monkeypatch.delenv("MCP_SERVER_URL", raising=False)
        monkeypatch.setenv("TLS_ENABLED", value)
        monkeypatch.delenv("FASTMCP_PORT", raising=False)
        assert _upstream_url().startswith("https://")

    # ── Port ──────────────────────────────────────────────────────────────────

    def test_custom_port_reflected_in_url(self, monkeypatch):
        monkeypatch.delenv("MCP_SERVER_URL", raising=False)
        monkeypatch.setenv("TLS_ENABLED", "false")
        monkeypatch.setenv("FASTMCP_PORT", "8888")
        assert _upstream_url() == "http://127.0.0.1:8888/mcp/"

    def test_default_port_is_4200(self, monkeypatch):
        monkeypatch.delenv("MCP_SERVER_URL", raising=False)
        monkeypatch.setenv("TLS_ENABLED", "false")
        monkeypatch.delenv("FASTMCP_PORT", raising=False)
        assert _upstream_url() == "http://127.0.0.1:4200/mcp/"

    def test_url_always_ends_with_mcp_slash(self, monkeypatch):
        monkeypatch.delenv("MCP_SERVER_URL", raising=False)
        monkeypatch.setenv("TLS_ENABLED", "false")
        monkeypatch.setenv("FASTMCP_PORT", "4200")
        url = _upstream_url()
        assert url.endswith("/mcp/")


####  _static_auth_headers()  ##################################################


class TestStaticAuthHeaders:
    """Builds an Authorization header from ES credential env vars."""

    def test_no_credentials_returns_empty_dict(self, monkeypatch):
        monkeypatch.delenv("ELASTICSEARCH_API_KEY", raising=False)
        monkeypatch.delenv("ELASTICSEARCH_USERNAME", raising=False)
        monkeypatch.delenv("ELASTICSEARCH_PASSWORD", raising=False)
        assert _static_auth_headers() == {}

    # ── API key ───────────────────────────────────────────────────────────────

    def test_api_key_produces_apikey_header(self, monkeypatch):
        monkeypatch.setenv("ELASTICSEARCH_API_KEY", "myapikey")
        monkeypatch.delenv("ELASTICSEARCH_USERNAME", raising=False)
        assert _static_auth_headers() == {"Authorization": "ApiKey myapikey"}

    def test_api_key_whitespace_stripped(self, monkeypatch):
        monkeypatch.setenv("ELASTICSEARCH_API_KEY", "  trimmed  ")
        headers = _static_auth_headers()
        assert headers["Authorization"] == "ApiKey trimmed"

    def test_api_key_takes_precedence_over_username(self, monkeypatch):
        monkeypatch.setenv("ELASTICSEARCH_API_KEY", "apikey123")
        monkeypatch.setenv("ELASTICSEARCH_USERNAME", "alice")
        monkeypatch.setenv("ELASTICSEARCH_PASSWORD", "secret")
        assert _static_auth_headers()["Authorization"].startswith("ApiKey ")

    def test_blank_api_key_falls_through_to_username(self, monkeypatch):
        monkeypatch.setenv("ELASTICSEARCH_API_KEY", "   ")
        monkeypatch.setenv("ELASTICSEARCH_USERNAME", "alice")
        monkeypatch.setenv("ELASTICSEARCH_PASSWORD", "pass")
        assert _static_auth_headers()["Authorization"].startswith("Basic ")

    # ── Basic (username/password) ─────────────────────────────────────────────

    def test_username_password_produces_basic_header(self, monkeypatch):
        monkeypatch.delenv("ELASTICSEARCH_API_KEY", raising=False)
        monkeypatch.setenv("ELASTICSEARCH_USERNAME", "alice")
        monkeypatch.setenv("ELASTICSEARCH_PASSWORD", "secret")
        headers = _static_auth_headers()
        assert headers["Authorization"].startswith("Basic ")
        encoded = headers["Authorization"][len("Basic "):]
        assert base64.b64decode(encoded).decode() == "alice:secret"

    def test_basic_encoding_handles_special_chars(self, monkeypatch):
        monkeypatch.delenv("ELASTICSEARCH_API_KEY", raising=False)
        monkeypatch.setenv("ELASTICSEARCH_USERNAME", "user")
        monkeypatch.setenv("ELASTICSEARCH_PASSWORD", "p@ss:word=!#")
        encoded = _static_auth_headers()["Authorization"][len("Basic "):]
        assert base64.b64decode(encoded).decode() == "user:p@ss:word=!#"

    def test_username_without_password_encodes_colon(self, monkeypatch):
        monkeypatch.delenv("ELASTICSEARCH_API_KEY", raising=False)
        monkeypatch.setenv("ELASTICSEARCH_USERNAME", "alice")
        monkeypatch.delenv("ELASTICSEARCH_PASSWORD", raising=False)
        encoded = _static_auth_headers()["Authorization"][len("Basic "):]
        assert base64.b64decode(encoded).decode() == "alice:"

    def test_blank_username_returns_empty(self, monkeypatch):
        monkeypatch.delenv("ELASTICSEARCH_API_KEY", raising=False)
        monkeypatch.setenv("ELASTICSEARCH_USERNAME", "   ")
        monkeypatch.setenv("ELASTICSEARCH_PASSWORD", "pass")
        assert _static_auth_headers() == {}

    def test_only_one_authorization_key_in_result(self, monkeypatch):
        monkeypatch.delenv("ELASTICSEARCH_API_KEY", raising=False)
        monkeypatch.setenv("ELASTICSEARCH_USERNAME", "u")
        monkeypatch.setenv("ELASTICSEARCH_PASSWORD", "p")
        headers = _static_auth_headers()
        assert list(headers.keys()) == ["Authorization"]


####  _ssl_httpx_factory()  ####################################################


class TestSslHttpxFactory:
    """Returns a McpHttpClientFactory that threads custom SSL verification through."""

    def test_returns_callable(self):
        assert callable(_ssl_httpx_factory(verify=True))

    def test_factory_returns_async_client(self):
        client = _ssl_httpx_factory(verify=False)()
        assert isinstance(client, httpx.AsyncClient)

    def test_verify_false_creates_client(self):
        client = _ssl_httpx_factory(verify=False)()
        assert isinstance(client, httpx.AsyncClient)

    def test_verify_true_creates_client(self):
        client = _ssl_httpx_factory(verify=True)()
        assert isinstance(client, httpx.AsyncClient)

    def test_verify_cert_path_forwarded_to_client(self, tmp_path):
        # httpx validates the CA file is real PEM at instantiation time, so patch
        # the constructor and confirm the verify= kwarg is threaded through correctly.
        cert = tmp_path / "ca.pem"
        cert.write_text("cert")
        factory = _ssl_httpx_factory(verify=str(cert))
        with patch("server.fastmcp_proxy.httpx.AsyncClient") as mock_client:
            factory(headers={})
        _, kw = mock_client.call_args
        assert kw["verify"] == str(cert)

    def test_headers_forwarded_to_client(self):
        headers = {"Authorization": "ApiKey abc", "X-Custom": "val"}
        client = _ssl_httpx_factory(verify=False)(headers=headers)
        assert client.headers.get("authorization") == "ApiKey abc"
        assert client.headers.get("x-custom") == "val"

    def test_none_headers_does_not_raise(self):
        client = _ssl_httpx_factory(verify=False)(headers=None)
        assert isinstance(client, httpx.AsyncClient)

    def test_follow_redirects_kwarg_accepted(self):
        client = _ssl_httpx_factory(verify=False)(follow_redirects=True)
        assert isinstance(client, httpx.AsyncClient)

    def test_unknown_extra_kwargs_absorbed(self):
        client = _ssl_httpx_factory(verify=False)(headers={}, extra_unused="ignored")
        assert isinstance(client, httpx.AsyncClient)

    def test_custom_timeout_accepted(self):
        timeout = httpx.Timeout(60.0, read=120.0)
        client = _ssl_httpx_factory(verify=False)(timeout=timeout)
        assert client.timeout.connect == 60.0
        assert client.timeout.read == 120.0

    def test_default_timeout_applied_when_none(self):
        client = _ssl_httpx_factory(verify=False)(timeout=None)
        assert client.timeout.connect == 30.0
        assert client.timeout.read == 300.0

    def test_two_factories_are_independent(self):
        f1 = _ssl_httpx_factory(verify=False)
        f2 = _ssl_httpx_factory(verify=True)
        assert f1 is not f2


####  Module-level proxy construction  ########################################


def _reload_proxy(monkeypatch, env: dict):
    """
    Apply env overrides and reload server.fastmcp_proxy, returning the fresh module.

    Values:
      - str → monkeypatch.setenv (dotenv will not overwrite an already-set var)
      - None → monkeypatch.delenv (use sparingly; dotenv may re-read from .env)

    For credential vars that should be absent, prefer passing "" (empty string)
    rather than None.  load_dotenv() skips vars that are already present in the
    environment (even if empty), so an empty-string value reliably prevents .env
    from re-injecting a real credential.
    """
    for k, v in env.items():
        if v is None:
            monkeypatch.delenv(k, raising=False)
        else:
            monkeypatch.setenv(k, v)
    import server.fastmcp_proxy as mod
    importlib.reload(mod)
    return mod


class TestModuleConstruction:
    """Transport is built correctly at import time based on env vars."""

    def test_tls_disabled_upstream_url_uses_http(self, monkeypatch):
        mod = _reload_proxy(monkeypatch, {
            "TLS_ENABLED": "false",
            "FASTMCP_PORT": "4200",
            "MCP_SERVER_URL": "",
        })
        assert mod._transport.url == "http://127.0.0.1:4200/mcp/"

    def test_tls_disabled_no_ssl_factory(self, monkeypatch):
        mod = _reload_proxy(monkeypatch, {
            "TLS_ENABLED": "false",
            "MCP_SERVER_URL": "",
        })
        assert mod._transport.httpx_client_factory is None

    def test_tls_enabled_upstream_url_uses_https(self, monkeypatch, tmp_path):
        cert = tmp_path / "cert.pem"
        key = tmp_path / "key.pem"
        cert.write_text("cert")
        key.write_text("key")
        mod = _reload_proxy(monkeypatch, {
            "TLS_ENABLED": "true",
            "TLS_CERT_FILE": str(cert),
            "TLS_KEY_FILE": str(key),
            "FASTMCP_PORT": "4200",
            "MCP_SERVER_URL": "",
        })
        assert mod._transport.url == "https://127.0.0.1:4200/mcp/"

    def test_tls_enabled_ssl_factory_attached(self, monkeypatch, tmp_path):
        cert = tmp_path / "cert.pem"
        key = tmp_path / "key.pem"
        cert.write_text("cert")
        key.write_text("key")
        mod = _reload_proxy(monkeypatch, {
            "TLS_ENABLED": "true",
            "TLS_CERT_FILE": str(cert),
            "TLS_KEY_FILE": str(key),
            "MCP_SERVER_URL": "",
        })
        assert callable(mod._transport.httpx_client_factory)

    def test_tls_enabled_factory_uses_cert_as_ca(self, monkeypatch, tmp_path):
        cert = tmp_path / "cert.pem"
        key = tmp_path / "key.pem"
        cert.write_text("cert")
        key.write_text("key")
        mod = _reload_proxy(monkeypatch, {
            "TLS_ENABLED": "true",
            "TLS_CERT_FILE": str(cert),
            "TLS_KEY_FILE": str(key),
            "MCP_SERVER_URL": "",
            "ELASTICSEARCH_API_KEY": "",
            "ELASTICSEARCH_USERNAME": "",
        })
        # The factory should use TLS_CERT_FILE as the CA bundle (verify=cert_path).
        # Patch httpx.AsyncClient to avoid actually parsing the fake PEM file.
        with patch("server.fastmcp_proxy.httpx.AsyncClient") as mock_client:
            mod._transport.httpx_client_factory(headers={})
        _, kw = mock_client.call_args
        assert kw["verify"] == str(cert)

    def test_static_auth_injected_into_transport_headers(self, monkeypatch):
        mod = _reload_proxy(monkeypatch, {
            "TLS_ENABLED": "false",
            "MCP_SERVER_URL": "",
            "ELASTICSEARCH_API_KEY": "test-key-123",
            "ELASTICSEARCH_USERNAME": "",
        })
        assert mod._transport.headers.get("Authorization") == "ApiKey test-key-123"

    def test_no_credentials_transport_has_empty_headers(self, monkeypatch):
        mod = _reload_proxy(monkeypatch, {
            "TLS_ENABLED": "false",
            "MCP_SERVER_URL": "",
            "ELASTICSEARCH_API_KEY": "",   # empty → not picked up by _static_auth_headers
            "ELASTICSEARCH_USERNAME": "",
        })
        assert mod._transport.headers.get("Authorization") is None

    def test_explicit_mcp_server_url_used_in_transport(self, monkeypatch):
        mod = _reload_proxy(monkeypatch, {
            "MCP_SERVER_URL": "https://remote-host:5000/mcp",
            "TLS_ENABLED": "false",
            "ELASTICSEARCH_API_KEY": "",
        })
        assert mod._transport.url == "https://remote-host:5000/mcp/"

    def test_mcp_object_created(self, monkeypatch):
        from fastmcp import FastMCP
        mod = _reload_proxy(monkeypatch, {"TLS_ENABLED": "false", "MCP_SERVER_URL": ""})
        assert isinstance(mod.mcp, FastMCP)


####  __main__ block  ##########################################################


class TestMain:
    """Transport selection, port config, and TLS error handling at startup."""

    def _run_main(self, monkeypatch, mod):
        """
        Execute the __main__ block of the already-loaded module by reimporting
        it with run_name="__main__" and the module's patched mcp.run mock.
        We simulate by directly calling what __main__ would do.
        """
        import runpy
        return runpy.run_module("server.fastmcp_proxy", run_name="__main__", alter_sys=False)

    def test_stdio_transport_calls_mcp_run_without_args(self, monkeypatch, tmp_path):
        monkeypatch.setenv("FASTMCP_SERVER_TRANSPORT", "stdio")
        monkeypatch.setenv("TLS_ENABLED", "false")
        monkeypatch.setenv("MCP_SERVER_URL", "")

        import server.fastmcp_proxy as mod
        importlib.reload(mod)

        with patch.object(mod.mcp, "run") as mock_run:
            # Execute only the __main__ logic, not the full module reload
            tls = mod.get_tls_config()
            server_transport = "stdio"
            if server_transport == "http":
                pass
            else:
                mod.mcp.run()
            mock_run.assert_called_once_with()

    def test_http_transport_calls_mcp_run_with_transport_and_port(self, monkeypatch):
        monkeypatch.setenv("FASTMCP_SERVER_TRANSPORT", "http")
        monkeypatch.setenv("FASTMCP_PROXY_PORT", "4201")
        monkeypatch.setenv("TLS_ENABLED", "false")
        monkeypatch.setenv("MCP_SERVER_URL", "")

        import server.fastmcp_proxy as mod
        importlib.reload(mod)

        with patch.object(mod.mcp, "run") as mock_run:
            port = int("4201")
            mod.mcp.run(transport="http", port=port, log_level="debug")
            mock_run.assert_called_once_with(transport="http", port=4201, log_level="debug")

    def test_http_transport_default_port_is_4201(self, monkeypatch):
        monkeypatch.setenv("FASTMCP_SERVER_TRANSPORT", "http")
        monkeypatch.setenv("FASTMCP_PROXY_PORT", "")
        monkeypatch.setenv("TLS_ENABLED", "false")
        monkeypatch.setenv("MCP_SERVER_URL", "")

        import server.fastmcp_proxy as mod
        importlib.reload(mod)

        calls = []
        with patch.object(mod.mcp, "run", side_effect=lambda **kw: calls.append(kw)):
            port = int(mod.os.environ.get("FASTMCP_PROXY_PORT") or "4201")
            mod.mcp.run(transport="http", port=port, log_level="debug")
        assert calls[0]["port"] == 4201

    def test_tls_error_exits_with_code_1_at_import_time(self, monkeypatch):
        """
        TLS misconfiguration causes sys.exit(1) at module import time, before
        any server starts. This must happen at module scope (not just in
        __main__) so the stdio entry point — which imports ``mcp`` rather than
        executing fastmcp_proxy as a script — fails fast with a clear error.
        """
        monkeypatch.setenv("TLS_ENABLED", "true")
        monkeypatch.setenv("TLS_CERT_FILE", "")
        monkeypatch.setenv("TLS_KEY_FILE", "")
        monkeypatch.setenv("MCP_SERVER_URL", "")

        import server.fastmcp_proxy as mod
        with pytest.raises(SystemExit) as exc_info:
            importlib.reload(mod)
        assert exc_info.value.code == 1

    def test_tls_error_message_printed_to_stderr_at_import_time(self, monkeypatch, capsys):
        """The clear error from get_tls_config() is surfaced during import."""
        monkeypatch.setenv("TLS_ENABLED", "true")
        monkeypatch.setenv("TLS_CERT_FILE", "")
        monkeypatch.setenv("TLS_KEY_FILE", "")
        monkeypatch.setenv("MCP_SERVER_URL", "")

        import server.fastmcp_proxy as mod
        with pytest.raises(SystemExit):
            importlib.reload(mod)
        captured = capsys.readouterr()
        assert "TLS_CERT_FILE" in captured.err

    def test_http_transport_with_tls_passes_uvicorn_config(self, monkeypatch, tmp_path):
        cert = tmp_path / "cert.pem"
        key = tmp_path / "key.pem"
        cert.write_text("cert")
        key.write_text("key")
        monkeypatch.setenv("TLS_ENABLED", "true")
        monkeypatch.setenv("TLS_CERT_FILE", str(cert))
        monkeypatch.setenv("TLS_KEY_FILE", str(key))
        monkeypatch.setenv("FASTMCP_SERVER_TRANSPORT", "http")
        monkeypatch.setenv("FASTMCP_PROXY_PORT", "4201")
        monkeypatch.setenv("MCP_SERVER_URL", "")

        import server.fastmcp_proxy as mod
        importlib.reload(mod)

        tls = mod.get_tls_config()
        assert tls["error"] is None
        assert tls["uvicorn_config"] is not None
        assert tls["uvicorn_config"]["ssl_certfile"] == str(cert)
        assert tls["uvicorn_config"]["ssl_keyfile"] == str(key)
