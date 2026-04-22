# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""
Unit tests for the standalone Claude Desktop entry point (fastmcp_proxy_entry.py).

The entry point exists so that `fastmcp install claude-desktop` can target a
plain script file rather than a package module, sidestepping the relative-import
constraint that prevents running fastmcp_proxy.py directly.
"""

import importlib
import os
import sys

import pytest
from fastmcp import FastMCP
from unittest.mock import patch


####  Helpers  #################################################################

def _import_entry(monkeypatch, env: dict | None = None):
    """
    Apply env overrides, then import/reload fastmcp_proxy_entry.
    Uses empty-string values (not deletion) for credential vars so that
    load_dotenv() inside the proxy module does not re-inject real credentials
    from .env.
    """
    defaults = {
        "TLS_ENABLED": "false",
        "MCP_SERVER_URL": "",
        "ELASTICSEARCH_API_KEY": "",
        "ELASTICSEARCH_USERNAME": "",
    }
    merged = {**defaults, **(env or {})}
    for k, v in merged.items():
        if v is None:
            monkeypatch.delenv(k, raising=False)
        else:
            monkeypatch.setenv(k, v)

    import fastmcp_proxy_entry as mod
    importlib.reload(mod)
    return mod


####  sys.path injection  ######################################################


class TestSysPathInjection:
    """src/ is added to sys.path so the server package is importable."""

    def test_src_dir_is_on_sys_path_after_import(self, monkeypatch):
        mod = _import_entry(monkeypatch)
        src_dir = os.path.dirname(os.path.abspath(mod.__file__))
        assert src_dir in sys.path

    def test_src_dir_not_duplicated_on_repeated_import(self, monkeypatch):
        _import_entry(monkeypatch)
        _import_entry(monkeypatch)
        import fastmcp_proxy_entry as mod
        src_dir = os.path.dirname(os.path.abspath(mod.__file__))
        assert sys.path.count(src_dir) == 1

    def test_server_package_importable_after_entry_import(self, monkeypatch):
        _import_entry(monkeypatch)
        # If src/ is on path, this import must not raise.
        import server  # noqa: F401


####  mcp object  ##############################################################


class TestMcpObject:
    """The entry point exposes the same mcp proxy object as fastmcp_proxy."""

    def test_mcp_is_fastmcp_instance(self, monkeypatch):
        mod = _import_entry(monkeypatch)
        assert isinstance(mod.mcp, FastMCP)

    def test_mcp_is_same_object_as_proxy_module(self, monkeypatch):
        # _import_entry reloads the entry module which runs
        # `from server.fastmcp_proxy import mcp`.  After that,
        # server.fastmcp_proxy is already in sys.modules, so importing
        # it here returns the same module — and the same mcp object.
        mod = _import_entry(monkeypatch)
        import server.fastmcp_proxy as proxy
        assert mod.mcp is proxy.mcp

    def test_mcp_named_relevance_studio(self, monkeypatch):
        mod = _import_entry(monkeypatch)
        assert mod.mcp.name == "Relevance Studio"


####  __main__ block  ##########################################################


class TestMainBlock:
    """Running the entry point as __main__ delegates to mcp.run()."""

    def test_main_calls_mcp_run(self, monkeypatch):
        mod = _import_entry(monkeypatch)
        with patch.object(mod.mcp, "run") as mock_run:
            mod.mcp.run()
        mock_run.assert_called_once_with()

    def test_main_block_calls_run_without_transport_arg(self, monkeypatch):
        """Entry point always uses default (stdio) transport — no transport= kwarg."""
        mod = _import_entry(monkeypatch)
        calls = []
        with patch.object(mod.mcp, "run", side_effect=lambda **kw: calls.append(kw)):
            mod.mcp.run()
        assert calls == [{}]
