# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""
Central TLS configuration loader for Relevance Studio servers.

Environment variables:
- TLS_ENABLED: "true" or "false" (default: "true")
- TLS_CERT_FILE: Path to PEM certificate file (required when TLS_ENABLED=true)
- TLS_KEY_FILE: Path to PEM private key file (required when TLS_ENABLED=true)

When TLS_ENABLED is true, both TLS_CERT_FILE and TLS_KEY_FILE must be set and
the files must exist. Otherwise startup fails with a clear error message.
"""

# Standard packages
import os
import sys
from typing import Any, Dict, Optional, Tuple

# Third-party packages
from dotenv import load_dotenv

load_dotenv()


def _strip_env(value: Optional[str]) -> str:
    """
    Normalize an env var value: strip whitespace and a single matching pair of
    surrounding quotes. Some env_file parsers (notably older docker compose
    versions) preserve quotes verbatim, which would silently break boolean and
    path parsing downstream.
    """
    if value is None:
        return ""
    v = value.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in ("'", '"'):
        v = v[1:-1].strip()
    return v


def _parse_bool(value: Optional[str], default: bool = True) -> bool:
    """Parse a string as boolean. Default when empty/None."""
    v = _strip_env(value)
    if v == "":
        return default
    return v.lower() in ("1", "true", "yes", "on")


def get_tls_config() -> Dict[str, Any]:
    """
    Load TLS configuration from environment.

    Returns:
        Dict with:
        - enabled: bool
        - ssl_context: Optional[Tuple[str, str]] - (cert_path, key_path) for Flask/werkzeug
        - uvicorn_config: Optional[Dict] - ssl_certfile/ssl_keyfile for FastMCP/uvicorn
        - error: Optional[str] - clear error message when config is invalid
    """
    enabled = _parse_bool(os.environ.get("TLS_ENABLED"), default=True)
    cert_file = _strip_env(os.environ.get("TLS_CERT_FILE"))
    key_file = _strip_env(os.environ.get("TLS_KEY_FILE"))

    if not enabled:
        return {
            "enabled": False,
            "ssl_context": None,
            "uvicorn_config": None,
            "error": None,
        }

    # TLS enabled: require both vars
    if not cert_file:
        return {
            "enabled": True,
            "ssl_context": None,
            "uvicorn_config": None,
            "error": "TLS_ENABLED is true but TLS_CERT_FILE is not set. Set TLS_CERT_FILE to the path of your PEM certificate, or set TLS_ENABLED=false to disable TLS.",
        }
    if not key_file:
        return {
            "enabled": True,
            "ssl_context": None,
            "uvicorn_config": None,
            "error": "TLS_ENABLED is true but TLS_KEY_FILE is not set. Set TLS_KEY_FILE to the path of your PEM private key, or set TLS_ENABLED=false to disable TLS.",
        }

    # Require files to exist
    if not os.path.isfile(cert_file):
        return {
            "enabled": True,
            "ssl_context": None,
            "uvicorn_config": None,
            "error": f"TLS_CERT_FILE does not exist or is not a file: {cert_file}. Provide a valid PEM certificate path or set TLS_ENABLED=false.",
        }
    if not os.path.isfile(key_file):
        return {
            "enabled": True,
            "ssl_context": None,
            "uvicorn_config": None,
            "error": f"TLS_KEY_FILE does not exist or is not a file: {key_file}. Provide a valid PEM key path or set TLS_ENABLED=false.",
        }

    ssl_context: Tuple[str, str] = (cert_file, key_file)
    uvicorn_config = {"ssl_certfile": cert_file, "ssl_keyfile": key_file}

    return {
        "enabled": True,
        "ssl_context": ssl_context,
        "uvicorn_config": uvicorn_config,
        "error": None,
    }


def log_tls_status(service: str, host: str, port: int, tls: Dict[str, Any]) -> None:
    """
    Print an unambiguous startup line describing the actual TLS state.

    FastMCP's own banner hardcodes ``http://`` regardless of whether TLS is
    configured, which makes it easy to misdiagnose a working HTTPS server as
    HTTP. Callers should invoke this just before starting the server so the
    log clearly reflects the resolved scheme and source of the cert files.
    """
    scheme = "https" if tls.get("enabled") and tls.get("ssl_context") else "http"
    raw = os.environ.get("TLS_ENABLED")
    if raw is None:
        source = "unset (default: true)"
    else:
        source = f"{raw!r}"
    cert = tls.get("ssl_context", (None, None))[0] if tls.get("ssl_context") else None
    key = tls.get("ssl_context", (None, None))[1] if tls.get("ssl_context") else None
    print(
        f"[{service}] TLS_ENABLED={source} -> serving on {scheme}://{host}:{port}"
        + (f" (cert={cert}, key={key})" if cert and key else ""),
        file=sys.stderr,
        flush=True,
    )
