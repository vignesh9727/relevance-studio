# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""
Standalone entry point for MCP clients that use stdio transport (e.g. Claude Desktop).

fastmcp_proxy.py uses package-relative imports (from .tls import ...) which
require it to be imported as part of the ``server`` package.  Running it
directly as a top-level script fails with:

    ImportError: attempted relative import with no known parent package

This file resolves that by inserting the ``src/`` directory onto sys.path
before importing from the ``server`` package, making it safe to run as a
standalone script regardless of the working directory.

────────────────────────────────────────────────────────────────────────────────
Install in Claude Desktop
────────────────────────────────────────────────────────────────────────────────
From the project root, run:

    python scripts/integrate_claude_desktop.py

This reads .env and writes the correct entry into Claude Desktop's config
automatically. Re-run whenever .env changes, then restart Claude Desktop.

See docs/{{VERSION}}/guide/mcp-client-auth.md for full configuration details.
────────────────────────────────────────────────────────────────────────────────
"""

import os
import sys

# Make the ``server`` package importable regardless of the working directory
# when Claude Desktop launches this script.  __file__ is always the absolute
# path to this file (src/fastmcp_proxy_entry.py), so dirname gives src/.
_src_dir = os.path.dirname(os.path.abspath(__file__))
if _src_dir not in sys.path:
    sys.path.insert(0, _src_dir)

from server.fastmcp_proxy import mcp  # noqa: E402

if __name__ == "__main__":
    mcp.run()
