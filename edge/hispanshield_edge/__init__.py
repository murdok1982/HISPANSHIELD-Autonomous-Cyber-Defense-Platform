"""HISPANSHIELD edge gateway agent.

The agent is a standalone, dependency-light Python package that enrolls a site
gateway against the HISPANSHIELD core, keeps telemetry in a crash-safe SQLite
queue and ships signed batches over HTTPS with store-and-forward semantics.
"""

from __future__ import annotations

__all__ = ["AGENT_VERSION", "__version__"]

AGENT_VERSION = "0.1.0"
__version__ = AGENT_VERSION
