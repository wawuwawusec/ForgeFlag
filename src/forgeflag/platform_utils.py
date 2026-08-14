"""Cross-platform helpers for commands ForgeFlag suggests to operators."""

from __future__ import annotations

import sys


def script_invocation(script: str, *args: str) -> str:
    """Return an executable command line for a repo script on the current platform.

    POSIX systems can exec the shebang scripts directly; Windows needs the
    interpreter spelled out.
    """
    path = f"scripts/{script}"
    if sys.platform == "win32":
        parts = [sys.executable or "python", path.replace("/", "\\")]
    else:
        parts = [path]
    parts.extend(args)
    return " ".join(parts)
