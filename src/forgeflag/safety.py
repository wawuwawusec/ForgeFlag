from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse


class ScopeError(ValueError):
    pass


@dataclass(frozen=True)
class ScopePolicy:
    allowed_hosts: tuple[str, ...] = ()
    active_probe: bool = False

    def require_active_allowed(self, target: str | None) -> None:
        if not self.active_probe:
            raise ScopeError("active probing is disabled; pass --active-probe to enable scoped probes")
        self.require_target_allowed(target)

    def require_target_allowed(self, target: str | None) -> None:
        if not target:
            raise ScopeError("target is required for scoped tool use")
        host = host_from_target(target)
        if host not in set(self.allowed_hosts):
            allowed = ", ".join(self.allowed_hosts) or "<none>"
            raise ScopeError(f"target host {host!r} is outside allowed scope: {allowed}")


def host_from_target(target: str) -> str:
    parsed = urlparse(target)
    if parsed.hostname:
        return parsed.hostname
    return target.split("/")[0].split(":")[0]

