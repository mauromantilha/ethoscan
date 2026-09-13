from __future__ import annotations

from app.adapters.base import RawFinding
from app.models import Severity


_RANK = {
    Severity.info: 1,
    Severity.low: 2,
    Severity.medium: 3,
    Severity.high: 4,
    Severity.critical: 5,
}


def correlate(findings: list[RawFinding]) -> list[RawFinding]:
    """Deduplicate by fingerprint and keep the highest severity copy."""
    best: dict[str, RawFinding] = {}
    for item in findings:
        key = item.fingerprint()
        current = best.get(key)
        if current is None or _RANK[item.severity] > _RANK[current.severity]:
            best[key] = item
    ordered = sorted(best.values(), key=lambda f: (-_RANK[f.severity], f.title))
    return ordered
