"""
Risk level of an AI report, worked out from its structured findings.

Agents are asked to return findings like
    {"attack_vectors": [{"name": ..., "severity": "High", ...}, ...]}
Severity words vary between models, so they are normalised here.
"""

LEVELS = ("critical", "high", "medium", "low")  # most severe first

_ALIASES = {
    "critical": "critical", "crit": "critical", "p0": "critical",
    "high": "high", "severe": "high", "p1": "high",
    "medium": "medium", "moderate": "medium", "med": "medium", "p2": "medium",
    "low": "low", "minor": "low", "info": "low", "informational": "low", "p3": "low",
}


def _normalise(severity) -> str | None:
    if severity is None:
        return None
    word = str(severity).strip().lower().split()[0] if str(severity).strip() else ""
    return _ALIASES.get(word)


def risk_summary(findings) -> dict:
    """
    {"level": "critical|high|medium|low|none|''", "counts": {level: n}, "total": n}
    level "" means the report has no attack_vectors list (not assessed).
    """
    vectors = findings.get("attack_vectors") if isinstance(findings, dict) else None
    counts = {level: 0 for level in LEVELS}
    if not isinstance(vectors, list):
        return {"level": "", "counts": counts, "total": 0}
    for vector in vectors:
        if isinstance(vector, dict):
            # Models name this field differently (Nemotron uses "rating")
            level = _normalise(next(
                (vector.get(k) for k in ("severity", "rating", "risk", "level", "priority") if vector.get(k)),
                None,
            ))
            if level:
                counts[level] += 1
    total = sum(counts.values())
    level = next((lvl for lvl in LEVELS if counts[lvl]), "none")
    return {"level": level, "counts": counts, "total": total}
