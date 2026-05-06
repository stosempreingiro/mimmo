from dataclasses import dataclass, asdict, field
from typing import Tuple


@dataclass(frozen=True)
class Finding:
    """A single discovery from a detector.

    Frozen so instances are hashable (we use them in sets for dedup).

    Attributes:
        type:        Stable machine-readable identifier of the rule that fired
                     (e.g. "google_api_key", "manifest_debuggable", "url").
        value:       The matched string. Truncated by detectors when very long.
        source:      Path *inside* the APK (e.g. "classes.dex",
                     "assets/config.json"). For directory scans this stays
                     relative to the APK so output is comparable across runs.
                     After source-collapsing this is the *first* source where
                     the value was found; the full list lives in ``sources``.
        apk:         Absolute path to the APK file the finding came from.
        confidence:  0.0 - 1.0. Higher means the rule is unlikely to false-
                     positive. Use this to triage and to filter via
                     ``--min-confidence``.
        category:    Coarse grouping for reporting: ``secret``, ``url``,
                     ``misconfig``.
        description: Short human-readable explanation, useful in JSON output.
        sources:     Empty when the finding has a single source (use ``source``
                     instead). Populated by source-collapsing dedup with the
                     full list of locations where this (type, value) was
                     observed in the same APK. Keeps evidence intact for
                     report writeup without flooding the table.
    """

    type: str
    value: str
    source: str
    apk: str
    confidence: float
    category: str = ""
    description: str = ""
    sources: Tuple[str, ...] = ()

    def dedup_key(self) -> Tuple[str, str, str, str]:
        """Key used to deduplicate identical findings (same source).

        For source-collapsing dedup (one row per (type, value, apk)
        regardless of where it was found), see :func:`collapse_key`.
        """
        return (self.type, self.value, self.source, self.apk)

    def collapse_key(self) -> Tuple[str, str, str]:
        """Key used to collapse the same (type, value) across many sources."""
        return (self.type, self.value, self.apk)

    def to_dict(self) -> dict:
        d = asdict(self)
        # Keep JSON tidy: drop the empty `sources` tuple for findings
        # that came from a single source.
        if not self.sources:
            d.pop("sources", None)
        else:
            d["sources"] = list(self.sources)
        return d
