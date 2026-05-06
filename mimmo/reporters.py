"""Output formatters: JSON (machine-readable) and ANSI table (default)."""

from __future__ import annotations

import json
import os
import sys
from typing import Dict, List, TextIO

from . import __version__
from .finding import Finding



_USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")

_BOLD, _DIM = "1", "2"
_RED, _YELLOW, _GREEN, _CYAN, _MAGENTA = "31", "33", "32", "36", "35"
_BOLD_RED = "1;31"  # used for top-level malware verdicts


def _c(code: str, s: str) -> str:
    if not _USE_COLOR:
        return s
    return f"\x1b[{code}m{s}\x1b[0m"


# -----
# JSON
# ------


def write_json(findings: List[Finding], out: TextIO, pretty: bool = True) -> None:
    """Write findings as a single JSON document with metadata wrapper."""
    payload = {
        "tool": "mimmo",
        "version": __version__,
        "count": len(findings),
        "findings": [f.to_dict() for f in findings],
    }
    if pretty:
        json.dump(payload, out, indent=2, ensure_ascii=False)
    else:
        json.dump(payload, out, ensure_ascii=False)
    out.write("\n")


# -----
# Table
# ------


def _confidence_color(c: float) -> str:
    if c >= 0.85:
        return _RED
    if c >= 0.6:
        return _YELLOW
    return _GREEN


def _category_color(category: str) -> str:
    return {
        "secret": _RED,
        "misconfig": _YELLOW,
        "url": _CYAN,
        "verdict": _BOLD_RED,
    }.get(category, _MAGENTA)


def _shorten(s: str, n: int) -> str:
    s = s.replace("\n", "\\n").replace("\r", "").replace("\t", " ")
    if len(s) <= n:
        return s
    return s[: n - 3] + "..."


def write_table(findings: List[Finding], out: TextIO) -> None:
    """Pretty-print findings grouped by APK as ASCII tables.

    Columns: TYPE | VALUE | SOURCE | CONF
    Sorted within each APK by confidence descending, then by type.
    """
    if not findings:
        out.write(_c(_DIM, "No findings.\n"))
        return

    # Group by APK so the user can see the per-file picture at a glance.
    by_apk: Dict[str, List[Finding]] = {}
    for f in findings:
        by_apk.setdefault(f.apk, []).append(f)

    headers = ["TYPE", "VALUE", "SOURCE", "CONF"]
    total_secret = sum(1 for f in findings if f.category == "secret")
    total_url = sum(1 for f in findings if f.category == "url")
    total_misc = sum(1 for f in findings if f.category == "misconfig")
    total_verdict = sum(1 for f in findings if f.category == "verdict")

    for apk, items in by_apk.items():
        out.write(
            "\n"
            + _c(_BOLD, f"== {apk} ")
            + _c(_DIM, f"({len(items)} findings) ==")
            + "\n"
        )
        rows: List[List[str]] = []
        plain_rows: List[List[str]] = []
        # Sort: verdicts first (always at the top, attention-grabbing),
        # then by confidence descending, then by type for stability.
        def sort_key(x):
            verdict_priority = 0 if x.category == "verdict" else 1
            return (verdict_priority, -x.confidence, x.type)
        for f in sorted(items, key=sort_key):
            type_cell = _c(_category_color(f.category), f.type)
            conf_cell = _c(_confidence_color(f.confidence), f"{f.confidence:.2f}")
            # When the same (type, value) was collapsed across multiple
            # sources, append a `(+N more)` note so the user knows the
            # finding has wider scope than a single file.
            if f.sources and len(f.sources) > 1:
                source_display = f"{f.source} (+{len(f.sources)-1} more)"
            else:
                source_display = f.source
            rows.append([
                type_cell,
                _shorten(f.value, 60),
                _shorten(source_display, 40),
                conf_cell,
            ])
            # Plain version is used to compute column widths (ANSI codes
            # are invisible but make len() lie).
            plain_rows.append([
                f.type,
                _shorten(f.value, 60),
                _shorten(source_display, 40),
                f"{f.confidence:.2f}",
            ])
        _write_grid(out, headers, rows, plain_rows)

    summary_parts = [
        _c(_BOLD, "Summary: "),
        f"{len(findings)} findings  ",
        _c(_RED, f"secrets={total_secret}") + "  ",
        _c(_YELLOW, f"misconfigs={total_misc}") + "  ",
        _c(_CYAN, f"urls={total_url}"),
    ]
    if total_verdict > 0:
        summary_parts.append("  " + _c(_BOLD_RED, f"verdicts={total_verdict}"))
    out.write("\n" + "".join(summary_parts) + "\n")


def _write_grid(
    out: TextIO,
    headers: List[str],
    rows: List[List[str]],
    plain_rows: List[List[str]],
) -> None:
    """Render an ASCII grid. Widths are computed from ANSI-stripped cells."""
    widths = [len(h) for h in headers]
    for r in plain_rows:
        for i, cell in enumerate(r):
            if len(cell) > widths[i]:
                widths[i] = len(cell)

    sep = "+" + "+".join("-" * (w + 2) for w in widths) + "+"

    def _fmt(cells: List[str], plain: List[str], bold: bool = False) -> str:
        parts = []
        for i, cell in enumerate(cells):
            pad = widths[i] - len(plain[i] if plain else cell)
            parts.append(" " + cell + " " * pad + " ")
        line = "|" + "|".join(parts) + "|"
        return _c(_BOLD, line) if bold else line

    out.write(sep + "\n")
    out.write(_fmt(headers, headers, bold=True) + "\n")
    out.write(sep + "\n")
    for r, p in zip(rows, plain_rows):
        out.write(_fmt(r, p) + "\n")
    out.write(sep + "\n")
