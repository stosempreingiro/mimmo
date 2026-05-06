from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__, reporters
from .core import Scanner, dedupe, collapse_sources, derive_verdicts
from .finding import Finding


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mimmo",
        description=(
            "MIMMO - Mobile Inspector for Misconfigurations & Data Mining. "
            "Lightweight static analyzer for Android APK/APKX files."
        ),
        epilog=(
            "Examples:\n"
            "  mimmo scan app.apk\n"
            "  mimmo scan ./apps --json output.json\n"
            "  mimmo scan app.apk --json - --no-table   # JSON to stdout\n"
            "  mimmo scan ./apps --min-confidence 0.8 -v\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # ---- scan -----
    scan = sub.add_parser(
        "scan",
        help="Scan an APK file or directory",
        description="Scan an APK/APKX file, or a directory containing APKs (recursive).",
    )
    scan.add_argument("target", help="APK/APKX file or directory")

    scan.add_argument(
        "--json", metavar="FILE", default=None,
        help='Write JSON output to FILE (use "-" for stdout)',
    )
    scan.add_argument(
        "--table", action="store_true", default=False,
        help="Print a human-readable table (default if --json not given)",
    )
    scan.add_argument(
        "--no-table", action="store_true",
        help="Suppress the table output (useful with --json -)",
    )

    scan.add_argument(
        "--scan-native", action="store_true",
        help="Also scan native libraries (.so files); off by default",
    )
    scan.add_argument(
        "--max-file-size", type=int, default=50 * 1024 * 1024,
        metavar="BYTES",
        help="Skip files larger than this many bytes (default 50MB)",
    )
    scan.add_argument(
        "--min-confidence", type=float, default=0.0, metavar="N",
        help="Drop findings with confidence below N (0.0-1.0, default 0.0)",
    )

    # CI gate: by default, exit non-zero if any finding crosses this
    # confidence threshold. Set to 1.01 (or use --no-fail) to disable.
    scan.add_argument(
        "--fail-on", type=float, default=0.85, metavar="N",
        help=("Exit with code 1 if any finding has confidence >= N "
              "(default 0.85). Useful as a CI gate."),
    )
    scan.add_argument(
        "--no-fail", action="store_true",
        help="Always exit 0 regardless of findings (overrides --fail-on)",
    )

    scan.add_argument(
        "--no-collapse", action="store_true",
        help=("Don't collapse the same value found in multiple sources "
              "into one finding. By default a value appearing in N "
              "files is shown once with all sources preserved in the "
              "JSON output."),
    )

    verb = scan.add_mutually_exclusive_group()
    verb.add_argument("--quiet", "-q", action="store_true",
                      help="Suppress progress messages")
    verb.add_argument("--verbose", "-v", action="store_true",
                      help="Print progress and debug messages")

    # ---- inspect 
    inspect = sub.add_parser(
        "inspect",
        help="Dump every extracted string from an APK (no detectors)",
        description=(
            "Diagnostic mode: walk the APK with the same routing rules "
            "as `scan` but instead of running detectors, dump each "
            "extracted string to stdout. Format: SOURCE | KIND | STRING. "
            "Use this when `scan` reports fewer findings than you "
            "expected — pipe to grep to find what's actually inside, "
            "then we can write a regex for it."
        ),
    )
    inspect.add_argument("target", help="APK/APKX file to inspect")
    inspect.add_argument(
        "--min-len", type=int, default=4, metavar="N",
        help="Minimum string length to emit (default 4)",
    )
    inspect.add_argument(
        "--filter-source", default=None, metavar="SUBSTR",
        help="Only show strings from sources containing SUBSTR "
             "(e.g. --filter-source classes.dex)",
    )
    inspect.add_argument(
        "--grep", default=None, metavar="REGEX",
        help="Only show strings matching REGEX (Python regex syntax)",
    )
    inspect.add_argument(
        "--max-file-size", type=int, default=50 * 1024 * 1024,
        metavar="BYTES",
        help="Skip files larger than this many bytes (default 50MB)",
    )
    inspect.add_argument("--scan-native", action="store_true",
                         help="Also dump strings from .so libraries")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return _do_scan(args)
    if args.command == "inspect":
        return _do_inspect(args)

    parser.print_help()
    return 1


def _do_inspect(args: argparse.Namespace) -> int:
    import re as _re

    target = Path(args.target).expanduser().resolve()
    if not target.exists():
        print(f"error: target not found: {target}", file=sys.stderr)
        return 2
    if not target.is_file():
        print(f"error: inspect requires a file, got directory: {target}",
              file=sys.stderr)
        return 2

    grep_re = _re.compile(args.grep) if args.grep else None

    scanner = Scanner(
        max_file_size=args.max_file_size,
        scan_native_libs=args.scan_native,
        log=lambda m: print(m, file=sys.stderr),
    )

    count = 0
    try:
        for source, string, kind in scanner.iter_strings(
                target, min_len=args.min_len):
            if args.filter_source and args.filter_source not in source:
                continue
            if grep_re and not grep_re.search(string):
                continue
            # Escape control bytes so the terminal isn't messed up by
            # arbitrary strings extracted from binaries.
            display = string.replace("\n", "\\n").replace("\r", "\\r")\
                            .replace("\t", "\\t")
            # Use \x{:02x} for any remaining control bytes (DEX/.arsc
            # binary scans can produce them).
            display = "".join(
                c if (32 <= ord(c) < 127 or ord(c) >= 160) else f"\\x{ord(c):02x}"
                for c in display
            )
            print(f"{source} | {kind:12s} | {display}")
            count += 1
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    print(f"\n[+] {count} strings emitted", file=sys.stderr)
    return 0


def _make_logger(args: argparse.Namespace):
    """Return a logging callable that respects --quiet / --verbose."""

    def log(msg: str) -> None:
        if args.quiet:
            return
        if args.verbose:
            print(msg, file=sys.stderr)
            return
        # Default: only show top-level scan progress and errors.
        if msg.startswith("[*]") or msg.startswith("[!]"):
            print(msg, file=sys.stderr)

    return log


def _do_scan(args: argparse.Namespace) -> int:
    target = Path(args.target).expanduser().resolve()
    if not target.exists():
        print(f"error: target not found: {target}", file=sys.stderr)
        return 2

    log = _make_logger(args)

    scanner = Scanner(
        max_file_size=args.max_file_size,
        scan_native_libs=args.scan_native,
        log=log,
    )

    try:
        findings: List[Finding] = list(scanner.scan_path(target))
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    findings = dedupe(findings)
    if not args.no_collapse:
        findings = collapse_sources(findings)
    # Verdict aggregation: turn co-occurring signals into one summary
    # finding per APK at the top of the report.
    findings = derive_verdicts(findings)
    if args.min_confidence > 0:
        findings = [f for f in findings if f.confidence >= args.min_confidence]

    # Stable sort: highest confidence first, then APK / type / source so
    # diffs across runs are clean.
    findings.sort(key=lambda f: (-f.confidence, f.apk, f.type, f.source))

    # Decide what to render:
    #   - --json -    : JSON to stdout, no table (would garble the JSON)
    #   - --json FILE : JSON to FILE, table to stdout (unless --no-table)
    #   - default     : table to stdout
    json_to_stdout = args.json == "-"
    show_table = not args.no_table and not json_to_stdout

    if args.json:
        if json_to_stdout:
            reporters.write_json(findings, sys.stdout)
        else:
            with open(args.json, "w", encoding="utf-8") as fh:
                reporters.write_json(findings, fh)
            if not args.quiet:
                print(
                    f"[+] Wrote {len(findings)} findings to {args.json}",
                    file=sys.stderr,
                )

    if show_table:
        reporters.write_table(findings, sys.stdout)

    # Exit-code policy: exit 1 if any finding crosses --fail-on, unless
    # --no-fail was passed. This makes MIMMO usable as a CI gate without
    # a wrapper script. Exit codes overall:
    #   0  -> clean (no findings >= --fail-on, or --no-fail set)
    #   1  -> findings present at or above the configured threshold
    #   2  -> hard error (target missing, etc.) — set earlier
    if args.no_fail:
        return 0
    if any(f.confidence >= args.fail_on for f in findings):
        if not args.quiet:
            crossed = sum(1 for f in findings if f.confidence >= args.fail_on)
            print(
                f"[!] {crossed} finding(s) at confidence >= {args.fail_on}; "
                f"exiting 1 (use --no-fail to disable)",
                file=sys.stderr,
            )
        return 1
    return 0
