"""Scanner: walks APK contents and dispatches to detectors."""

from __future__ import annotations

import io
import re
import zipfile
from pathlib import Path
from typing import Callable, Iterable, Iterator, List, Optional, Set, Tuple

from . import axml, detectors, dex
from .finding import Finding
from .strings_util import extract_ascii_strings, extract_utf16le_strings


# Bundles like .xapk / .apkm / .apks contain inner *.apk files. We descend
# into them up to this depth (0 = outer file the user passed). 2 is enough
# for every real-world bundle format.
MAX_NEST_DEPTH = 2

# File extensions we recognise as scannable APK containers when walking a
# directory. Single-file invocation works on anything ZIP-shaped regardless.
APK_SUFFIXES = (".apk", ".apkx", ".xapk", ".apkm", ".apks")


# Files we treat as plain text and decode as UTF-8 directly. Everything
# else falls back to the binary path (string-extract -> detectors).
TEXT_FILE_SUFFIXES = (
    ".json", ".xml", ".txt", ".properties", ".cfg", ".conf", ".ini",
    ".yaml", ".yml", ".html", ".htm", ".js", ".css", ".md", ".sql",
    ".pem", ".crt", ".cer", ".keystore", ".smali",
)

# Files we don't bother opening: pure media / fonts / native libs (.so is
# opt-in via --scan-native).
SKIP_SUFFIXES = (
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico",
    ".mp3", ".mp4", ".m4a", ".wav", ".ogg", ".webm", ".mkv", ".aac",
    ".ttf", ".otf", ".woff", ".woff2",
)

# Hard cap on per-file size we'll read into memory. Mostly to protect
# against pathological inputs; can be raised via --max-file-size.
DEFAULT_MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MiB

# When scanning binaries, flush the accumulated string-pool to detectors
# every ~2 MiB so very large DEX files don't build a huge intermediate.
_BINARY_FLUSH_BYTES = 2 * 1024 * 1024

# Control bytes (incl. ANSI escape introducer 0x1b) that should never
# appear in a sanely-named ZIP member. Ripping them out prevents an
# attacker-supplied filename from corrupting the terminal table or
# injecting fake-looking paths into JSON reports.
_FILENAME_UNSAFE_RE = re.compile(r"[\x00-\x1f\x7f]")


def _sanitize_source(name: str) -> str:
    """Sanitise a ZIP member name for safe inclusion in reports.

    Replaces control bytes and ANSI escapes with ``?`` and collapses
    any directory traversal segments so the displayed path can't
    impersonate a host filesystem location. We never *write* using
    member names, so this is purely about output integrity.
    """
    cleaned = _FILENAME_UNSAFE_RE.sub("?", name)
    # Collapse traversal segments. We don't need true canonicalisation —
    # we just don't want "../../../etc/passwd" appearing verbatim in a
    # report shown to a human or a log viewer.
    if ".." in cleaned:
        cleaned = cleaned.replace("../", "").replace("..\\", "")
    return cleaned


LogFn = Callable[[str], None]


class Scanner:
    """Walk an APK (or a tree of APKs) and stream findings."""

    def __init__(
        self,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
        scan_native_libs: bool = False,
        log: Optional[LogFn] = None,
    ) -> None:
        self.max_file_size = max_file_size
        self.scan_native_libs = scan_native_libs
        self.log: LogFn = log or (lambda _msg: None)
        self.detectors = detectors.get_all()

    # -- Public API ---------------------------------------------------------

    def scan_path(self, path: Path) -> Iterator[Finding]:
        """Scan a single APK or every ``*.apk`` / ``*.apkx`` under a directory."""
        if path.is_file():
            yield from self._scan_apk(path)
        elif path.is_dir():
            for apk in self._iter_apks(path):
                yield from self._scan_apk(apk)
        else:
            raise FileNotFoundError(f"path not found: {path}")

    def iter_strings(
        self, path: Path, min_len: int = 4
    ) -> Iterator[Tuple[str, str, str]]:
        """Yield ``(source, string, kind)`` for every string in an APK.

        Diagnostic helper used by ``mimmo inspect``: walks the same
        files ``scan_path`` would, but instead of running detectors
        emits the raw extracted strings. ``kind`` distinguishes between
        ``"dex"`` (structured DEX walk), ``"text"`` (UTF-8 decode of
        text-like files) and ``"binary"`` (ASCII/UTF-16LE scan of
        binary blobs). Useful when MIMMO finds nothing on an APK that
        you suspect has secrets — dump the strings, find what's there,
        write a new pattern for it.
        """
        if not path.is_file():
            raise FileNotFoundError(f"file not found: {path}")
        try:
            with zipfile.ZipFile(path, "r") as zf:
                yield from self._iter_zip_strings(
                    zf, source_prefix="", depth=0, min_len=min_len
                )
        except zipfile.BadZipFile:
            self.log(f"[!] Not a valid ZIP/APK: {path}")

    def _iter_zip_strings(
        self,
        zf: zipfile.ZipFile,
        source_prefix: str,
        depth: int,
        min_len: int,
    ) -> Iterator[Tuple[str, str, str]]:
        for member in zf.infolist():
            if member.is_dir():
                continue
            full_source = source_prefix + member.filename
            name = member.filename
            lower = name.lower()

            # Recurse into nested APKs.
            if (depth < MAX_NEST_DEPTH and lower.endswith(".apk")):
                inner = self._safe_read(zf, member, full_source)
                if inner is None:
                    continue
                try:
                    with zipfile.ZipFile(io.BytesIO(inner)) as inner_zf:
                        yield from self._iter_zip_strings(
                            inner_zf, full_source + "!", depth + 1, min_len
                        )
                    continue
                except zipfile.BadZipFile:
                    pass

            if lower.endswith(SKIP_SUFFIXES):
                continue
            if lower.endswith(".so") and not self.scan_native_libs:
                continue

            data = self._safe_read(zf, member, full_source)
            if data is None:
                continue

            # DEX: structured walk first, fall back to ascii scan.
            if name == "classes.dex" or (
                    lower.startswith("classes") and lower.endswith(".dex")):
                try:
                    for s in dex.parse_dex_strings(data):
                        if s and len(s) >= min_len:
                            yield (full_source, s, "dex")
                    continue
                except dex.DexParseError:
                    pass  # fall through to binary scan

            # Text-like: decode and yield each non-empty line.
            if any(lower.endswith(s) for s in TEXT_FILE_SUFFIXES):
                text = data.decode("utf-8", errors="replace")
                for line in text.splitlines():
                    line = line.strip()
                    if len(line) >= min_len:
                        yield (full_source, line, "text")
                continue

            # Binary fallback (resources.arsc, unknown blobs, .so when on).
            for s in extract_ascii_strings(data, min_len=min_len):
                yield (full_source, s, "binary")
            for s in extract_utf16le_strings(data, min_len=min_len):
                yield (full_source, s, "binary-utf16")

    # -- Walking ------------------------------------------------------------

    @staticmethod
    def _iter_apks(root: Path) -> Iterator[Path]:
        for p in root.rglob("*"):
            if p.is_file() and p.suffix.lower() in APK_SUFFIXES:
                yield p

    def _safe_read(
        self,
        zf: zipfile.ZipFile,
        member: zipfile.ZipInfo,
        source_path: str,
    ) -> Optional[bytes]:
        """Read a ZIP member with a hard cap on **decompressed** bytes.

        ZIP headers carry a *declared* uncompressed size which an
        attacker can lie about (a 100KB compressed entry can claim 1KB
        and decompress to 50MB, or vice versa). Streaming through
        ``zf.open(member).read(N)`` lets us enforce a real ceiling
        regardless of what the header says, so a hostile bundle can't
        OOM us via a single decompression call.
        """
        if member.file_size > self.max_file_size:
            self.log(
                f"[~] Skipping oversized {source_path} "
                f"(declared {member.file_size} bytes > cap {self.max_file_size})"
            )
            return None
        try:
            with zf.open(member, "r") as fh:
                # Read one byte past the cap so we can detect overrun.
                data = fh.read(self.max_file_size + 1)
        except (RuntimeError, zipfile.BadZipFile, OSError) as e:
            self.log(f"[!] Failed to read {source_path}: {e}")
            return None
        if len(data) > self.max_file_size:
            self.log(
                f"[~] {source_path}: decompressed bytes exceeded cap "
                f"({self.max_file_size}); declared size was {member.file_size}. "
                f"Likely a malformed or hostile entry — skipping."
            )
            return None
        return data

    def _scan_apk(self, apk_path: Path) -> Iterator[Finding]:
        self.log(f"[*] Scanning {apk_path}")
        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                yield from self._scan_zip(
                    zf, apk_label=str(apk_path), source_prefix="", depth=0
                )
        except zipfile.BadZipFile:
            self.log(f"[!] Not a valid ZIP/APK: {apk_path}")
        except (OSError, RuntimeError) as e:
            # RuntimeError covers password-protected entries.
            self.log(f"[!] Error scanning {apk_path}: {e}")

    def _scan_zip(
        self,
        zf: zipfile.ZipFile,
        apk_label: str,
        source_prefix: str,
        depth: int,
    ) -> Iterator[Finding]:
        """Walk one ZIP container. Recurses into nested .apk members.

        ``apk_label`` is what ends up in ``Finding.apk`` (always the
        original outer file the user invoked us on). ``source_prefix`` is
        prepended to each inner member name with a ``!`` separator so
        users can see the path through the bundle, e.g.
        ``base.apk!classes.dex``.
        """
        for member in zf.infolist():
            if member.is_dir():
                continue
            full_source = _sanitize_source(source_prefix + member.filename)

            # Nested APK? Open it and recurse before falling through to
            # the per-member dispatch. We cap recursion depth as a cheap
            # defence against degenerate / cyclic bundles.
            if (depth < MAX_NEST_DEPTH
                    and member.filename.lower().endswith(".apk")):
                inner_bytes = self._safe_read(zf, member, full_source)
                if inner_bytes is None:
                    continue
                try:
                    with zipfile.ZipFile(io.BytesIO(inner_bytes)) as inner_zf:
                        self.log(f"[*] Descending into {full_source}")
                        yield from self._scan_zip(
                            inner_zf,
                            apk_label=apk_label,
                            source_prefix=full_source + "!",
                            depth=depth + 1,
                        )
                    continue
                except zipfile.BadZipFile:
                    # Member is .apk-named but not a valid ZIP. Fall
                    # through and treat it as an opaque blob.
                    self.log(f"[~] {full_source} is .apk but not a ZIP; "
                             f"scanning as binary")

            yield from self._scan_member(zf, member, apk_label, full_source)

    # -- Per-member dispatch ------------------------------------------------

    def _scan_member(
        self,
        zf: zipfile.ZipFile,
        member: zipfile.ZipInfo,
        apk_path: str,
        source_path: str,
    ) -> Iterator[Finding]:
        # ``name`` drives routing decisions (it's the bare filename inside
        # the current ZIP). ``source_path`` is what we put in findings
        # (may include nested-APK prefixes like "base.apk!classes.dex").
        name = member.filename
        lower = name.lower()

        if lower.endswith(SKIP_SUFFIXES):
            return
        if lower.endswith(".so") and not self.scan_native_libs:
            return

        data = self._safe_read(zf, member, source_path)
        if data is None:
            return

        # AndroidManifest.xml -> structured AXML parse + string fallback.
        if name == "AndroidManifest.xml":
            yield from self._scan_manifest(data, source_path, apk_path)
            return

        # DEX -> structured string-table walk first, fall back to binary
        # scan if the header doesn't validate. ARSC stays on the binary
        # path because we don't have a structured parser for it yet.
        if name == "classes.dex" or (
                lower.startswith("classes") and lower.endswith(".dex")):
            yield from self._scan_dex(data, source_path, apk_path)
            return

        if name == "resources.arsc":
            yield from self._scan_binary(data, source_path, apk_path)
            return

        # Text-like files -> straight UTF-8 decode.
        if any(lower.endswith(s) for s in TEXT_FILE_SUFFIXES):
            yield from self._scan_text(data, source_path, apk_path)
            return

        # Catch-all for small unknown files (config blobs, embedded JSON, ...).
        if len(data) <= 5 * 1024 * 1024:
            yield from self._scan_binary(data, source_path, apk_path)

    # -- Detector entry points ---------------------------------------------

    def _scan_text(self, data: bytes, name: str, apk_path: str) -> Iterator[Finding]:
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception as e:  # pragma: no cover - defensive
            self.log(f"[!] decode failed for {name}: {e}")
            return
        for det in self.detectors:
            yield from det.scan_text(text, name, apk_path)

    def _scan_binary(self, data: bytes, name: str, apk_path: str) -> Iterator[Finding]:
        """Extract printable strings from binary data and run text detectors.

        We chunk the join so very large DEX blobs don't materialise a
        single multi-MB string in memory.
        """
        chunks: List[str] = []
        chunk_bytes = 0

        for s in extract_ascii_strings(data, min_len=6):
            chunks.append(s)
            chunk_bytes += len(s) + 1
            if chunk_bytes >= _BINARY_FLUSH_BYTES:
                yield from self._run_text_detectors(
                    "\n".join(chunks), name, apk_path
                )
                chunks.clear()
                chunk_bytes = 0

        if chunks:
            yield from self._run_text_detectors(
                "\n".join(chunks), name, apk_path
            )

    def _scan_dex(self, data: bytes, name: str, apk_path: str) -> Iterator[Finding]:
        """Run detectors over a DEX file's structured string table.

        Plus a raw-bytecode pass for IPs that are encoded as 4
        sequential ``const/16`` operands rather than string literals
        (the way msfvenom and similar payloads embed LHOST). The
        bytecode pass is cheap (~20 MB/s) and catches IPs that the
        string-table walk cannot.

        Falls back to the legacy binary path on parse error so we never
        silently drop coverage on an obfuscated or truncated .dex.
        """
        # Bytecode-level IP recovery first — independent of header parse
        # success, since even a malformed DEX has bytecode regions.
        yield from detectors._DexBytecodeIPDetector.scan_bytes(
            data, name, apk_path
        )

        try:
            string_iter = dex.parse_dex_strings(data)
        except dex.DexParseError as e:
            self.log(
                f"[~] DEX parse failed for {name}: {e}; using binary string scan"
            )
            yield from self._scan_binary(data, name, apk_path)
            return

        # Same chunk-and-flush strategy as the binary path: detectors
        # see batches of strings joined by newlines, never one giant
        # blob. Useful for >500k-string mega-DEX files.
        chunks: List[str] = []
        chunk_bytes = 0
        emitted = 0

        for s in string_iter:
            if not s:
                continue
            chunks.append(s)
            chunk_bytes += len(s) + 1
            emitted += 1
            if chunk_bytes >= _BINARY_FLUSH_BYTES:
                yield from self._run_text_detectors(
                    "\n".join(chunks), name, apk_path
                )
                chunks.clear()
                chunk_bytes = 0

        if chunks:
            yield from self._run_text_detectors(
                "\n".join(chunks), name, apk_path
            )

        self.log(f"[*] DEX {name}: {emitted} strings via structured walk")

    def _run_text_detectors(
        self, text: str, name: str, apk_path: str
    ) -> Iterator[Finding]:
        for det in self.detectors:
            yield from det.scan_text(text, name, apk_path)

    def _scan_manifest(
        self, data: bytes, name: str, apk_path: str
    ) -> Iterator[Finding]:
        """Try AXML parse for structured checks, always also string-scan."""
        parsed_ok = False
        try:
            elements = axml.parse_axml(data)
            parsed_ok = True
            for det in self.detectors:
                yield from det.scan_manifest(elements, name, apk_path)
        except axml.AXMLParseError as e:
            self.log(f"[~] AXML parse failed for {name}: {e}; using string scan")

        # Always run string-scan over the manifest too: catches hardcoded
        # URLs, package names, intent filter data, and any odd strings the
        # binary parse skipped.
        yield from self._scan_binary(data, name, apk_path)

        if not parsed_ok:
            # Last-resort heuristic so we don't entirely miss
            # debuggable=true when AXML parsing fails.
            string_set = set(extract_ascii_strings(data, min_len=4))
            string_set.update(extract_utf16le_strings(data, min_len=4))
            if "debuggable" in string_set and "true" in string_set:
                yield Finding(
                    type="manifest_debuggable_heuristic",
                    value="manifest contains 'debuggable' and 'true' strings",
                    source=name,
                    apk=apk_path,
                    confidence=0.4,
                    category="misconfig",
                    description=(
                        "Heuristic only: AXML parse failed but the manifest "
                        "contains both 'debuggable' and 'true' tokens; "
                        "verify manually with aapt or apktool."
                    ),
                )


# ---------------------------------------------------------------------------
# Post-processing helpers
# ---------------------------------------------------------------------------


def dedupe(findings: Iterable[Finding]) -> List[Finding]:
    """Remove findings that are exact duplicates (same source too).

    Use :func:`collapse_sources` instead to also fold findings that
    share (type, value, apk) across multiple sources into a single
    representative entry.
    """
    seen: Set[Tuple[str, str, str, str]] = set()
    out: List[Finding] = []
    for f in findings:
        key = f.dedup_key()
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def collapse_sources(findings: Iterable[Finding]) -> List[Finding]:
    """Collapse findings sharing (type, value, apk) into one entry.

    The same secret/URL/email often appears in dozens of files inside
    one APK (think: an analytics SDK URL splattered across every
    activity, a hard-coded token referenced from both classes.dex and
    a config asset). Showing each occurrence as a separate row in the
    output is noise — the user wants to know that a value exists once
    per APK, with the list of locations preserved as evidence.

    The kept representative is the highest-confidence finding for the
    group; if confidences tie, the first occurrence wins. Confidence
    is taken as the **max** across the group (a high-confidence hit in
    classes.dex shouldn't be downgraded just because the same string
    also appears in a low-confidence text file).

    Manifest findings are intentionally NOT collapsed — they're already
    one-shot (you only have one AndroidManifest.xml per APK), and the
    full ``<activity ...>`` snippet stored in ``value`` makes each
    misconfig genuinely distinct.
    """
    from dataclasses import replace
    groups: dict = {}
    order: List[Tuple[str, str, str]] = []

    for f in findings:
        # Manifest findings keep per-source identity. They're already
        # unique per APK in practice and collapsing them would lose
        # the per-component context (which activity is exported, etc.).
        if f.category == "misconfig":
            key = (f.type, f.value, f.source, f.apk)
        else:
            key = f.collapse_key()

        if key not in groups:
            groups[key] = [f]
            order.append(key)
        else:
            groups[key].append(f)

    out: List[Finding] = []
    for key in order:
        members = groups[key]
        if len(members) == 1:
            out.append(members[0])
            continue

        # Pick the representative: highest confidence wins; on ties
        # keep insertion order (stable).
        members.sort(key=lambda x: -x.confidence)
        rep = members[0]

        # Aggregate sources, preserving stable order without dups.
        seen_src: Set[str] = set()
        all_sources: List[str] = []
        for m in members:
            if m.source not in seen_src:
                seen_src.add(m.source)
                all_sources.append(m.source)

        out.append(replace(
            rep,
            confidence=max(m.confidence for m in members),
            sources=tuple(all_sources),
        ))
    return out


# Meta-detector verdict rules. Each rule is (verdict_name, required, conf,
# description) where ``required`` is a list of either:
#   * a single type string — must appear in findings for this APK
#   * a tuple of type strings — at least one must appear (OR-of)
_VERDICT_RULES = [
    (
        "verdict_metasploit_payload",
        [
            "metasploit_payload",
            "dynamic_dex_loading",
            "trustmanager_custom_trustmanager",
        ],
        0.99,
        "MIMMO is highly confident this APK is a Metasploit/Meterpreter "
        "Android payload. Signals: Metasploit package present, runtime "
        "DEX loading via reflection (stager pattern), and a custom "
        "TrustManager that accepts any TLS certificate (for unverified "
        "reverse_https C2). Do NOT install this APK on a real device.",
    ),
    (
        "verdict_likely_rat",
        [
            ("metasploit_payload", "meterpreter_marker", "generic_rat_marker"),
            "trustmanager_custom_trustmanager",
            "dynamic_dex_loading",
        ],
        0.95,
        "Strong indicators of an Android RAT / reverse-shell payload: "
        "known malware family marker + permissive TLS validation + "
        "runtime code loading. The combination of these three is "
        "almost never legitimate.",
    ),
    (
        "verdict_debug_signed_with_payload_pattern",
        [
            "debug_signing_certificate",
            ("metasploit_payload", "dynamic_dex_loading",
             "trustmanager_custom_trustmanager", "meterpreter_marker"),
        ],
        0.95,
        "APK signed with the Android debug key AND contains code "
        "patterns typical of malware/payload generation tooling. "
        "This is the default output of msfvenom and similar offensive "
        "frameworks: a non-release-signed APK with a backdoor inside.",
    ),
]


def derive_verdicts(findings: List[Finding]) -> List[Finding]:
    """Emit high-confidence verdicts from co-occurring signals.

    Individual detectors already flag the pieces (MSF package, custom
    TrustManager, dynamic loading, debug cert, …). When several of
    those land together on the same APK, the conclusion is
    unambiguous even if specific values (LHOST, LPORT) are missing
    because they're encoded or downloaded from a second stage.

    This function appends one summary :class:`Finding` per matched
    verdict so the user sees the conclusion at the top of the report
    rather than joining the dots themselves.
    """
    if not findings:
        return findings

    # Index findings by APK → set of types present.
    by_apk: dict = {}
    for f in findings:
        by_apk.setdefault(f.apk, set()).add(f.type)

    verdicts: List[Finding] = []
    for apk, present in by_apk.items():
        for vtype, required, conf, desc in _VERDICT_RULES:
            evidence: List[str] = []
            ok = True
            for req in required:
                if isinstance(req, tuple):
                    # OR-of: at least one alternative must be present.
                    matched = [r for r in req if r in present]
                    if not matched:
                        ok = False
                        break
                    evidence.append(matched[0])
                else:
                    if req not in present:
                        ok = False
                        break
                    evidence.append(req)

            if ok:
                verdicts.append(Finding(
                    type=vtype,
                    value=f"signals: {', '.join(evidence)}",
                    source="<aggregate>",
                    apk=apk,
                    confidence=conf,
                    category="verdict",
                    description=desc,
                ))

    return findings + verdicts
