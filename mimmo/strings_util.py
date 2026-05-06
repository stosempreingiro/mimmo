"""String extraction from binary blobs.

Used for ``classes.dex``, ``resources.arsc`` and as a fallback for any
binary file we don't have a structured parser for. The implementation is
deliberately simple and fast: a single compiled regex over the whole
buffer, lazy generator output so the caller can stream into detectors.
"""

import re
from typing import Iterator

# A "string" is a run of printable ASCII characters (space..tilde) of at
# least ``min_len`` bytes. This catches embedded URLs, secrets and identifiers
# without parsing DEX or ARSC formats. min_len=6 is a good default for DEX:
# it removes tons of single-letter symbol-table noise while still catching
# realistic secrets and short paths.
_DEFAULT_ASCII_RE = re.compile(rb"[\x20-\x7e]{6,}")


def extract_ascii_strings(data: bytes, min_len: int = 6) -> Iterator[str]:
    """Yield printable-ASCII runs of at least ``min_len`` chars from ``data``.

    Decoding uses ``ascii`` with ``replace`` so output is always valid str.
    """
    if min_len == 6:
        regex = _DEFAULT_ASCII_RE
    else:
        regex = re.compile(rb"[\x20-\x7e]{" + str(int(min_len)).encode() + rb",}")
    for m in regex.finditer(data):
        yield m.group().decode("ascii", errors="replace")


# UTF-16LE pattern: ASCII char followed by 0x00 byte. Useful when scanning
# files that wrap text in UTF-16 (rare in APKs but cheap to also look for).
def extract_utf16le_strings(data: bytes, min_len: int = 6) -> Iterator[str]:
    """Yield ASCII-content UTF-16LE runs from ``data``."""
    n = int(min_len)
    regex = re.compile(rb"(?:[\x20-\x7e]\x00){" + str(n).encode() + rb",}")
    for m in regex.finditer(data):
        try:
            yield m.group().decode("utf-16-le", errors="replace").rstrip("\x00")
        except Exception:
            # Defensive: malformed UTF-16 fragments shouldn't break a scan.
            continue
