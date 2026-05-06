"""Minimal DEX (Dalvik EXecutable) parser: extract the string table.

We implement just enough of the DEX format to enumerate
``string_ids`` -> ``string_data_item`` and yield each string. This is the
same set of strings ``dexdump -d`` would print, minus the bytecode itself:
class names, method names, field names, and every string literal in the
.dex constant pool.

Compared to a raw ``strings``-style ASCII scan, the structured walk:

* never emits cross-record garbage from adjacent code/metadata,
* recovers UTF-8 / non-ASCII strings cleanly (Java identifiers are 7-bit
  but string literals are full Unicode),
* lets us count strings deterministically.

If the header doesn't validate (wrong magic, declared sizes out of
bounds, non-LE endianness) we raise :class:`DexParseError` and the
caller falls back to the legacy binary string scan, so a malformed or
obfuscated .dex never silently produces zero output.

References:
    https://source.android.com/docs/core/runtime/dex-format
"""

from __future__ import annotations

import struct
from typing import Iterator, Tuple

# DEX magic is "dex\n" + 3-byte version + 0x00. Common versions in the
# wild: 035 (Android 1.x+), 037 (N), 038 (O), 039 (P+), 040 (planned).
_DEX_MAGIC = b"dex\n"
# Endian tag value when the file matches host byte order (we only support
# little-endian, which is what every Android DEX in practice uses).
_ENDIAN_LE = 0x12345678

# Standard DEX header is exactly 0x70 bytes.
_HEADER_SIZE = 0x70

# Cap on the number of strings we'll walk, as a defence against a
# malformed header that claims billions of strings. Real APKs go up to
# ~250k strings per .dex; 5M is comfortably above that.
_MAX_STRING_IDS = 5_000_000


class DexParseError(Exception):
    """Raised when DEX bytes don't look like a parseable little-endian DEX."""


def _read_uleb128(data: bytes, offset: int) -> Tuple[int, int]:
    """Decode a ULEB128 starting at ``offset``.

    Returns ``(value, new_offset)``. DEX uses ULEB128 for the UTF-16
    code-unit count that prefixes each ``string_data_item``.
    """
    result = 0
    shift = 0
    n = len(data)
    # ULEB128 in DEX is bounded to 5 bytes (32-bit values).
    for _ in range(5):
        if offset >= n:
            raise DexParseError("uleb128 truncated")
        b = data[offset]
        offset += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, offset
        shift += 7
    raise DexParseError("uleb128 overlong")


def parse_dex_strings(data: bytes) -> Iterator[str]:
    """Yield every string from the DEX string table.

    Header is validated *eagerly* so that callers can rely on
    ``DexParseError`` being raised at call time, before they start
    iterating. Once iteration begins, individual record errors are
    swallowed (we yield ``""`` for the bad record and move on) so a
    single corrupt entry can't kill the whole walk.

    Strings are decoded as UTF-8 with ``errors="replace"``. Strict
    MUTF-8 decoding (with the 0xC0 0x80 quirk for embedded NULs and
    surrogate pairs for supplementary chars) is not implemented: those
    cases are rare and ``errors="replace"`` keeps the output usable
    rather than aborting on a single odd byte sequence.
    """
    string_ids_size, string_ids_off = _validate_dex_header(data)
    if string_ids_size == 0:
        return iter(())
    return _walk_string_table(data, string_ids_size, string_ids_off)


def _validate_dex_header(data: bytes) -> Tuple[int, int]:
    """Validate header and return ``(string_ids_size, string_ids_off)``.

    Raises :class:`DexParseError` on any structural problem so the
    caller can catch it before iteration starts.
    """
    if len(data) < _HEADER_SIZE:
        raise DexParseError(f"truncated header ({len(data)} bytes)")
    if not data.startswith(_DEX_MAGIC):
        raise DexParseError("not a DEX file (bad magic)")

    # endian_tag at offset 40, string_ids at 56/60.
    endian_tag = struct.unpack_from("<I", data, 40)[0]
    if endian_tag != _ENDIAN_LE:
        raise DexParseError(
            f"unsupported endianness tag {endian_tag:#x} (only LE supported)"
        )

    string_ids_size, string_ids_off = struct.unpack_from("<II", data, 56)

    if string_ids_size > _MAX_STRING_IDS:
        raise DexParseError(
            f"absurd string_ids_size {string_ids_size}; refusing to parse"
        )

    if string_ids_size > 0:
        end_of_ids = string_ids_off + string_ids_size * 4
        if end_of_ids > len(data) or string_ids_off < _HEADER_SIZE:
            raise DexParseError("string_ids table out of bounds")

    return string_ids_size, string_ids_off


def _walk_string_table(
    data: bytes, string_ids_size: int, string_ids_off: int
) -> Iterator[str]:
    """Internal generator: walk a *validated* string_ids table."""
    n = len(data)
    for i in range(string_ids_size):
        sid_off = struct.unpack_from(
            "<I", data, string_ids_off + i * 4
        )[0]
        if sid_off >= n:
            yield ""
            continue
        try:
            # string_data_item layout:
            #   uleb128 utf16_size  (number of UTF-16 code units)
            #   bytes   data        (MUTF-8, NUL-terminated)
            _utf16_size, pos = _read_uleb128(data, sid_off)
            # Find the terminating NUL. Cap the search so a truncated
            # data section can't make us scan to EOF.
            search_end = min(n, pos + (1 << 20))  # 1 MiB per-string cap
            end = data.find(b"\x00", pos, search_end)
            if end < 0:
                yield ""
                continue
            yield data[pos:end].decode("utf-8", errors="replace")
        except DexParseError:
            yield ""
            continue
        except Exception:
            # Defensive: never let one malformed record break the run.
            yield ""
            continue
