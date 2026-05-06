"""Minimal Android Binary XML (AXML) parser.

Implements just enough of the AXML format used in compiled
``AndroidManifest.xml`` files to extract:

  * the string pool
  * each START_ELEMENT tag's name + attributes (name -> string value)

It deliberately does **not** reconstruct the document tree, comments,
or namespaces beyond what's needed to prefix attributes with ``android:``
when they belong to the Android namespace. On any parse error we raise
``AXMLParseError`` and the caller falls back to plain string scanning.

References (Android source):
    frameworks/base/include/androidfw/ResourceTypes.h
"""

import struct
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

# --- Resource chunk types ----

RES_NULL_TYPE = 0x0000
RES_STRING_POOL_TYPE = 0x0001
RES_XML_TYPE = 0x0003
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
RES_XML_CDATA_TYPE = 0x0104
RES_XML_RESOURCE_MAP_TYPE = 0x0180

# --- String pool flags -----------------

STRING_POOL_FLAG_UTF8 = 1 << 8

# --- Res_value data types -----------

TYPE_NULL = 0x00
TYPE_REFERENCE = 0x01
TYPE_ATTRIBUTE = 0x02
TYPE_STRING = 0x03
TYPE_FLOAT = 0x04
TYPE_DIMENSION = 0x05
TYPE_FRACTION = 0x06
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOL = 0x12

# Android system namespace URI; used to prefix attributes for callers.
ANDROID_NS = "http://schemas.android.com/apk/res/android"


class AXMLParseError(Exception):
    """Raised when AXML data is malformed enough that we can't recover. bleah"""


@dataclass
class Element:
    """A flattened start-element from the AXML tree."""

    name: str
    ns: str = ""
    attrs: Dict[str, str] = field(default_factory=dict)


# --------------------
# String-pool helpers
# --------------------


def _decode_length_utf8(data: bytes, offset: int) -> Tuple[int, int]:
    """Decode an AXML UTF-8 length prefix.
    The length can be 1 or 2 bytes; the high bit of the first byte signals
    a 2-byte form. Returns ``(length, bytes_consumed)``.
    """
    if offset >= len(data):
        return 0, 0
    b = data[offset]
    if b & 0x80:
        if offset + 1 >= len(data):
            return 0, 1
        return ((b & 0x7F) << 8) | data[offset + 1], 2
    return b, 1


def _decode_length_utf16(data: bytes, offset: int) -> Tuple[int, int]:
    """Decode an AXML UTF-16 length prefix (2 or 4 bytes)."""
    if offset + 2 > len(data):
        return 0, 2
    val = struct.unpack_from("<H", data, offset)[0]
    if val & 0x8000:
        if offset + 4 > len(data):
            return 0, 2
        high = val & 0x7FFF
        low = struct.unpack_from("<H", data, offset + 2)[0]
        return (high << 16) | low, 4
    return val, 2


def _read_string_pool(data: bytes, offset: int) -> List[str]:
    """Parse a RES_STRING_POOL_TYPE chunk at ``offset`` and return its strings."""
    if offset + 28 > len(data):
        raise AXMLParseError("string pool header truncated")

    typ, header_size, _size = struct.unpack_from("<HHI", data, offset)
    if typ != RES_STRING_POOL_TYPE:
        raise AXMLParseError(f"expected string pool, got chunk type {typ:#x}")

    string_count, _style_count, flags, strings_start, _styles_start = struct.unpack_from(
        "<IIIII", data, offset + 8
    )
    is_utf8 = bool(flags & STRING_POOL_FLAG_UTF8)

    offsets_start = offset + header_size
    if offsets_start + 4 * string_count > len(data):
        raise AXMLParseError("string offset table truncated")

    offsets = struct.unpack_from(f"<{string_count}I", data, offsets_start)
    strings_data_base = offset + strings_start

    out: List[str] = []
    for off in offsets:
        spos = strings_data_base + off
        if spos >= len(data):
            out.append("")
            continue
        try:
            if is_utf8:
                # UTF-8 strings carry both a char-count and a byte-count.
                _u16len, n = _decode_length_utf8(data, spos)
                spos += n
                bytelen, n = _decode_length_utf8(data, spos)
                spos += n
                if spos + bytelen > len(data):
                    out.append("")
                    continue
                s = data[spos : spos + bytelen].decode("utf-8", errors="replace")
            else:
                charlen, n = _decode_length_utf16(data, spos)
                spos += n
                byte_len = charlen * 2
                if spos + byte_len > len(data):
                    out.append("")
                    continue
                s = data[spos : spos + byte_len].decode("utf-16-le", errors="replace")
            out.append(s)
        except Exception:
            # One bad string shouldn't tank the whole parse.
            out.append("")
    return out


# --------------------------
# Attribute value formatting
# --------------------------


def _format_attr_value(
    strings: List[str], data_value: int, type_byte: int, raw_value_idx: int
) -> str:
    """Render a Res_value as a string suitable for our detectors."""
    if type_byte == TYPE_STRING:
        if 0 <= raw_value_idx < len(strings):
            return strings[raw_value_idx]
        return ""
    if type_byte == TYPE_INT_BOOL:
        # Android encodes "true" as 0xFFFFFFFF, "false" as 0x00000000.
        return "true" if data_value != 0 else "false"
    if type_byte == TYPE_INT_HEX:
        return f"0x{data_value & 0xFFFFFFFF:x}"
    if type_byte == TYPE_INT_DEC:
        # Treat as signed 32-bit if high bit set (rare but possible).
        v = data_value & 0xFFFFFFFF
        if v & 0x80000000:
            v -= 0x100000000
        return str(v)
    if type_byte == TYPE_REFERENCE or type_byte == TYPE_ATTRIBUTE:
        return f"@0x{data_value & 0xFFFFFFFF:08x}"
    if type_byte == TYPE_NULL:
        return ""
    return f"<type:{type_byte:#x}:{data_value}>"


# ---------------------
# Top-level parser
# ------------------

def parse_axml(data: bytes) -> List[Element]:
    """Parse AXML bytes and return a flat list of start-elements.

    Only START_ELEMENT chunks are emitted. The element tree itself is not
    reconstructed (we don't need it for manifest checks). Order of the
    returned list mirrors document order.
    """
    if len(data) < 8:
        raise AXMLParseError("data too short")

    typ, header_size, file_size = struct.unpack_from("<HHI", data, 0)
    if typ != RES_XML_TYPE:
        raise AXMLParseError(f"not AXML (root chunk type {typ:#x})")

    pos = header_size
    file_end = min(file_size, len(data))

    strings: List[str] = []
    elements: List[Element] = []

    # Walk top-level chunks.
    while pos + 8 <= file_end:
        c_type, c_header_size, c_size = struct.unpack_from("<HHI", data, pos)
        if c_size == 0 or pos + c_size > file_end:
            # Bad chunk; bail out but keep what we have so far.
            break

        if c_type == RES_STRING_POOL_TYPE:
            strings = _read_string_pool(data, pos)

        elif c_type == RES_XML_START_ELEMENT_TYPE:
            # Layout (after the 8-byte chunk header):
            #   uint32 lineNumber, uint32 commentRef                    -> 8 bytes
            # then ResXMLTree_attrExt:
            #   int32 ns_idx, int32 name_idx,                           -> 8 bytes
            #   uint16 attributeStart, attributeSize, attributeCount,
            #   uint16 idIndex, classIndex, styleIndex                  -> 12 bytes
            #
            # The chunk's header_size is 16 (chunk_header + line/comment).
            # attributeStart is relative to the start of attrExt
            # (== pos + 16).
            attrext_pos = pos + 16
            if attrext_pos + 20 > file_end:
                pos += c_size
                continue

            ns_idx, name_idx = struct.unpack_from("<ii", data, attrext_pos)
            attr_start, attr_size, attr_count = struct.unpack_from(
                "<HHH", data, attrext_pos + 8
            )

            elem_name = strings[name_idx] if 0 <= name_idx < len(strings) else ""
            elem_ns = strings[ns_idx] if 0 <= ns_idx < len(strings) else ""

            attrs: Dict[str, str] = {}
            first_attr_pos = attrext_pos + attr_start
            # Newer aapt2 sometimes emits attributeSize 0; treat as the
            # canonical 20-byte attribute record.
            actual_attr_size = attr_size if attr_size >= 20 else 20

            for i in range(attr_count):
                ap = first_attr_pos + i * actual_attr_size
                if ap + 20 > file_end:
                    break
                # ResXMLTree_attribute:
                #   int32 ns_idx, int32 name_idx, int32 rawValue_idx (-1 if none)
                #   Res_value: uint16 size, uint8 res0, uint8 dataType, uint32 data
                a_ns_idx, a_name_idx, a_rawval_idx = struct.unpack_from(
                    "<iii", data, ap
                )
                _val_size, _val_res0, dtype, dval = struct.unpack_from(
                    "<HBBI", data, ap + 12
                )

                a_name = (
                    strings[a_name_idx] if 0 <= a_name_idx < len(strings) else ""
                )
                a_value = _format_attr_value(strings, dval, dtype, a_rawval_idx)
                a_ns_str = (
                    strings[a_ns_idx] if 0 <= a_ns_idx < len(strings) else ""
                )

                # Prefix android-namespace attributes so detectors can
                # match them with simple string keys.
                key = a_name
                if a_ns_str and "schemas.android.com" in a_ns_str:
                    key = "android:" + a_name
                attrs[key] = a_value

            elements.append(Element(name=elem_name, ns=elem_ns, attrs=attrs))

        pos += c_size

    return elements
