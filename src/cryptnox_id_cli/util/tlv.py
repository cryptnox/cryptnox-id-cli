"""A small, dependency-free BER-TLV parser.

PIV data objects and the Application Property Template use BER-TLV with
multi-byte tags (e.g. ``5FC102``, ``7F61``) and short/long length forms. We need
read-only parsing only; this stays intentionally minimal and well-tested.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class TLV:
    tag: int
    value: bytes
    children: list[TLV] = field(default_factory=list)

    @property
    def constructed(self) -> bool:
        """True if the tag's constructed bit (0x20 in the leading byte) is set."""
        lead = self.tag
        while lead > 0xFF:
            lead >>= 8
        return bool(lead & 0x20)

    def tag_hex(self) -> str:
        length = max(1, (self.tag.bit_length() + 7) // 8)
        return self.tag.to_bytes(length, "big").hex().upper()


def _read_tag(data: bytes, off: int) -> tuple[int, int]:
    if off >= len(data):
        raise ValueError("truncated tag")
    start = off
    first = data[off]
    off += 1
    tag = first
    if (first & 0x1F) == 0x1F:  # multi-byte tag
        while True:
            if off >= len(data):
                raise ValueError("truncated multi-byte tag")
            b = data[off]
            tag = (tag << 8) | b
            off += 1
            if not (b & 0x80):
                break
    _ = start
    return tag, off


def _read_len(data: bytes, off: int) -> tuple[int, int]:
    if off >= len(data):
        raise ValueError("truncated length")
    first = data[off]
    off += 1
    if first < 0x80:
        return first, off
    num = first & 0x7F
    if num == 0 or num > 4:
        raise ValueError(f"unsupported BER length form: 0x{first:02X}")
    if off + num > len(data):
        raise ValueError("truncated length field")
    length = int.from_bytes(data[off : off + num], "big")
    return length, off + num


def parse(data: bytes | bytearray, *, recurse: bool = True) -> list[TLV]:
    """Parse a concatenation of TLVs at the top level."""
    data = bytes(data)
    out: list[TLV] = []
    off = 0
    n = len(data)
    while off < n:
        tag, off = _read_tag(data, off)
        length, off = _read_len(data, off)
        if off + length > n:
            raise ValueError("TLV value extends beyond buffer")
        value = data[off : off + length]
        off += length
        node = TLV(tag=tag, value=value)
        if recurse and node.constructed:
            try:
                node.children = parse(value, recurse=True)
            except ValueError:
                node.children = []  # not actually constructed payload; keep raw value
        out.append(node)
    return out


def find(tlvs: list[TLV], tag: int) -> TLV | None:
    """Depth-first search for the first TLV with ``tag``."""
    for t in tlvs:
        if t.tag == tag:
            return t
        if t.children:
            hit = find(t.children, tag)
            if hit is not None:
                return hit
    return None


# --------------------------------------------------------------------------- #
# Encoders (BER-TLV) — mirror the applet's perso toolkit byte-for-byte.        #
# --------------------------------------------------------------------------- #
def encode_tag(tag: int) -> bytes:
    """Encode a numeric tag big-endian by its natural byte width (1..3 bytes)."""
    if tag < 0:
        raise ValueError("tag must be non-negative")
    if tag <= 0xFF:
        return bytes([tag])
    if tag <= 0xFFFF:
        return bytes([(tag >> 8) & 0xFF, tag & 0xFF])
    if tag <= 0xFFFFFF:
        return bytes([(tag >> 16) & 0xFF, (tag >> 8) & 0xFF, tag & 0xFF])
    raise ValueError(f"tag too large: {tag:#x}")


def encode_length(n: int) -> bytes:
    """BER length: short form < 0x80, else long form (0x81/0x82/0x83 + bytes)."""
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return bytes([0x81, n])
    if n < 0x10000:
        return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])
    if n < 0x1000000:
        return bytes([0x83, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF])
    raise ValueError(f"value too long: {n}")


def build(tag: int, value: bytes = b"") -> bytes:
    """Build a single primitive/constructed TLV."""
    value = bytes(value)
    return encode_tag(tag) + encode_length(len(value)) + value


def concat(*parts: bytes) -> bytes:
    return b"".join(bytes(p) for p in parts)


def build_constructed(tag: int, *children: bytes) -> bytes:
    """Build a constructed TLV whose value is the concatenation of children."""
    return build(tag, concat(*children))
