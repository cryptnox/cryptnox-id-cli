"""Parse the PIV Application Property Template (returned by SELECT)."""

from __future__ import annotations

from dataclasses import dataclass

from cryptnox_id_cli.util import tlv

TAG_APT = 0x61
TAG_AID = 0x4F
TAG_APP_LABEL = 0x50
TAG_URL = 0x5F50
TAG_ALLOC_AUTHORITY = 0x79


@dataclass(frozen=True)
class APTInfo:
    raw: bytes
    aid: bytes | None
    label: str | None
    url: str | None

    @property
    def aid_hex(self) -> str | None:
        return self.aid.hex().upper() if self.aid is not None else None

    def to_dict(self) -> dict[str, object]:
        return {"aid": self.aid_hex, "label": self.label, "url": self.url}


def _decode_ascii(value: bytes | None) -> str | None:
    if value is None:
        return None
    try:
        return value.decode("ascii").rstrip("\x00") or None
    except UnicodeDecodeError:
        return value.decode("latin-1", "replace")


def parse_apt(data: bytes) -> APTInfo:
    """Parse the APT, extracting AID, application label and discovery URL."""
    try:
        tlvs = tlv.parse(data)
    except ValueError:
        return APTInfo(raw=bytes(data), aid=None, label=None, url=None)

    template = tlv.find(tlvs, TAG_APT)
    scope = template.children if (template and template.children) else tlvs

    aid_node = next((t for t in scope if t.tag == TAG_AID), None)  # the direct AID, not the RID
    label_node = tlv.find(scope, TAG_APP_LABEL)
    url_node = tlv.find(scope, TAG_URL)
    return APTInfo(
        raw=bytes(data),
        aid=aid_node.value if aid_node else None,
        label=_decode_ascii(label_node.value if label_node else None),
        url=_decode_ascii(url_node.value if url_node else None),
    )
