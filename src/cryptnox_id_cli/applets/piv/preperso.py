"""OpenFIPS201 PUT DATA ADMIN grammar (pre-personalization / factory).

Mirrors the applet's own perso toolkit (``tools/perso/piv_admin.py``) byte-for-byte.
Builders emit only the CDATA; the SCP03 layer wraps it into the secured APDU
``84 DB 3F 00 <Lc> <payload> <C-MAC>``.

Create-object parse order enforced by the applet (sequential TLVReader):
  common prefix:  8B object-id, 8C mode-contact, 8D mode-contactless, [91 admin-key]
  CONTAINER (0x64): nothing further
  VERIFIER  (0x65): 8E min-len, 8F max-len, 90 retries-contact, 91 retries-contactless,
                    [92 charset] [93 history] [94 sequence] [95 repeat] [96 restrict-update]
  KEY       (0x66): 8E mechanism, 8F role, 90 attributes
The order is significant — do not reorder elements.
"""

from __future__ import annotations

from collections.abc import Sequence

from cryptnox_id_cli.transport.apdu import APDU
from cryptnox_id_cli.util.tlv import build, build_constructed, concat

# PUT DATA ADMIN command header.
INS_PUT_DATA = 0xDB
PUT_DATA_P1 = 0x3F
PUT_DATA_P2_ADMIN = 0x00

# Operation tags.
OP_CREATE_CONTAINER = 0x64
OP_CREATE_VERIFIER = 0x65
OP_CREATE_KEY = 0x66
OP_UPDATE_CONFIG = 0x68
OP_SECURE_APPLET = 0x5F
OP_BULK_REQUEST = 0x6A

# Common element tags.
TAG_OBJECT_ID = 0x8B
TAG_MODE_CONTACT = 0x8C
TAG_MODE_CONTACTLESS = 0x8D
TAG_ADMIN_KEY = 0x91  # optional, container/key only (NOT verifier)

# Key element tags.
TAG_KEY_MECHANISM = 0x8E
TAG_KEY_ROLE = 0x8F
TAG_KEY_ATTRIBUTE = 0x90

# Verifier element tags.
TAG_PIN_MIN_LENGTH = 0x8E
TAG_PIN_MAX_LENGTH = 0x8F
TAG_PIN_RETRIES_CONTACT = 0x90
TAG_PIN_RETRIES_CONTACTLESS = 0x91
TAG_PIN_RULE_CHARSET = 0x92
TAG_PIN_RULE_HISTORY = 0x93
TAG_PIN_RULE_SEQUENCE = 0x94
TAG_PIN_RULE_REPEAT = 0x95
TAG_PIN_RESTRICT_UPDATE = 0x96

# Access-mode bytes. A mode is a bitmap EXCEPT ALWAYS which is the special 0x3F.
MODE_NEVER = 0x00
MODE_PIN = 0x01
MODE_OCC = 0x04
MODE_SM = 0x40
MODE_USER_ADMIN = 0x80
MODE_ALWAYS = 0x3F
MODE_VCI = MODE_SM  # 0x40 (contactless read gated to a PIV-SM session)
MODE_VCI_PIN = MODE_SM | MODE_PIN  # 0x41

# Key roles and attributes (bitmaps).
ROLE_AUTHENTICATE = 0x01
ROLE_KEY_ESTABLISH = 0x02
ROLE_SIGN = 0x04

ATTR_PERMIT_EXTERNAL = 0x04
ATTR_PERMIT_MUTUAL = 0x08
ATTR_IMPORTABLE = 0x10
ATTR_RSA_CRT = 0x20


def _object_id_bytes(object_id: int | bytes | Sequence[int]) -> bytes:
    if isinstance(object_id, int):
        return bytes([object_id])
    return bytes(object_id)


def create_container(
    object_id: int | bytes,
    mode_contact: int,
    mode_contactless: int,
    admin_key: int | None = None,
) -> bytes:
    parts = [
        build(TAG_OBJECT_ID, _object_id_bytes(object_id)),
        build(TAG_MODE_CONTACT, bytes([mode_contact])),
        build(TAG_MODE_CONTACTLESS, bytes([mode_contactless])),
    ]
    if admin_key is not None:
        parts.append(build(TAG_ADMIN_KEY, bytes([admin_key])))
    return build_constructed(OP_CREATE_CONTAINER, *parts)


def create_verifier(
    verifier_id: int,
    mode_contact: int,
    mode_contactless: int,
    min_length: int,
    max_length: int,
    retries_contact: int,
    retries_contactless: int,
    charset: int | None = None,
    history: int | None = None,
    sequence: int | None = None,
    repeat: int | None = None,
    restrict_update: int | None = None,
) -> bytes:
    parts = [
        build(TAG_OBJECT_ID, bytes([verifier_id])),
        build(TAG_MODE_CONTACT, bytes([mode_contact])),
        build(TAG_MODE_CONTACTLESS, bytes([mode_contactless])),
        build(TAG_PIN_MIN_LENGTH, bytes([min_length])),
        build(TAG_PIN_MAX_LENGTH, bytes([max_length])),
        build(TAG_PIN_RETRIES_CONTACT, bytes([retries_contact])),
        build(TAG_PIN_RETRIES_CONTACTLESS, bytes([retries_contactless])),
    ]
    for tag, val in (
        (TAG_PIN_RULE_CHARSET, charset),
        (TAG_PIN_RULE_HISTORY, history),
        (TAG_PIN_RULE_SEQUENCE, sequence),
        (TAG_PIN_RULE_REPEAT, repeat),
        (TAG_PIN_RESTRICT_UPDATE, restrict_update),
    ):
        if val is not None:
            parts.append(build(tag, bytes([val])))
    return build_constructed(OP_CREATE_VERIFIER, *parts)


def create_key(
    key_id: int,
    mode_contact: int,
    mode_contactless: int,
    mechanism: int,
    role: int,
    attributes: int,
    admin_key: int | None = None,
) -> bytes:
    parts = [
        build(TAG_OBJECT_ID, bytes([key_id])),
        build(TAG_MODE_CONTACT, bytes([mode_contact])),
        build(TAG_MODE_CONTACTLESS, bytes([mode_contactless])),
    ]
    if admin_key is not None:
        parts.append(build(TAG_ADMIN_KEY, bytes([admin_key])))
    parts.extend(
        [
            build(TAG_KEY_MECHANISM, bytes([mechanism])),
            build(TAG_KEY_ROLE, bytes([role])),
            build(TAG_KEY_ATTRIBUTE, bytes([attributes])),
        ]
    )
    return build_constructed(OP_CREATE_KEY, *parts)


def secure_applet() -> bytes:
    """SECURE APPLET (0x5F) — primitive, empty body. IRREVERSIBLE (locks the applet)."""
    return build(OP_SECURE_APPLET, b"")


def build_bulk(ops: Sequence[bytes]) -> bytes:
    """Wrap operation TLVs into a BULK request (0x6A)."""
    return build_constructed(OP_BULK_REQUEST, concat(*ops))


def put_data_admin_apdu(payload: bytes) -> APDU:
    """The (unsecured) PUT DATA ADMIN command; the SCP03 layer secures/wraps it."""
    return APDU(0x00, INS_PUT_DATA, PUT_DATA_P1, PUT_DATA_P2_ADMIN, data=payload)
