"""Golden-vector tests for the pre-perso grammar (vs the applet's own toolkit)."""

from cryptnox_id_cli.applets.piv import preperso as p
from cryptnox_id_cli.util.tlv import encode_length


def test_create_key_admin_9b():
    op = p.create_key(
        0x9B,
        p.MODE_ALWAYS,
        p.MODE_NEVER,
        0x0C,
        p.ROLE_AUTHENTICATE,
        p.ATTR_IMPORTABLE | p.ATTR_PERMIT_MUTUAL,
    )
    assert op.hex().upper() == "66128B019B8C013F8D01008E010C8F0101900118"


def test_create_key_9a_with_admin_tag():
    op = p.create_key(
        0x9A, p.MODE_PIN, p.MODE_NEVER, 0x07, p.ROLE_AUTHENTICATE, p.ATTR_IMPORTABLE, admin_key=0x9B
    )
    assert op.hex().upper() == "66158B019A8C01018D010091019B8E01078F0101900110"


def test_create_container_chuid():
    op = p.create_container(bytes.fromhex("5FC102"), p.MODE_ALWAYS, p.MODE_NEVER, admin_key=0x9B)
    assert op.hex().upper() == "640E8B035FC1028C013F8D010091019B"


def test_create_verifier_local_pin():
    op = p.create_verifier(0x80, p.MODE_ALWAYS, p.MODE_NEVER, 6, 8, 3, 0, charset=0x00)
    assert op.hex().upper() == "65188B01808C013F8D01008E01068F0108900103910100920100"


def test_bulk_length():
    c = p.create_container(bytes.fromhex("5FC102"), p.MODE_ALWAYS, p.MODE_NEVER, admin_key=0x9B)
    v = p.create_verifier(0x80, p.MODE_ALWAYS, p.MODE_NEVER, 6, 8, 3, 0, charset=0x00)
    k = p.create_key(
        0x9B,
        p.MODE_ALWAYS,
        p.MODE_NEVER,
        0x0C,
        p.ROLE_AUTHENTICATE,
        p.ATTR_IMPORTABLE | p.ATTR_PERMIT_MUTUAL,
    )
    ka = p.create_key(
        0x9A, p.MODE_PIN, p.MODE_NEVER, 0x07, p.ROLE_AUTHENTICATE, p.ATTR_IMPORTABLE, admin_key=0x9B
    )
    assert len(p.build_bulk([c, v, k, ka])) == 87


def test_secure_applet_is_empty_primitive():
    assert p.secure_applet().hex().upper() == "5F00"


def test_long_form_length():
    assert encode_length(200) == bytes([0x81, 200])
    assert encode_length(0x0138) == bytes([0x82, 0x01, 0x38])  # the 316-byte BULK uses this
