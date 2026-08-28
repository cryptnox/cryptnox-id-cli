"""Profile tests, including a byte-exact match to the applet's FIPS reference BULK."""

import pytest

from cryptnox_id_cli.applets.piv import profiles

# Captured from the applet toolkit `profile_fips.py` (default: AES-256 admin, ECC-P256).
GOLDEN_DEFAULT = (
    "6A820138640E8B035FC1028C013F8D013F91019B640E8B035FC1078C013F8D014091019B640E8B035FC105"
    "8C013F8D014091019B640E8B035FC1018C013F8D013F91019B640E8B035FC10A8C013F8D014091019B640E"
    "8B035FC10B8C013F8D014091019B640E8B035FC1068C013F8D014091019B640E8B035FC1038C01018D0141"
    "91019B640E8B035FC1088C01018D014191019B640E8B035FC1098C01018D014191019B65188B01808C013F"
    "8D01008E01068F010890010691010092010065188B01818C013F8D01008E01088F0108900106910100920100"
    "66128B019B8C013F8D01008E010C8F010190011C66128B019A8C01018D01008E01118F0101900110"
    "66128B019C8C01018D01008E01118F010490011066128B019D8C01018D01008E01118F0102900110"
    "66128B019E8C013F8D013F8E01118F0101900110"
)


def test_cryptnox_default_matches_reference():
    prof = profiles.builtin("cryptnox-default")
    assert prof.validate() == []
    assert prof.build_payload().hex().upper() == GOLDEN_DEFAULT


def test_yaml_roundtrip_preserves_payload():
    prof = profiles.builtin("cryptnox-default")
    reloaded = profiles.from_yaml(prof.to_yaml())
    assert reloaded.build_payload() == prof.build_payload()


def test_all_builtins_valid():
    for name in profiles.builtin_names():
        assert profiles.builtin(name).validate() == []


def test_validation_rejects_unsupported_algorithm():
    prof = profiles.builtin("cryptnox-default")
    prof.keys[1].mechanism = 0x06  # RSA-1024, removed on this FIPS build
    assert any("not supported" in e for e in prof.validate())


def test_validation_rejects_short_pin():
    prof = profiles.builtin("cryptnox-default")
    prof.pin.min_length = 4
    assert any("min_length" in e for e in prof.validate())


def test_from_yaml_rejects_unknown_mode():
    bad = (
        "name: x\nmode: production\nadmin: {key_ref: '9B', mechanism: AES256}\n"
        "pin: {min: 6, max: 8, retries: 6}\npuk: {min: 8, max: 8, retries: 6}\n"
        "containers: [{oid: 5FC102, name: chuid, contact: NOPE, contactless: ALWAYS}]\n"
    )
    with pytest.raises(profiles.ProfileError):
        profiles.from_yaml(bad)


# ------------------------------------------------------------- ms-logon ---- #
def test_ms_logon_9a_is_sign_capable():
    """The applet dispatches PKI challenge signing on ROLE_SIGN only, and routes
    KEY_ESTABLISH first - 9A must be exactly SIGN|AUTHENTICATE (0x05)."""
    prof = profiles.builtin("ms-logon")
    auth_keys = [k for k in prof.keys if k.ref == 0x9A]
    assert len(auth_keys) == 2  # on-card ECC + importable RSA, coexisting by mechanism
    assert {k.mechanism for k in auth_keys} == {0x11, 0x07}
    for k in auth_keys:
        assert k.role == 0x05  # SIGN | AUTHENTICATE, no KEY_ESTABLISH bit
    rsa = next(k for k in auth_keys if k.mechanism == 0x07)
    assert rsa.attributes & 0x10 and rsa.attributes & 0x20  # IMPORTABLE | RSA_CRT


def test_ms_logon_only_changes_9a():
    base = {(k.ref, k.mechanism): k.role for k in profiles.builtin("cryptnox-default").keys}
    ms = profiles.builtin("ms-logon")
    for k in ms.keys:
        if k.ref != 0x9A:
            assert k.role == base[(k.ref, k.mechanism)]


def test_ms_logon_yaml_roundtrip_preserves_payload():
    prof = profiles.builtin("ms-logon")
    text = prof.to_yaml()
    assert "AUTHENTICATE+SIGN" in text  # combined role serializes by name, not hex
    assert profiles.from_yaml(text).build_payload() == prof.build_payload()


# ------------------------------------------------------------------ ssh ---- #
def test_ssh_9a_is_sign_capable():
    prof = profiles.builtin("ssh")
    auth_keys = [k for k in prof.keys if k.ref == 0x9A]
    assert len(auth_keys) == 1  # no second RSA object, unlike ms-logon
    assert auth_keys[0].role == 0x05  # SIGN | AUTHENTICATE, no KEY_ESTABLISH bit


def test_ssh_only_changes_9a():
    base = {(k.ref, k.mechanism): k.role for k in profiles.builtin("cryptnox-default").keys}
    ssh = profiles.builtin("ssh")
    for k in ssh.keys:
        if k.ref != 0x9A:
            assert k.role == base[(k.ref, k.mechanism)]


def test_ssh_yaml_roundtrip_preserves_payload():
    prof = profiles.builtin("ssh")
    text = prof.to_yaml()
    assert "AUTHENTICATE+SIGN" in text  # combined role serializes by name, not hex
    assert profiles.from_yaml(text).build_payload() == prof.build_payload()


def test_role_parsing_forms():
    assert profiles._role("SIGN") == 0x04
    assert profiles._role("sign+authenticate") == 0x05
    assert profiles._role(["SIGN", "AUTHENTICATE"]) == 0x05
    assert profiles._role(0x05) == 0x05
    with pytest.raises(profiles.ProfileError):
        profiles._role("SIGN+NOPE")
