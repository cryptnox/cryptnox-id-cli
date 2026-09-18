"""The relay policy: what a hostile or confused service cannot make the card do."""

import pytest

from cryptnox_id_cli.remote import policy as pol
from cryptnox_id_cli.transport.errors import RemotePolicyError

WALLET_AID = bytes.fromhex("A0000010000112")
FIDO2_AID = bytes.fromhex("A0000006472F0001")
GENUINE_AID = bytes.fromhex("A000001000024701")
DESFIRE_AID = bytes.fromhex("D2760000850100")


def select(aid: bytes) -> bytes:
    return bytes([0x00, 0xA4, 0x04, 0x00, len(aid)]) + aid + b"\x00"


def apdu(cla: int, ins: int, p1: int = 0, p2: int = 0, data: bytes = b"", le: bool = True) -> bytes:
    out = bytes([cla, ins, p1, p2])
    if data:
        out += bytes([len(data)]) + data
    if le:
        out += b"\x00"
    return out


CPLC = apdu(0x80, 0xCA, 0x9F, 0x7F)
KEY_INFO = apdu(0x80, 0xCA, 0x00, 0xE0)
INIT_UPDATE = apdu(0x80, 0x50, 0x00, 0x00, bytes(8))
EXT_AUTH = apdu(0x84, 0x82, 0x00, 0x00, bytes(16), le=False)
PIV_GET_DATA = apdu(0x00, 0xCB, 0x3F, 0xFF, bytes.fromhex("5C035FC102"))


def allow(policy: pol.RelayPolicy, command: bytes, sw=(0x90, 0x00)) -> None:
    policy.check(command)
    policy.observe(command, *sw)


# --------------------------------------------------------------------------- #
# Header parsing                                                              #
# --------------------------------------------------------------------------- #
def test_channel_bits_are_decoded():
    assert pol.Header(0x00, 0, 0, 0).channel == 0
    assert pol.Header(0x01, 0, 0, 0).channel == 1
    assert pol.Header(0x83, 0, 0, 0).channel == 3
    assert pol.Header(0x40, 0, 0, 0).channel == 4
    assert pol.Header(0x4F, 0, 0, 0).channel == 19


def test_gp_secure_messaging_is_recognised():
    assert pol.Header(0x84, 0, 0, 0).secure_messaging is True
    assert pol.Header(0x80, 0, 0, 0).secure_messaging is False
    assert pol.Header(0x00, 0, 0, 0).secure_messaging is False


def test_select_target_extracts_the_aid():
    assert pol.select_target(select(pol.PIV_AID)) == pol.PIV_AID
    assert pol.select_target(bytes.fromhex("00A4040000")) == b""
    assert pol.select_target(CPLC) is None


def test_select_by_file_id_is_refused_not_ignored():
    with pytest.raises(RemotePolicyError, match="not select-by-name"):
        pol.select_target(bytes.fromhex("00A40000023F00"))


def test_extended_length_select_is_refused():
    with pytest.raises(RemotePolicyError, match="extended-length"):
        pol.select_target(bytes.fromhex("00A40400000009") + pol.PIV_SSD_AID)


def test_select_with_short_data_is_refused():
    with pytest.raises(RemotePolicyError, match="shorter than its length"):
        pol.select_target(bytes.fromhex("00A404000BA000"))


# --------------------------------------------------------------------------- #
# Operations without rules                                                    #
# --------------------------------------------------------------------------- #
def test_operations_without_rules_are_refused_up_front():
    with pytest.raises(RemotePolicyError, match="no relay policy"):
        pol.RelayPolicy("reset")


# --------------------------------------------------------------------------- #
# authenticate: ATR + CPLC, nothing else                                      #
# --------------------------------------------------------------------------- #
def test_authenticate_allows_cplc_from_the_card_manager():
    policy = pol.RelayPolicy("authenticate")
    allow(policy, CPLC)
    allow(policy, KEY_INFO)
    allow(policy, select(pol.ISD_AID))
    allow(policy, bytes.fromhex("00A4040000"))  # select the default applet
    assert policy.context == pol.ISD


def test_authenticate_refuses_selecting_the_piv_domains():
    policy = pol.RelayPolicy("authenticate")
    for aid in (pol.PIV_SSD_AID, pol.PIV_AID):
        with pytest.raises(RemotePolicyError, match="not allowed during authenticate"):
            policy.check(select(aid))


def test_authenticate_refuses_initialize_update():
    policy = pol.RelayPolicy("authenticate")
    with pytest.raises(RemotePolicyError, match="not allowed while the isd"):
        policy.check(INIT_UPDATE)


# --------------------------------------------------------------------------- #
# Every operation: the other card functions are unreachable                   #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("op", pol.READ_ONLY_OPS)
@pytest.mark.parametrize("aid", [WALLET_AID, FIDO2_AID, GENUINE_AID, DESFIRE_AID])
def test_other_card_functions_cannot_be_selected(op, aid):
    policy = pol.RelayPolicy(op)
    with pytest.raises(RemotePolicyError, match="SELECT of AID") as info:
        policy.check(select(aid))
    assert info.value.header == "00A40400"


@pytest.mark.parametrize("op", pol.READ_ONLY_OPS)
def test_partial_aid_select_cannot_sneak_past_the_allow_list(op):
    policy = pol.RelayPolicy(op)
    with pytest.raises(RemotePolicyError, match="SELECT of AID"):
        policy.check(select(pol.PIV_AID[:5]))


@pytest.mark.parametrize("op", pol.READ_ONLY_OPS)
def test_ctap_framing_is_refused(op):
    policy = pol.RelayPolicy(op)
    with pytest.raises(RemotePolicyError, match="CTAP"):
        policy.check(apdu(0x80, 0x10, 0x00, 0x00, b"\x04"))


@pytest.mark.parametrize("op", pol.READ_ONLY_OPS)
def test_desfire_wrapping_is_refused(op):
    policy = pol.RelayPolicy(op)
    with pytest.raises(RemotePolicyError, match="DESFire"):
        policy.check(apdu(0x90, 0x60))


@pytest.mark.parametrize("op", pol.READ_ONLY_OPS)
def test_logical_channels_are_refused(op):
    policy = pol.RelayPolicy(op)
    with pytest.raises(RemotePolicyError, match="logical channel 1"):
        policy.check(apdu(0x01, 0xCA, 0x9F, 0x7F))
    with pytest.raises(RemotePolicyError, match="logical channel 4"):
        policy.check(apdu(0x40, 0xCA, 0x9F, 0x7F))


@pytest.mark.parametrize("op", pol.READ_ONLY_OPS)
@pytest.mark.parametrize("ins", [0x20, 0x24, 0x2C])
def test_card_holder_verifier_commands_are_never_relayed(op, ins):
    policy = pol.RelayPolicy(op)
    with pytest.raises(RemotePolicyError, match="never relayed"):
        policy.check(apdu(0x00, ins, 0x00, 0x80, b"\xff" * 8, le=False))


@pytest.mark.parametrize("op", pol.READ_ONLY_OPS)
def test_iso_secure_messaging_class_is_refused(op):
    policy = pol.RelayPolicy(op)
    with pytest.raises(RemotePolicyError, match="ISO secure messaging"):
        policy.check(apdu(0x0C, 0xCA, 0x9F, 0x7F))


# --------------------------------------------------------------------------- #
# inspect: probe, but never authenticate                                      #
# --------------------------------------------------------------------------- #
def test_inspect_follows_the_selected_applet():
    policy = pol.RelayPolicy("inspect")
    allow(policy, CPLC)
    allow(policy, select(pol.PIV_SSD_AID))
    assert policy.context == pol.PIV_SSD
    allow(policy, KEY_INFO)
    allow(policy, select(pol.PIV_AID))
    assert policy.context == pol.PIV
    allow(policy, PIV_GET_DATA)


def test_a_failed_select_does_not_move_the_context():
    policy = pol.RelayPolicy("inspect")
    allow(policy, select(pol.PIV_SSD_AID), sw=(0x6A, 0x82))
    assert policy.context == pol.ISD
    allow(policy, KEY_INFO)  # still the card manager's key table


def test_piv_context_allows_only_piv_reads():
    policy = pol.RelayPolicy("inspect")
    allow(policy, select(pol.PIV_AID))
    for forbidden in (
        apdu(0x00, 0x47, 0x00, 0x9C, b"\xac\x03\x80\x01\x11", le=False),  # GENERATE
        apdu(0x00, 0xDB, 0x3F, 0xFF, b"\x5c\x03\x5f\xc1\x02", le=False),  # PUT DATA
        apdu(0x00, 0x87, 0x11, 0x9B, b"\x7c\x02\x81\x00", le=False),  # GENERAL AUTH
        apdu(0x80, 0xCA, 0x9F, 0x7F),  # GP GET DATA is not a PIV command
        INIT_UPDATE,
    ):
        with pytest.raises(RemotePolicyError, match="not allowed while the piv"):
            policy.check(forbidden)


def test_inspect_caps_initialize_updates_per_domain():
    policy = pol.RelayPolicy("inspect")
    budget = policy.rules.max_initialize_updates
    for _ in range(budget):
        allow(policy, INIT_UPDATE)  # to the card manager, probing key versions
    with pytest.raises(RemotePolicyError, match=f"more than {budget} time"):
        policy.check(INIT_UPDATE)
    allow(policy, select(pol.PIV_SSD_AID))
    for _ in range(budget):
        allow(policy, INIT_UPDATE)  # a fresh budget for the PIV security domain
    with pytest.raises(RemotePolicyError, match=f"more than {budget} time"):
        policy.check(INIT_UPDATE)


def test_inspect_never_relays_external_authenticate():
    policy = pol.RelayPolicy("inspect")
    allow(policy, INIT_UPDATE)
    with pytest.raises(RemotePolicyError, match="EXTERNAL AUTHENTICATE"):
        policy.check(EXT_AUTH)


def test_a_failed_select_leaves_the_initialize_update_budget_alone():
    policy = pol.RelayPolicy("inspect")
    allow(policy, select(pol.PIV_SSD_AID), sw=(0x6A, 0x82))
    allow(policy, INIT_UPDATE)  # still counts against the card manager
    assert policy.initialize_updates == {pol.ISD: 1}


# --------------------------------------------------------------------------- #
# Volume                                                                      #
# --------------------------------------------------------------------------- #
def test_command_budget_is_enforced():
    policy = pol.RelayPolicy("authenticate")
    for _ in range(policy.rules.max_apdus):
        allow(policy, CPLC)
    with pytest.raises(RemotePolicyError, match="more than 20 commands"):
        policy.check(CPLC)


def test_a_refused_command_is_not_counted():
    policy = pol.RelayPolicy("authenticate")
    with pytest.raises(RemotePolicyError):
        policy.check(INIT_UPDATE)
    assert policy.apdus == 0


def test_refusal_carries_the_header_for_review():
    policy = pol.RelayPolicy("authenticate")
    with pytest.raises(RemotePolicyError) as info:
        policy.check(apdu(0x00, 0x47, 0x00, 0x9C))
    assert info.value.header == "0047009C"
    assert info.value.to_dict()["apdu_header"] == "0047009C"
