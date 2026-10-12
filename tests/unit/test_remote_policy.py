"""The relay policy: what a hostile or confused service cannot make the card do."""

import dataclasses

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
# Security level in P1: 01 = C-MAC only (what the service uses on the card
# manager), 03 = C-MAC + command encryption (what it uses on the applet).
EXT_AUTH = apdu(0x84, 0x82, 0x01, 0x00, bytes(16), le=False)
EXT_AUTH_ENC = apdu(0x84, 0x82, 0x03, 0x00, bytes(16), le=False)
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


def test_extended_length_select_is_read_like_the_short_form():
    extended = bytes.fromhex("00A40400000009") + pol.PIV_SSD_AID
    assert pol.select_target(extended) == pol.PIV_SSD_AID
    assert pol.select_target(extended + b"\x00\x00") == pol.PIV_SSD_AID


def test_command_data_reads_both_encodings():
    assert pol.command_data(bytes.fromhex("80CA9F7F")) == b""
    assert pol.command_data(bytes.fromhex("80CA9F7F00")) == b""  # short Le, no data
    assert pol.command_data(bytes.fromhex("80CA9F7F000000")) == b""  # extended Le, no data
    assert pol.command_data(bytes.fromhex("00A404000102")) == b"\x02"
    assert pol.command_data(bytes.fromhex("00A40400010200")) == b"\x02"
    assert pol.command_data(bytes.fromhex("00A4040000000102")) == b"\x02"
    assert pol.command_data(bytes.fromhex("00A40400000001020000")) == b"\x02"


@pytest.mark.parametrize(
    "command",
    [
        "00A404000BA000",  # short Lc longer than the data
        "00A40400020102FFFF",  # short form with two trailing bytes
        "00A404000002",  # extended form cut after the first length byte
        "00A40400000000AABB",  # extended Lc of zero
        "00A40400000009A000",  # extended Lc longer than the data
        "00A4040000000102FF",  # extended form with one trailing byte
    ],
)
def test_malformed_command_lengths_are_refused(command):
    with pytest.raises(RemotePolicyError, match="length fields"):
        pol.command_data(bytes.fromhex(command))


# --------------------------------------------------------------------------- #
# Operations without rules                                                    #
# --------------------------------------------------------------------------- #
def test_operations_without_rules_are_refused_up_front():
    with pytest.raises(RemotePolicyError, match="no relay policy"):
        pol.RelayPolicy("format-everything")


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


@pytest.mark.parametrize("op", ["reset", "dev-reset", "attest"])
@pytest.mark.parametrize("ref", sorted(pol.CARDHOLDER_REFS))
def test_card_holder_references_are_denied_even_where_9b_is_allowed(op, ref):
    policy = pol.RelayPolicy(op, slot=0x9C) if op == "attest" else pol.RelayPolicy(op)
    for ins in (0x20, 0x24, 0x2C):
        with pytest.raises(RemotePolicyError, match="never relayed"):
            policy.check(apdu(0x04, ins, 0x00, ref, b"\xff" * 8, le=False))


@pytest.mark.parametrize("op", ["reset", "dev-reset"])
def test_setting_the_management_key_is_allowed_where_the_rules_say_so(op):
    policy = pol.RelayPolicy(op)
    allow(policy, select(pol.PIV_AID))
    policy.check(apdu(0x04, 0x24, 0x08, pol.MANAGEMENT_KEY_REF, b"\x00" * 24, le=False))


def test_setting_the_management_key_is_allowed_during_attest():
    policy = pol.RelayPolicy("attest", slot=0x9C)
    allow(policy, select(pol.PIV_AID))
    policy.check(apdu(0x04, 0x24, 0x08, pol.MANAGEMENT_KEY_REF, b"\x00" * 24, le=False))


@pytest.mark.parametrize("op", pol.READ_ONLY_OPS)
def test_read_only_operations_may_not_touch_the_management_key(op):
    policy = pol.RelayPolicy(op)
    with pytest.raises(RemotePolicyError, match="never relayed"):
        policy.check(apdu(0x04, 0x24, 0x08, pol.MANAGEMENT_KEY_REF, b"\x00" * 24, le=False))


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


def test_a_select_answered_61xx_moves_the_context():
    # 61XX is success with the response waiting for GET RESPONSE, the normal
    # answer to a SELECT that returns data on a T=0 reader.
    policy = pol.RelayPolicy("reset")
    allow(policy, select(pol.PIV_AID), sw=(0x61, 0x1A))
    assert policy.context == pol.PIV
    allow(policy, apdu(0x00, 0xC0, 0x00, 0x00))
    with pytest.raises(RemotePolicyError, match="not allowed while the piv is selected"):
        policy.check(wrapped(0xE4))


@pytest.mark.parametrize("sw", [(0x6C, 0x1A), (0x62, 0x83), (0x63, 0x00)])
def test_a_select_with_an_uncertain_answer_admits_only_another_select(sw):
    policy = pol.RelayPolicy("inspect")
    allow(policy, select(pol.PIV_AID), sw=sw)
    assert policy.context == pol.UNKNOWN
    for command in (KEY_INFO, PIV_GET_DATA, INIT_UPDATE):
        with pytest.raises(RemotePolicyError, match="selected applet is unknown"):
            policy.check(command)
    allow(policy, select(pol.ISD_AID))
    assert policy.context == pol.ISD
    allow(policy, KEY_INFO)


def test_a_selectable_aid_without_a_context_is_refused():
    policy = pol.RelayPolicy("inspect")
    policy.rules = dataclasses.replace(
        policy.rules, selectable=policy.rules.selectable | {WALLET_AID}
    )
    with pytest.raises(RemotePolicyError, match="no relay context"):
        policy.check(select(WALLET_AID))


def test_piv_context_allows_only_piv_reads():
    policy = pol.RelayPolicy("inspect")
    allow(policy, select(pol.PIV_AID))
    for forbidden in (
        apdu(0x00, 0x47, 0x00, 0x9C, b"\xac\x03\x80\x01\x11", le=False),  # GENERATE
        apdu(0x00, 0xDB, 0x3F, 0xFF, b"\x5c\x03\x5f\xc1\x02", le=False),  # PUT DATA
        apdu(0x00, 0x87, 0x11, 0x9B, b"\x7c\x02\x81\x00", le=False),  # GENERAL AUTH
        apdu(0x80, 0xCA, 0x9F, 0x7F),  # GP GET DATA is not a PIV command
    ):
        with pytest.raises(RemotePolicyError, match="not allowed while the piv"):
            policy.check(forbidden)
    # The applet's admin channel may be probed, never authenticated.
    allow(policy, INIT_UPDATE)
    with pytest.raises(RemotePolicyError, match="EXTERNAL AUTHENTICATE"):
        policy.check(EXT_AUTH)


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


# --------------------------------------------------------------------------- #
# reset / dev-reset: card content management, PIV only                        #
# --------------------------------------------------------------------------- #
PIV_PACKAGE_AID = pol.PIV_PACKAGE_AID
FIDO2_PACKAGE_AID = bytes.fromhex("A000000647")
SSD_PACKAGE_AID = bytes.fromhex("A0000001515350")


def delete_apdu(aid: bytes, cla: int = 0x84, mac: bytes = b"\x00" * 8) -> bytes:
    data = bytes([0x4F, len(aid)]) + aid + mac
    return bytes([cla, 0xE4, 0x00, 0x00, len(data)]) + data + b"\x00"


def delete_apdu_extended(aid: bytes, cla: int = 0x84, mac: bytes = b"\x00" * 8) -> bytes:
    data = bytes([0x4F, len(aid)]) + aid + mac
    return bytes([cla, 0xE4, 0x00, 0x00, 0x00]) + len(data).to_bytes(2, "big") + data


def wrapped(ins: int, p1: int = 0, p2: int = 0, n: int = 24) -> bytes:
    return apdu(0x84, ins, p1, p2, b"\x00" * n, le=False)


@pytest.mark.parametrize("op", pol.DESTRUCTIVE_OPS)
def test_reset_follows_the_documented_flow(op):
    policy = pol.RelayPolicy(op)
    allow(policy, CPLC)
    allow(policy, INIT_UPDATE)
    allow(policy, EXT_AUTH)
    allow(policy, wrapped(0xF2, 0x40, 0x00))  # GET STATUS
    allow(policy, delete_apdu(pol.PIV_AID))
    allow(policy, delete_apdu(PIV_PACKAGE_AID))
    allow(policy, delete_apdu(pol.PIV_SSD_AID))
    allow(policy, wrapped(0xE6, 0x02, 0x00))  # INSTALL for load
    for _ in range(10):
        allow(policy, wrapped(0xE8, 0x00, 0x00, n=200))  # LOAD blocks
    allow(policy, wrapped(0xE6, 0x0C, 0x00))  # INSTALL for install
    allow(policy, wrapped(0xE6, 0x10, 0x00))  # extradition
    allow(policy, select(pol.PIV_SSD_AID))
    allow(policy, INIT_UPDATE)
    allow(policy, EXT_AUTH)
    allow(policy, wrapped(0xD8, 0x00, 0x81))  # PUT KEY
    allow(policy, select(pol.PIV_AID))
    allow(policy, PIV_GET_DATA)
    assert policy.load_blocks == 10


@pytest.mark.parametrize("op", pol.DESTRUCTIVE_OPS)
@pytest.mark.parametrize(
    "aid", [WALLET_AID, FIDO2_AID, FIDO2_PACKAGE_AID, GENUINE_AID, SSD_PACKAGE_AID]
)
def test_reset_may_only_delete_piv_things(op, aid):
    policy = pol.RelayPolicy(op)
    allow(policy, INIT_UPDATE)
    allow(policy, EXT_AUTH)
    with pytest.raises(RemotePolicyError, match="DELETE of") as info:
        policy.check(delete_apdu(aid))
    assert info.value.header == "84E40000"


@pytest.mark.parametrize("op", pol.DESTRUCTIVE_OPS)
@pytest.mark.parametrize("aid", [WALLET_AID, FIDO2_AID, FIDO2_PACKAGE_AID])
def test_the_delete_allow_list_holds_in_the_extended_encoding_too(op, aid):
    policy = pol.RelayPolicy(op)
    allow(policy, INIT_UPDATE)
    allow(policy, EXT_AUTH)
    with pytest.raises(RemotePolicyError, match=f"DELETE of {aid.hex().upper()}"):
        policy.check(delete_apdu_extended(aid))
    allow(policy, delete_apdu_extended(pol.PIV_AID))


@pytest.mark.parametrize("op", pol.DESTRUCTIVE_OPS)
def test_an_encrypted_delete_passes_on_instruction_and_context_alone(op):
    # Under command encryption the AID is opaque; the header-level rules still
    # hold (ISD context only) and the limitation is documented.
    policy = pol.RelayPolicy(op)
    allow(policy, INIT_UPDATE)
    allow(policy, EXT_AUTH_ENC)
    allow(policy, wrapped(0xE4, 0x00, 0x00))


@pytest.mark.parametrize("op", pol.DESTRUCTIVE_OPS)
def test_an_unreadable_delete_is_refused_unless_the_channel_encrypts(op):
    # With a MAC alone the AID is in the clear, so a DELETE that does not parse
    # is not a legitimate command the relay happens not to understand.
    policy = pol.RelayPolicy(op)
    allow(policy, INIT_UPDATE)
    allow(policy, EXT_AUTH)
    with pytest.raises(RemotePolicyError, match="cannot read") as info:
        policy.check(wrapped(0xE4, 0x00, 0x00))
    assert info.value.header == "84E40000"
    with pytest.raises(RemotePolicyError, match="cannot read"):
        policy.check(delete_apdu(pol.PIV_AID)[:5] + b"\x00" * 21)  # template byte lost


@pytest.mark.parametrize("op", pol.DESTRUCTIVE_OPS)
def test_command_encryption_is_forgotten_when_the_channel_ends(op):
    policy = pol.RelayPolicy(op)
    allow(policy, INIT_UPDATE)
    allow(policy, EXT_AUTH_ENC)
    allow(policy, wrapped(0xE4))
    allow(policy, INIT_UPDATE)  # a new channel negotiation
    with pytest.raises(RemotePolicyError, match="cannot read"):
        policy.check(wrapped(0xE4))
    allow(policy, EXT_AUTH_ENC)
    allow(policy, wrapped(0xE4))
    allow(policy, select(pol.ISD_AID))  # selecting closes the channel
    with pytest.raises(RemotePolicyError, match="cannot read"):
        policy.check(wrapped(0xE4))


def test_a_failed_authentication_does_not_mark_the_channel_encrypted():
    policy = pol.RelayPolicy("reset")
    allow(policy, INIT_UPDATE)
    policy.check(EXT_AUTH_ENC)
    with pytest.raises(RemotePolicyError, match="EXTERNAL AUTHENTICATE failed"):
        policy.observe(EXT_AUTH_ENC, 0x63, 0x00)
    with pytest.raises(RemotePolicyError, match="cannot read"):
        policy.check(wrapped(0xE4))


@pytest.mark.parametrize("op", pol.DESTRUCTIVE_OPS)
def test_content_management_never_leaves_the_card_manager(op):
    policy = pol.RelayPolicy(op)
    allow(policy, select(pol.PIV_SSD_AID))
    for ins in (0xE4, 0xE6, 0xE8):
        with pytest.raises(RemotePolicyError, match="not allowed while the piv-ssd"):
            policy.check(wrapped(ins))
    allow(policy, select(pol.PIV_AID))
    for ins in (0xE4, 0xE6, 0xE8, 0xD8, 0x47, 0x87):
        with pytest.raises(RemotePolicyError, match="not allowed while the piv"):
            policy.check(wrapped(ins))


@pytest.mark.parametrize("op", pol.DESTRUCTIVE_OPS)
def test_a_failed_external_authenticate_ends_the_operation(op):
    policy = pol.RelayPolicy(op)
    allow(policy, INIT_UPDATE)
    policy.check(EXT_AUTH)
    with pytest.raises(RemotePolicyError, match="EXTERNAL AUTHENTICATE failed"):
        policy.observe(EXT_AUTH, 0x63, 0x00)


@pytest.mark.parametrize("op", pol.DESTRUCTIVE_OPS)
def test_external_authenticate_is_capped_per_domain(op):
    policy = pol.RelayPolicy(op)
    cap = policy.rules.max_external_authenticates
    for _ in range(cap):
        allow(policy, INIT_UPDATE)
        allow(policy, EXT_AUTH)
    with pytest.raises(
        RemotePolicyError, match=f"EXTERNAL AUTHENTICATE to the isd more than {cap}"
    ):
        policy.check(EXT_AUTH)


def test_load_blocks_are_capped():
    policy = pol.RelayPolicy("reset")
    allow(policy, INIT_UPDATE)
    allow(policy, EXT_AUTH)
    policy.load_blocks = policy.rules.max_load_blocks
    with pytest.raises(RemotePolicyError, match="LOAD blocks"):
        policy.check(wrapped(0xE8))


@pytest.mark.parametrize("op", pol.DESTRUCTIVE_OPS)
@pytest.mark.parametrize("aid", [WALLET_AID, FIDO2_AID, GENUINE_AID, DESFIRE_AID])
def test_reset_cannot_select_other_card_functions(op, aid):
    with pytest.raises(RemotePolicyError, match="SELECT of AID"):
        pol.RelayPolicy(op).check(select(aid))


def test_delete_target_parsing():
    assert pol.delete_target(delete_apdu(pol.PIV_AID)) == pol.PIV_AID
    assert pol.delete_target(delete_apdu_extended(pol.PIV_AID)) == pol.PIV_AID
    assert pol.delete_target(wrapped(0xE4)) is None  # opaque
    assert pol.delete_target(bytes.fromhex("84E40000034F01AA")) is None  # implausible length


# --------------------------------------------------------------------------- #
# attest: one slot, the management key, nothing else                          #
# --------------------------------------------------------------------------- #
def test_attest_needs_a_slot():
    with pytest.raises(RemotePolicyError, match="needs the target slot"):
        pol.RelayPolicy("attest")


def test_attest_follows_the_documented_flow():
    policy = pol.RelayPolicy("attest", slot=0x9C)
    allow(policy, CPLC)
    allow(policy, select(pol.PIV_AID))
    allow(policy, INIT_UPDATE)  # the applet's admin channel, keyed by the SSD
    allow(policy, EXT_AUTH)
    allow(policy, wrapped(0xDB, 0x3F, 0xFF))  # key-object setup
    allow(policy, apdu(0x00, 0x87, 0x03, 0x9B, b"\x7c\x02\x81\x00", le=False))
    allow(policy, apdu(0x00, 0x47, 0x00, 0x9C, b"\xac\x03\x80\x01\x11", le=False))
    allow(policy, apdu(0x00, 0xC0, 0x00, 0x00))
    allow(policy, apdu(0x00, 0xDB, 0x3F, 0xFF, b"\x5c\x03\x5f\xc1\x20", le=False))
    allow(policy, PIV_GET_DATA)


def test_attest_generate_is_bound_to_the_requested_slot():
    policy = pol.RelayPolicy("attest", slot=0x9C)
    allow(policy, select(pol.PIV_AID))
    for other in (0x9A, 0x9D, 0x9E, 0x82):
        with pytest.raises(RemotePolicyError, match=f"GENERATE for slot {other:02X}"):
            policy.check(apdu(0x00, 0x47, 0x00, other, b"\xac\x03\x80\x01\x11", le=False))


def test_attest_never_exercises_a_slot_key():
    policy = pol.RelayPolicy("attest", slot=0x9C)
    allow(policy, select(pol.PIV_AID))
    for key in (0x9A, 0x9C, 0x9D, 0x9E):
        with pytest.raises(RemotePolicyError, match="only the management key"):
            policy.check(apdu(0x00, 0x87, 0x11, key, b"\x7c\x02\x82\x00", le=False))


def test_attest_cannot_manage_card_content():
    policy = pol.RelayPolicy("attest", slot=0x9C)
    allow(policy, INIT_UPDATE)
    with pytest.raises(RemotePolicyError, match="EXTERNAL AUTHENTICATE to the isd|not allowed"):
        policy.check(wrapped(0xE4))
    for ins in (0xE4, 0xE6, 0xE8, 0xD8):
        with pytest.raises(RemotePolicyError, match="not allowed while the isd"):
            policy.check(wrapped(ins))


def test_attest_cannot_select_other_card_functions():
    for aid in (WALLET_AID, FIDO2_AID, GENUINE_AID, DESFIRE_AID):
        with pytest.raises(RemotePolicyError, match="SELECT of AID"):
            pol.RelayPolicy("attest", slot=0x9C).check(select(aid))
