"""CTAP2-over-APDU client (read-only commands for Phase 7A).

Framing (verified against the applet source and the Android client):
``CLA 0x80, INS 0x10, P1 0x00, P2 0x00``, data = ``[CTAP cmd byte][CBOR params]``.
The response is ``[CTAP status byte][CBOR payload]``; ``61xx``/GET RESPONSE
chaining is handled by the transport layer.
"""

from __future__ import annotations

import uuid
from typing import Any

import cbor2

from cryptnox_id_cli.applets.fido import constants as c
from cryptnox_id_cli.applets.fido import pinproto
from cryptnox_id_cli.applets.fido.authdata import parse_authenticator_data
from cryptnox_id_cli.applets.fido.errors import CtapStatusError
from cryptnox_id_cli.transport.apdu import APDU
from cryptnox_id_cli.transport.errors import AppletNotFoundError, StatusWordError
from cryptnox_id_cli.transport.pcsc import CardSession


class Ctap2Client:
    def __init__(self, session: CardSession) -> None:
        self.s = session

    # -- selection ----------------------------------------------------------- #
    def select(self) -> str:
        """SELECT the FIDO applet; returns the version string from the response."""
        resp = self.s.transmit(
            APDU(0x00, 0xA4, 0x04, 0x00, data=c.FIDO_AID, le=256), context="SELECT FIDO"
        )
        if resp.sw == 0x6A82:
            raise AppletNotFoundError("FIDO2 applet not found on this card.")
        if not resp.ok:
            raise StatusWordError(resp.sw1, resp.sw2, context="SELECT FIDO")
        return resp.data.decode("ascii", "replace") or "(no version string)"

    # -- CTAP message -------------------------------------------------------- #
    def command(self, cmd: int, params: dict | None = None, *, context: str | None = None) -> Any:
        # CTAP2 mandates canonical CBOR (map keys sorted by encoded form). Without it,
        # a strict authenticator misparses out-of-order maps -> CTAP2_ERR_MISSING_PARAMETER.
        payload = bytes([cmd]) + (
            cbor2.dumps(params, canonical=True) if params is not None else b""
        )
        resp = self.s.transmit(
            APDU(0x80, c.INS_CTAP_MSG, 0x00, 0x00, data=payload, le=256),
            context=context or f"CTAP 0x{cmd:02X}",
        )
        if not resp.ok:
            raise StatusWordError(resp.sw1, resp.sw2, context=context or "CTAP")
        if not resp.data:
            raise CtapStatusError(0x7F, context=context)
        status = resp.data[0]
        if status != 0x00:
            raise CtapStatusError(status, context=context)
        return cbor2.loads(resp.data[1:]) if len(resp.data) > 1 else None

    def get_info(self) -> dict:
        info = self.command(c.CTAP_GET_INFO, context="authenticatorGetInfo")
        if not isinstance(info, dict):
            raise CtapStatusError(0x12, context="authenticatorGetInfo")
        return info

    def pin_retries(self) -> tuple[int | None, bool | None]:
        """clientPIN getPinRetries → (retries, powerCycleState). Consumes nothing."""
        resp = self.command(
            c.CTAP_CLIENT_PIN,
            {0x01: 1, 0x02: c.PIN_GET_RETRIES},
            context="clientPIN getPinRetries",
        )
        if not isinstance(resp, dict):
            return None, None
        retries = resp.get(0x03)
        power_cycle = resp.get(0x04)
        return (
            int(retries) if isinstance(retries, int) else None,
            bool(power_cycle) if power_cycle is not None else None,
        )

    # -- PIN/UV auth protocol (write ops) ----------------------------------- #
    def get_key_agreement(self, protocol: int = 1) -> dict:
        """clientPIN getKeyAgreement -> the authenticator's COSE public key."""
        resp = self.command(
            c.CTAP_CLIENT_PIN,
            {c.CP_PROTOCOL: protocol, c.CP_SUBCOMMAND: c.PIN_GET_KEY_AGREEMENT},
            context="clientPIN getKeyAgreement",
        )
        key = resp.get(c.CPR_KEY_AGREEMENT) if isinstance(resp, dict) else None
        if not isinstance(key, dict):
            raise CtapStatusError(0x12, context="getKeyAgreement")
        return key

    def set_pin(self, new_pin: str, protocol: int = 1) -> None:
        """Set the initial PIN on an authenticator that has none."""
        platform_key, proto = pinproto.encapsulate(self.get_key_agreement(protocol), protocol)
        new_pin_enc = proto.encrypt(pinproto.pad_pin(new_pin))
        self.command(
            c.CTAP_CLIENT_PIN,
            {
                c.CP_PROTOCOL: protocol,
                c.CP_SUBCOMMAND: c.PIN_SET_PIN,
                c.CP_KEY_AGREEMENT: platform_key,
                c.CP_NEW_PIN_ENC: new_pin_enc,
                c.CP_PIN_UV_AUTH_PARAM: proto.authenticate(new_pin_enc),
            },
            context="clientPIN setPIN",
        )

    def change_pin(self, current_pin: str, new_pin: str, protocol: int = 1) -> None:
        """Change an existing PIN (decrements the retry counter on a wrong current PIN)."""
        platform_key, proto = pinproto.encapsulate(self.get_key_agreement(protocol), protocol)
        pin_hash_enc = proto.encrypt(pinproto.pin_hash_left16(current_pin))
        new_pin_enc = proto.encrypt(pinproto.pad_pin(new_pin))
        self.command(
            c.CTAP_CLIENT_PIN,
            {
                c.CP_PROTOCOL: protocol,
                c.CP_SUBCOMMAND: c.PIN_CHANGE_PIN,
                c.CP_KEY_AGREEMENT: platform_key,
                c.CP_PIN_HASH_ENC: pin_hash_enc,
                c.CP_NEW_PIN_ENC: new_pin_enc,
                c.CP_PIN_UV_AUTH_PARAM: proto.authenticate(new_pin_enc + pin_hash_enc),
            },
            context="clientPIN changePIN",
        )

    def get_pin_token(
        self,
        pin: str,
        *,
        protocol: int = 1,
        permissions: int | None = None,
        rp_id: str | None = None,
    ) -> bytes:
        """Obtain a pinUvAuthToken (decrypted). Uses the permissions-scoped subcommand
        (0x09) when ``permissions`` is given, else the legacy getPinToken (0x05)."""
        platform_key, proto = pinproto.encapsulate(self.get_key_agreement(protocol), protocol)
        pin_hash_enc = proto.encrypt(pinproto.pin_hash_left16(pin))
        params = {
            c.CP_PROTOCOL: protocol,
            c.CP_KEY_AGREEMENT: platform_key,
            c.CP_PIN_HASH_ENC: pin_hash_enc,
        }
        if permissions is not None:
            params[c.CP_SUBCOMMAND] = c.PIN_GET_TOKEN_USING_PIN
            params[c.CP_PERMISSIONS] = permissions
            if rp_id is not None:
                params[c.CP_RP_ID] = rp_id
            ctx = "clientPIN getPinUvAuthTokenUsingPinWithPermissions"
        else:
            params[c.CP_SUBCOMMAND] = c.PIN_GET_PIN_TOKEN
            ctx = "clientPIN getPinToken"
        resp = self.command(c.CTAP_CLIENT_PIN, params, context=ctx)
        enc = resp.get(c.CPR_PIN_UV_AUTH_TOKEN) if isinstance(resp, dict) else None
        if not isinstance(enc, (bytes, bytearray)):
            raise CtapStatusError(0x12, context=ctx)
        return proto.decrypt(bytes(enc))

    # -- credentials -------------------------------------------------------- #
    def make_credential(
        self,
        *,
        client_data_hash: bytes,
        rp_id: str,
        user_id: bytes,
        user_name: str = "cryptnox",
        resident_key: bool = False,
        pin_uv_token: bytes | None = None,
        protocol: int = 1,
        algorithms: tuple[int, ...] = (c.COSE_ALG_ES256,),
    ) -> dict[str, object]:
        """authenticatorMakeCredential (register). Returns the parsed credential id +
        public key. Requires user presence (a tap) on the authenticator."""
        params: dict[int, object] = {
            c.MC_CLIENT_DATA_HASH: client_data_hash,
            c.MC_RP: {"id": rp_id, "name": rp_id},
            c.MC_USER: {"id": user_id, "name": user_name, "displayName": user_name},
            c.MC_PUB_KEY_CRED_PARAMS: [{"alg": a, "type": "public-key"} for a in algorithms],
        }
        if resident_key:
            params[c.MC_OPTIONS] = {"rk": True}
        if pin_uv_token is not None:
            params[c.MC_PIN_UV_AUTH_PARAM] = pinproto.pin_uv_authenticate(
                protocol, pin_uv_token, client_data_hash
            )
            params[c.MC_PIN_UV_AUTH_PROTOCOL] = protocol
        resp = self.command(c.CTAP_MAKE_CREDENTIAL, params, context="authenticatorMakeCredential")
        auth_data = resp.get(c.MCR_AUTH_DATA) if isinstance(resp, dict) else None
        if not isinstance(auth_data, (bytes, bytearray)):
            raise CtapStatusError(0x12, context="makeCredential")
        parsed = parse_authenticator_data(bytes(auth_data))
        return {
            "fmt": resp.get(c.MCR_FMT),
            "auth_data": bytes(auth_data),
            "att_stmt": resp.get(c.MCR_ATT_STMT),
            "credential_id": parsed.credential_id,
            "credential_public_key": parsed.credential_public_key,
            "sign_count": parsed.sign_count,
        }

    def get_assertion(
        self,
        *,
        rp_id: str,
        client_data_hash: bytes,
        allow_credential_ids: list[bytes] | None = None,
        pin_uv_token: bytes | None = None,
        protocol: int = 1,
        user_presence: bool = True,
    ) -> dict[str, object]:
        """authenticatorGetAssertion (authenticate). Returns authData + signature."""
        params: dict[int, object] = {
            c.GA_RP_ID: rp_id,
            c.GA_CLIENT_DATA_HASH: client_data_hash,
            c.GA_OPTIONS: {"up": user_presence},
        }
        if allow_credential_ids:
            params[c.GA_ALLOW_LIST] = [
                {"id": cid, "type": "public-key"} for cid in allow_credential_ids
            ]
        if pin_uv_token is not None:
            params[c.GA_PIN_UV_AUTH_PARAM] = pinproto.pin_uv_authenticate(
                protocol, pin_uv_token, client_data_hash
            )
            params[c.GA_PIN_UV_AUTH_PROTOCOL] = protocol
        resp = self.command(c.CTAP_GET_ASSERTION, params, context="authenticatorGetAssertion")
        auth_data = resp.get(c.GAR_AUTH_DATA) if isinstance(resp, dict) else None
        signature = resp.get(c.GAR_SIGNATURE) if isinstance(resp, dict) else None
        credential = resp.get(c.GAR_CREDENTIAL) if isinstance(resp, dict) else None
        if not isinstance(auth_data, (bytes, bytearray)) or not isinstance(
            signature, (bytes, bytearray)
        ):
            raise CtapStatusError(0x12, context="getAssertion")
        return {
            "auth_data": bytes(auth_data),
            "signature": bytes(signature),
            "credential_id": credential.get("id") if isinstance(credential, dict) else None,
            "number_of_credentials": resp.get(c.GAR_NUMBER_OF_CREDENTIALS),
        }

    def reset(self) -> None:
        """authenticatorReset - IRREVERSIBLY wipes all credentials and the PIN. Many
        authenticators only honor it shortly after power-up and require user presence."""
        self.command(c.CTAP_RESET, context="authenticatorReset")

    # -- credential management (0x0A) --------------------------------------- #
    def credential_management(
        self,
        subcommand: int,
        *,
        sub_params: dict | None = None,
        pin_uv_token: bytes | None = None,
        protocol: int = 1,
    ) -> Any:
        """authenticatorCredentialManagement. pinUvAuthParam is over
        ``subCommand || subCommandParams`` (omitted for the GetNext sub-commands)."""
        params: dict[int, object] = {c.CM_SUBCOMMAND: subcommand}
        if sub_params is not None:
            params[c.CM_SUBCOMMAND_PARAMS] = sub_params
        if pin_uv_token is not None:
            msg = bytes([subcommand]) + (
                cbor2.dumps(sub_params, canonical=True) if sub_params is not None else b""
            )
            params[c.CM_PIN_UV_AUTH_PROTOCOL] = protocol
            params[c.CM_PIN_UV_AUTH_PARAM] = pinproto.pin_uv_authenticate(
                protocol, pin_uv_token, msg
            )
        return self.command(
            c.CTAP_CREDENTIAL_MANAGEMENT, params, context="authenticatorCredentialManagement"
        )

    def get_creds_metadata(self, pin_uv_token: bytes, protocol: int = 1) -> tuple[int, int]:
        """(existing resident credentials, max remaining)."""
        resp = self.credential_management(
            c.CM_GET_CREDS_METADATA, pin_uv_token=pin_uv_token, protocol=protocol
        )
        if not isinstance(resp, dict):
            return 0, 0
        return int(resp.get(c.CMR_EXISTING_RESIDENT_COUNT, 0)), int(
            resp.get(c.CMR_MAX_REMAINING, 0)
        )

    def enumerate_credentials(self, pin_uv_token: bytes, protocol: int = 1) -> list[dict]:
        """Walk every resident credential -> list of {rp_id, user, credential_id, public_key}."""
        out: list[dict] = []
        try:
            first_rp = self.credential_management(
                c.CM_ENUMERATE_RPS_BEGIN, pin_uv_token=pin_uv_token, protocol=protocol
            )
        except CtapStatusError as exc:
            if exc.status == 0x2E:  # CTAP2_ERR_NO_CREDENTIALS - none stored
                return out
            raise
        if not isinstance(first_rp, dict):
            return out
        total_rps = int(first_rp.get(c.CMR_TOTAL_RPS, 0))
        rps = [first_rp] if total_rps else []
        for _ in range(max(0, total_rps - 1)):
            rps.append(self.credential_management(c.CM_ENUMERATE_RPS_NEXT))
        for rp in rps:
            rp_info = rp.get(c.CMR_RP) if isinstance(rp, dict) else None
            rp_id = rp_info.get("id") if isinstance(rp_info, dict) else None
            rp_id_hash = rp.get(c.CMR_RP_ID_HASH) if isinstance(rp, dict) else None
            first = self.credential_management(
                c.CM_ENUMERATE_CREDS_BEGIN,
                sub_params={c.CMP_RP_ID_HASH: rp_id_hash},
                pin_uv_token=pin_uv_token,
                protocol=protocol,
            )
            if not isinstance(first, dict):
                continue
            total = int(first.get(c.CMR_TOTAL_CREDENTIALS, 0))
            creds = [first]
            for _ in range(max(0, total - 1)):
                creds.append(self.credential_management(c.CM_ENUMERATE_CREDS_NEXT))
            for cred in creds:
                if not isinstance(cred, dict):
                    continue
                cid = cred.get(c.CMR_CREDENTIAL_ID)
                out.append(
                    {
                        "rp_id": rp_id,
                        "user": cred.get(c.CMR_USER),
                        "credential_id": cid.get("id") if isinstance(cid, dict) else None,
                        "public_key": cred.get(c.CMR_PUBLIC_KEY),
                    }
                )
        return out

    def delete_credential(
        self, credential_id: bytes, pin_uv_token: bytes, protocol: int = 1
    ) -> None:
        self.credential_management(
            c.CM_DELETE_CREDENTIAL,
            sub_params={c.CMP_CREDENTIAL_ID: {"id": credential_id, "type": "public-key"}},
            pin_uv_token=pin_uv_token,
            protocol=protocol,
        )

    # -- authenticator configuration (0x0D) --------------------------------- #
    def authenticator_config(
        self,
        subcommand: int,
        *,
        sub_params: dict | None = None,
        pin_uv_token: bytes | None = None,
        protocol: int = 1,
    ) -> Any:
        """authenticatorConfig. When a pinUvAuthToken is supplied the pinUvAuthParam is
        a MAC over ``32×0xFF || 0x0D || subCommand || subCommandParams`` (the 0xFF prefix
        is mandated by the CTAP 2.1 spec, not a card quirk). The token needs the
        authenticatorConfiguration (acfg) permission. On an unprotected authenticator
        (no clientPIN, alwaysUv false) the card may accept the call with no token."""
        params: dict[int, object] = {c.AC_SUBCOMMAND: subcommand}
        if sub_params is not None:
            params[c.AC_SUBCOMMAND_PARAMS] = sub_params
        if pin_uv_token is not None:
            msg = (
                b"\xff" * 32
                + bytes([c.CTAP_AUTHENTICATOR_CONFIG, subcommand])
                + (cbor2.dumps(sub_params, canonical=True) if sub_params is not None else b"")
            )
            params[c.AC_PIN_UV_AUTH_PROTOCOL] = protocol
            params[c.AC_PIN_UV_AUTH_PARAM] = pinproto.pin_uv_authenticate(
                protocol, pin_uv_token, msg
            )
        return self.command(c.CTAP_AUTHENTICATOR_CONFIG, params, context="authenticatorConfig")

    def toggle_always_uv(self, *, pin_uv_token: bytes | None = None, protocol: int = 1) -> None:
        """Flip the alwaysUv flag (require user verification for every operation)."""
        self.authenticator_config(
            c.AC_TOGGLE_ALWAYS_UV, pin_uv_token=pin_uv_token, protocol=protocol
        )

    def set_min_pin_length(
        self,
        length: int,
        *,
        rp_ids: list[str] | None = None,
        force_change_pin: bool | None = None,
        pin_uv_token: bytes | None = None,
        protocol: int = 1,
    ) -> None:
        """Raise the minimum PIN length. The value can only INCREASE; lowering it again
        requires authenticatorReset."""
        sub: dict[int, object] = {c.ACP_NEW_MIN_PIN_LENGTH: length}
        if rp_ids:
            sub[c.ACP_MIN_PIN_LENGTH_RP_IDS] = rp_ids
        if force_change_pin is not None:
            sub[c.ACP_FORCE_CHANGE_PIN] = force_change_pin
        self.authenticator_config(
            c.AC_SET_MIN_PIN_LENGTH,
            sub_params=sub,
            pin_uv_token=pin_uv_token,
            protocol=protocol,
        )


def describe_get_info(info: dict) -> dict[str, object]:
    """Turn the int-keyed getInfo map into a readable, JSON-able structure."""
    aaguid = info.get(c.INFO_AAGUID)
    aaguid_str = None
    cryptnox = None
    if isinstance(aaguid, bytes) and len(aaguid) == 16:
        aaguid_str = str(uuid.UUID(bytes=aaguid))
        cryptnox = aaguid.hex() in c.CRYPTNOX_AAGUIDS
    algorithms = info.get(c.INFO_ALGORITHMS)
    alg_list = None
    if isinstance(algorithms, list):
        alg_list = [
            {"alg": a.get("alg"), "type": a.get("type")} for a in algorithms if isinstance(a, dict)
        ]
    return {
        "versions": info.get(c.INFO_VERSIONS),
        "extensions": info.get(c.INFO_EXTENSIONS),
        "aaguid": aaguid_str,
        "cryptnox_aaguid": cryptnox,
        "options": info.get(c.INFO_OPTIONS),
        "max_msg_size": info.get(c.INFO_MAX_MSG_SIZE),
        "pin_uv_auth_protocols": info.get(c.INFO_PIN_UV_AUTH_PROTOCOLS),
        "max_creds_in_list": info.get(c.INFO_MAX_CREDS_IN_LIST),
        "max_cred_id_length": info.get(c.INFO_MAX_CRED_ID_LENGTH),
        "transports": info.get(c.INFO_TRANSPORTS),
        "algorithms": alg_list,
        "min_pin_length": info.get(c.INFO_MIN_PIN_LENGTH),
        "firmware_version": info.get(c.INFO_FIRMWARE_VERSION),
    }
