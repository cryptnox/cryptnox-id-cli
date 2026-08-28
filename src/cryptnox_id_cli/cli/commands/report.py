"""``report`` — machine-readable, secret-safe status reports.

Reports contain only non-secret, shareable data: states, versions, object
presence, public identifiers. No PINs, keys, private material or sensitive
APDU payloads — by construction (they reuse the read-only inspectors).
"""

from __future__ import annotations

import contextlib
import datetime
import json
from pathlib import Path

import click
from rich.console import Console

from cryptnox_id_cli import CLI_NAME, __version__
from cryptnox_id_cli.applets.fido.ctap import Ctap2Client, describe_get_info
from cryptnox_id_cli.applets.mifare.desfire import DesfireNotSelectedError, DesfireTransport
from cryptnox_id_cli.cli.commands.info import _read_cplc
from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.state import StateDetector
from cryptnox_id_cli.transport.elevation import FIDO_WINDOWS_MESSAGE
from cryptnox_id_cli.transport.errors import (
    AppletNotFoundError,
    CardAccessDeniedError,
    CryptnoxError,
)


@click.group("report")
def command() -> None:
    """Export readable, secret-safe JSON reports."""


def _envelope(kind: str) -> dict[str, object]:
    return {
        "report": kind,
        "generated_by": f"{CLI_NAME} {__version__}",
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "safe_to_share": True,
    }


def _card_section(app: AppContext) -> dict[str, object]:
    with app.open_session() as session:
        state = StateDetector(session).detect()
        cplc = _read_cplc(session)
    return {"reader": app.resolved_reader, "state": state.to_dict(), "cplc": cplc}


def _piv_section(app: AppContext) -> dict[str, object]:
    with app.open_session() as session:
        st = StateDetector(
            session, probe_fido=False, probe_desfire=False, probe_genuine=False
        ).detect()
    return {
        "state": st.piv.label,
        "apt": st.piv_apt.to_dict() if st.piv_apt else None,
        "pin": st.piv_pin.to_dict() if st.piv_pin else None,
        "puk": st.piv_puk.to_dict() if st.piv_puk else None,
        "objects_present": st.piv_objects,
        "notes": st.notes,
    }


def _mifare_section(app: AppContext) -> dict[str, object]:
    try:
        with app.open_session() as session:
            dtx = DesfireTransport(session)
            version = dtx.get_version().to_dict()
            free = None
            with contextlib.suppress(CryptnoxError):
                free = dtx.get_free_memory()
            aids = [a.hex().upper() for a in dtx.application_ids()]
        return {
            "state": "DesfireReachable",
            "version": version,
            "free_memory": free,
            "applications": aids,
        }
    except DesfireNotSelectedError:
        return {
            "state": "DesfireNeedsContactlessReader",
            "note": "DESFire (the default MIFARE applet) did not answer on this interface.",
        }
    except CryptnoxError as exc:
        return {"state": "Unknown", "error": str(exc)}


def _genuine_section(app: AppContext) -> dict[str, object]:
    from cryptnox_id_cli.applets.genuine.genuine import GenuinenessApplet

    try:
        with app.open_session() as session:
            gen = GenuinenessApplet(session)
            if not gen.try_select():
                return {
                    "state": "GenuinenessNotPresent",
                    "note": "genuineness applet not found (contact-only; absent over contactless).",
                }
            info = gen.get_info()
            leaf_der = gen.get_cert()
        subject = None
        if leaf_der:
            from cryptography import x509

            subject = x509.load_der_x509_certificate(leaf_der).subject.rfc4514_string()
        return {
            "state": "GenuinenessPersonalized" if leaf_der else "GenuinenessPresent",
            "leaf_subject": subject,
            "info": info.hex if info else None,
            "note": "state only; run `genuine verify` to prove the device key + chain.",
        }
    except CryptnoxError as exc:
        return {"state": "Unknown", "error": str(exc)}


def _fido_section(app: AppContext) -> dict[str, object]:
    try:
        with app.open_session() as session:
            ctap = Ctap2Client(session)
            version = ctap.select()
            info = describe_get_info(ctap.get_info())
        return {"state": "FidoPersonalized", "select_version": version, "get_info": info}
    except CardAccessDeniedError:
        return {"state": "FidoBlockedByOS", "note": FIDO_WINDOWS_MESSAGE}
    except AppletNotFoundError:
        return {"state": "FidoNotPresent"}
    except CryptnoxError as exc:
        return {"state": "Unknown", "error": str(exc)}


def _emit(app: AppContext, payload: dict[str, object], out: str | None) -> None:
    text = json.dumps(payload, indent=2, default=str)
    if out:
        Path(out).write_text(text + "\n", encoding="utf-8")

    def human(c: Console) -> None:
        if out:
            c.print(f"[green]Report written to {out}[/green] (secret-safe JSON).")
        else:
            c.print(text)

    app.out.result(payload, human)


def _out_option(fn):
    return click.option(
        "--out", "out_", type=click.Path(dir_okay=False), help="Write the JSON report to FILE."
    )(fn)


@command.command("card")
@_out_option
@click.pass_obj
def card(app: AppContext, out_: str | None) -> None:
    """Full card detection report (all three functions)."""
    payload = _envelope("card")
    payload.update(_card_section(app))
    _emit(app, payload, out_)


@command.command("piv")
@_out_option
@click.pass_obj
def piv(app: AppContext, out_: str | None) -> None:
    """PIV applet report."""
    payload = _envelope("piv")
    payload["piv"] = _piv_section(app)
    _emit(app, payload, out_)


@command.command("mifare")
@_out_option
@click.pass_obj
def mifare(app: AppContext, out_: str | None) -> None:
    """MIFARE DESFire report."""
    payload = _envelope("mifare")
    payload["mifare"] = _mifare_section(app)
    _emit(app, payload, out_)


@command.command("fido")
@_out_option
@click.pass_obj
def fido(app: AppContext, out_: str | None) -> None:
    """FIDO2 authenticator report."""
    payload = _envelope("fido")
    payload["fido"] = _fido_section(app)
    _emit(app, payload, out_)


@command.command("genuine")
@_out_option
@click.pass_obj
def genuine(app: AppContext, out_: str | None) -> None:
    """Genuineness / attestation applet report (state only)."""
    payload = _envelope("genuine")
    payload["genuine"] = _genuine_section(app)
    _emit(app, payload, out_)


@command.command("full")
@_out_option
@click.pass_obj
def full(app: AppContext, out_: str | None) -> None:
    """Everything: card + per-function sections (DESFire probed first)."""
    payload = _envelope("full")
    # DESFire first: it answers only while no JavaCard applet is selected.
    payload["mifare"] = _mifare_section(app)
    payload["card"] = _card_section(app)
    payload["piv"] = _piv_section(app)
    payload["fido"] = _fido_section(app)
    payload["genuine"] = _genuine_section(app)
    _emit(app, payload, out_)
