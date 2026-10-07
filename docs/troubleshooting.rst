Troubleshooting
===============

First stop, always:

.. code-block:: console

   $ cryptnox-id doctor

It checks the PC/SC service, readers, transport, and each card function, and
says what to fix.

Quick hits:

* **FIDO commands fail on Windows** — run from an Administrator terminal.
* **DESFire not answering** — use a DESFire-capable *contactless* reader.
* **PIV admin/perso fails over NFC** — administration is contact-only.
* **yubico-piv-tool sees nothing** — pass your reader: ``-r <substring>``.
* **Two readers hold a card** — the CLI refuses to guess; pass ``--reader``.

Reader and transport
----------------------

**"No PC/SC readers found" / cannot reach the PC/SC service.**
Windows: ensure the *Smart Card* service (``SCardSvr``) is running. Linux: start
``pcscd`` and install ``libccid``. macOS: PC/SC is built in.

**Multiple readers, wrong one picked.**
The CLI prefers ACS readers. Pass ``--reader <index>`` or a name substring
(``--reader "ACR1252 1S CL Reader PICC"``). ``cryptnox-id readers`` shows the
indices.

**Reader compatibility (DESFire).**
DESFire native commands are passed through correctly by the **ACS ACR1252**
(PICC interface). The **HID OMNIKEY 5422CL is incompatible** — DESFire frames go
unanswered (and the link can wedge into ``SCARD_E_READER_UNAVAILABLE``); PIV and
GlobalPlatform still work on it. Use a DESFire-capable reader for ``mifare``
commands.

Status words and errors
-------------------------

**``SCARD_E_NO_ACCESS 0x80100027`` on ``fido`` commands.**
Windows blocks non-elevated PC/SC access to the FIDO CTAP AID. Run the command
from an **Administrator terminal**; the CLI prints exactly this guidance and can
relaunch itself elevated.

**``6D00`` to DESFire commands (even contactless).**
A JavaCard applet (e.g. PIV) is currently selected and answering the interface.
DESFire is the card's **default applet**: re-present the card or open a fresh
connection without selecting anything, on a DESFire-capable reader. The CLI's
detector probes DESFire first for this reason.

**``6700`` (wrong length) on large PIV writes.**
A full certificate does not fit one short APDU, and extended length is rejected
on these transports. The CLI sends large objects via **ISO command chaining**
(CLA ``0x10``); ``import-cert`` does this automatically.

**``6700`` on ``SELECT PIV``, only over a contactless reader
(``info`` shows PIV as ``Unknown``).**
The multi-applet card rejects the *first* case-4 ISO SELECT (data **+ Le**)
issued right after a DESFire native-command session, and the composite detector
(``info`` / ``doctor`` / ``report full``) probes DESFire first. The identical
SELECT sent as **case-3** (no Le) is accepted and returns the FCI, so the CLI
retries once without Le. Standalone ``piv …`` commands are never affected. If
you script raw ``apdu`` calls, drop the trailing Le on the SELECT that follows
DESFire native commands.

**``6E27``-style failure on the second admin command in one SCP03 session.**
This JCOP 4.5 card accepts only **one application APDU per applet-directed SCP03
session**. The CLI opens a fresh SCP03 channel per admin/perso command (and uses
ISO command chaining when one logical command must span blocks), so you should
not hit this in normal use — only when scripting raw ``apdu`` calls.

**``6985`` (conditions not satisfied) on ``generate-csr`` / signing.**
The slot's key has the wrong role. Signing needs a **SIGN-role** slot such as
**9C** (or a 9A provisioned with the ``ssh`` / ``ms-logon`` profile); a
default-profile 9A is AUTHENTICATE-only and refuses ``GENERAL AUTHENTICATE``
signing. See :doc:`/factory/pre-personalization-profiles`.

**``0xAE AUTHENTICATION_ERROR`` on ``mifare app delete``.**
Deleting an application requires authentication. Pass ``--zero-key`` (factory
default) or ``--key-env NAME``; the CLI then authenticates and sends a MACed
DeleteApplication.

**``0x9D PERMISSION_DENIED`` on ``mifare write``.**
The file's write access condition needs a key you have not authenticated with,
or you authenticated with the wrong key number. Check ``--key-no`` and the
file's access rights.

FIDO2
-------

**Nothing happens / access denied even as Administrator.**
Confirm the terminal is truly elevated (``fido info`` prints a non-elevated
warning otherwise). Some security software also brokers WebAuthn; close other
FIDO clients.

Genuineness
-------------

**``genuine`` reports "applet not found" on a contactless reader.**
The genuineness applet is **contact-only** — it does not answer over the
contactless interface (SELECT returns ``6A82``). Use a contact reader (e.g. ACS
ACR39U). ``info`` shows ``GenuinenessNeedsContactReader`` when DESFire is
reachable, i.e. you are on a contactless interface.

**``genuine verify``: proof of possession ``valid`` but chain ``not verified``
(``NOT proven``).**
No Cryptnox genuineness root is pinned, so the chain cannot be anchored — the
tool reports ``NOT proven`` rather than silently passing. Pass ``--anchors DIR``
with the trust anchor, or bundle the pinned root. A **dev** card chains to a
throwaway dev root: ``genuine verify --anchors <dev-ca-dir>``.

**Genuineness is not the ISD / PIV-SSD check.**
``genuine verify`` proves the attestation applet's device key and certificate
chain. It does **not** verify the per-card ISD or PIV-SSD keys (KDF/HSM-derived)
— this tool has no access to those secrets, and the output says so.

yubico-piv-tool interop
-------------------------

**``yubico-piv-tool`` sees nothing / "failed to connect".**
It defaults to Yubico's own reader-name matching. Pass your reader explicitly
with ``-r <substring>``. Note that ``yubico-piv-tool`` gates its connect on the
applet answering a Yubico firmware-version query — OpenSC and the Windows
minidriver use standard PIV discovery instead and are unaffected. See the interop
matrix in :doc:`/piv/quick-start-a-working-piv-card`.

Getting a shareable diagnostic
--------------------------------

.. code-block:: console

   $ cryptnox-id report full --out report.json

Writes a secret-safe JSON snapshot of all three functions to attach to a bug
report. It never contains PINs or keys.
