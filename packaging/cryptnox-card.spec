# PyInstaller spec for a single-file Windows build.
#   pip install -e ".[dev]"
#   pyinstaller packaging/cryptnox-card.spec
# Produces dist/cryptnox-card.exe
#
# Note: FIDO2 commands still require an Administrator terminal on Windows
# (the OS blocks the FIDO AID over PC/SC for non-elevated processes).

from PyInstaller.utils.hooks import collect_data_files

block_cipher = None

# Pinned attestation trust anchors (PEM). Empty until a root is placed in
# src/cryptnox_ident_card/trust/genuine/ — see that dir's README.md.
trust_datas = collect_data_files("cryptnox_ident_card", includes=["trust/genuine/*.pem"])

a = Analysis(
    ["entry.py"],
    pathex=["."],
    binaries=[],
    datas=trust_datas,
    hiddenimports=[
        "smartcard",
        "smartcard.System",
        "smartcard.scard",
        "smartcard.CardConnection",
        "cbor2",
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    cipher=block_cipher,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="cryptnox-card",
    debug=False,
    strip=False,
    upx=True,
    console=True,
)
