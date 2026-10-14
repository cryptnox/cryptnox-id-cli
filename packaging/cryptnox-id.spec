# PyInstaller spec for a single-file build.
#   pip install -e ".[dev]"
#   pyinstaller packaging/cryptnox-id.spec
# Produces dist/cryptnox-id (dist/cryptnox-id.exe on Windows). PyInstaller does
# not cross-compile: each platform's binary is built on that platform.
#
# Note: FIDO2 commands still require an Administrator terminal on Windows
# (the OS blocks the FIDO AID over PC/SC for non-elevated processes).

from PyInstaller.utils.hooks import collect_data_files

block_cipher = None

# Pinned trust anchors (PEM) from src/cryptnox_id_cli/trust/genuine/; see that
# directory's README.md. tests/unit/test_packaging_spec.py checks the names here.
trust_datas = collect_data_files("cryptnox_id_cli", includes=["trust/genuine/*.pem"])

a = Analysis(
    ["entry.py"],
    pathex=["."],
    binaries=[],
    datas=trust_datas,
    # websockets needs no entry: the analysis finds its imports inside functions.
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
    name="cryptnox-id",
    debug=False,
    strip=False,
    upx=True,
    console=True,
)
