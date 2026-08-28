"""Extended-length SCP03 command wrapping (the pre-perso BULK is ~316 bytes)."""

from cryptnox_id_cli.transport.apdu import APDU
from cryptnox_id_cli.transport.scp03 import SL_CMAC_CENC, Scp03Session, _aes_cmac


def test_wrap_extended_length():
    sess = Scp03Session(bytes(16), bytes(16), bytes(16), SL_CMAC_CENC)
    wrapped = sess.wrap(APDU(0x00, 0xDB, 0x3F, 0x00, data=bytes(300)))
    assert wrapped[0] == 0x04  # SM bit on CLA 0x00
    assert wrapped[4] == 0x00  # extended-length marker
    lc = (wrapped[5] << 8) | wrapped[6]
    enc_len = lc - 8
    assert enc_len % 16 == 0 and enc_len >= 300
    assert len(wrapped) == 7 + enc_len + 8  # header(7) + enc + C-MAC(8), no Le
    full = _aes_cmac(bytes(16), b"\x00" * 16 + wrapped[: 7 + enc_len])
    assert wrapped[-8:] == full[:8]


def test_wrap_chaining_across_commands():
    """Sequential wrapped commands chain the C-MAC and advance the encryption counter."""
    sess = Scp03Session(bytes(16), bytes(16), bytes(16), SL_CMAC_CENC)
    w1 = sess.wrap(APDU(0x00, 0xDB, 0x3F, 0x00, data=bytes(4)))
    mcv_after_1 = sess.mac_chaining
    assert mcv_after_1 != b"\x00" * 16 and sess.encrypt_counter == 2
    w2 = sess.wrap(APDU(0x00, 0xDB, 0x3F, 0x00, data=bytes(4)))
    assert sess.encrypt_counter == 3
    # w2's C-MAC must chain off the MAC value left by w1.
    full = _aes_cmac(bytes(16), mcv_after_1 + w2[:-8])
    assert w2[-8:] == full[:8]
    assert w1 != w2  # different encryption counter -> different ciphertext/MAC
