# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""MIFARE DESFire EV2 support (contactless).

The DESFire function is the card's default (MIFARE) applet, reached over a
contactless reader with no JavaCard applet selected. Native commands are sent
ISO-7816-wrapped (CLA 0x90); multi-frame responses chain via 0x91AF.
"""

from cryptnox_id_cli.applets.mifare.desfire import DesfireError, DesfireTransport

__all__ = ["DesfireError", "DesfireTransport"]
