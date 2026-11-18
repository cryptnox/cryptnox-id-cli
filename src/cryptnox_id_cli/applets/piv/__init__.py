# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""PIV applet support (OpenFIPS201 2.0.0, FIPS-mode build).

Phase 3 scope is strictly read-only: SELECT, GET DATA, VERIFY status query, and
discovery. Pre-personalization (factory) and personalization land in later phases.
"""

from cryptnox_id_cli.applets.piv.piv import PivApplet

__all__ = ["PivApplet"]
