# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""PyInstaller entry point (mirrors the console-script entry)."""

from cryptnox_id_cli.cli.main import main

if __name__ == "__main__":
    main()
