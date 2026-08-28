"""PIV applet support (OpenFIPS201 2.0.0 FIPS).

Phase 3 scope is strictly read-only: SELECT, GET DATA, VERIFY status query, and
discovery. Pre-personalization (factory) and personalization land in later phases.
"""

from cryptnox_id_cli.applets.piv.piv import PivApplet

__all__ = ["PivApplet"]
