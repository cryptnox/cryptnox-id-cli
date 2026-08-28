"""`scp_label` is the single place that turns an SCP version byte into a display
name. Its callers hand it loosely-typed values -- `PivAdmin.scp_version` (None until a
channel is open) and entries out of an `initialize_update_probe` payload -- so the
"not a known version byte" paths matter as much as the two happy ones."""

import pytest

from cryptnox_id_cli.applets.piv.admin import SCP02, SCP03, scp_label


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        (SCP02, "SCP02"),
        (SCP03, "SCP03"),
        (0x02, "SCP02"),
        (0x03, "SCP03"),
        (None, "unknown"),  # no channel open yet, or the probe key was absent
        (0x00, "unknown"),  # 0 is not a version byte; must not read as falsy-special
        (0x01, "unknown"),
        (0x11, "unknown"),  # SCP11 exists in GP but this applet does not speak it
        ("03", "unknown"),  # a hex string is not a version byte
        (b"\x03", "unknown"),
    ],
)
def test_scp_label_maps_known_versions_and_falls_back_otherwise(version, expected):
    assert scp_label(version) == expected
