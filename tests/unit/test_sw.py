from cryptnox_id_cli.transport.errors import StatusWordError, describe_sw


def test_ok():
    info = describe_sw(0x90, 0x00)
    assert info.ok and info.name == "OK"


def test_pin_retries():
    info = describe_sw(0x63, 0xC5)
    assert info.retries == 5 and not info.ok


def test_blocked_pin_zero_retries():
    assert describe_sw(0x63, 0xC0).retries == 0


def test_more_data_and_wrong_le():
    assert describe_sw(0x61, 0x10).more_data == 0x10
    assert describe_sw(0x6C, 0x20).wrong_le == 0x20


def test_known_messages():
    assert "not found" in describe_sw(0x6A, 0x82).message.lower()
    assert "cla" in describe_sw(0x6E, 0x00).message.lower()
    assert "verify the pin" in describe_sw(0x69, 0x82).message.lower()


def test_status_word_error_carries_context():
    err = StatusWordError(0x69, 0x82, context="reading CHUID")
    assert "reading CHUID" in str(err)
    assert err.to_dict()["sw"] == "6982"
