from wifiguard_auditor.utils import dbm_to_percent, frequency_to_channel


def test_frequency_to_channel_for_24ghz_and_5ghz() -> None:
    assert frequency_to_channel(2412) == 1
    assert frequency_to_channel(2437) == 6
    assert frequency_to_channel(5180) == 36


def test_dbm_to_percent_clamps_output() -> None:
    assert dbm_to_percent(-100) == 0
    assert dbm_to_percent(-50) == 100
    assert dbm_to_percent(-67) == 66
