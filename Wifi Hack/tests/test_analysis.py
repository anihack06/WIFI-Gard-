from wifiguard_auditor.analysis import analyze_network
from wifiguard_auditor.models import WiFiNetwork


def test_analyze_network_flags_open_default_and_signal() -> None:
    network = WiFiNetwork(
        ssid="TP-Link_1234",
        bssid="00:11:22:33:44:55",
        signal_percent=20,
        encryption="Open",
        wps_enabled=True,
    )

    findings = analyze_network(network)

    assert any("Open network" in item for item in findings)
    assert any("default or vendor-style" in item for item in findings)
    assert any("WPS appears enabled" in item for item in findings)
    assert any("Weak signal area" in item for item in findings)

