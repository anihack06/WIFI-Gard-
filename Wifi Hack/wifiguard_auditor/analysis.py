from __future__ import annotations

import re

from .models import WiFiNetwork

DEFAULT_SSID_PATTERNS = [
    re.compile(r"^(linksys|netgear|d-?link|tp-?link|asus|belkin|tenda|mercusys)$"),
    re.compile(r"^(default|admin|wireless|wifi|router)$"),
    re.compile(r"^(jiofiber|airtel|zte|huawei|miwifi|gl[-_ ]?inet)[-_ ]?\w*$"),
    re.compile(r"^(home|wifi|router)[-_ ]?\d{2,}$"),
    re.compile(r"^(tp-link|tplink|netgear|dlink|jiofiber|airtel)[-_ ]?[0-9a-f]{2,}$"),
]


def analyze_network(network: WiFiNetwork) -> list[str]:
    findings: list[str] = []
    encryption = network.encryption.upper()

    if encryption == "OPEN":
        findings.append("Open network detected. Traffic can be observed by nearby users.")
    elif encryption == "WEP":
        findings.append("WEP detected. This legacy encryption should be replaced immediately.")
    elif encryption in {"WPA", "WPA/WPA2"}:
        findings.append("Legacy WPA compatibility detected. Prefer WPA2-AES or WPA3 only.")

    if is_probable_default_ssid(network.ssid):
        findings.append("SSID appears to use a default or vendor-style router name.")

    if network.wps_enabled is True:
        findings.append("WPS appears enabled. Disable it unless there is a specific operational need.")

    if has_weak_signal(network):
        findings.append("Weak signal area detected. Coverage gaps can encourage unsafe fallback behavior.")

    return findings


def is_probable_default_ssid(ssid: str) -> bool:
    normalized = ssid.strip().lower()
    if not normalized:
        return False
    return any(pattern.search(normalized) for pattern in DEFAULT_SSID_PATTERNS)


def has_weak_signal(network: WiFiNetwork) -> bool:
    if network.signal_percent is not None and network.signal_percent < 35:
        return True
    if network.signal_dbm is not None and network.signal_dbm <= -75:
        return True
    return False

