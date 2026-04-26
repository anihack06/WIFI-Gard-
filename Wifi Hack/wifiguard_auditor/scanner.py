from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass

from .models import WiFiNetwork
from .utils import (
    CommandExecutionError,
    command_exists,
    dbm_to_percent,
    discover_wireless_interface,
    extract_int,
    frequency_to_channel,
    run_command,
)


class ScannerError(RuntimeError):
    """Raised when no supported Wi-Fi scanner is available or scan data is invalid."""


@dataclass(slots=True)
class ScannerContext:
    backend_name: str = "auto"
    interface: str | None = None


class BaseScannerBackend:
    name = "base"

    def __init__(self, context: ScannerContext) -> None:
        self.context = context

    @classmethod
    def is_supported(cls) -> bool:
        raise NotImplementedError

    def scan(self) -> list[WiFiNetwork]:
        raise NotImplementedError

    def deduplicate(self, networks: list[WiFiNetwork]) -> list[WiFiNetwork]:
        strongest_by_key: dict[str, WiFiNetwork] = {}
        for network in networks:
            key = network.bssid.lower() or f"{network.display_ssid}:{network.channel}"
            existing = strongest_by_key.get(key)
            if existing is None or _network_strength(network) > _network_strength(existing):
                strongest_by_key[key] = network

        return sorted(
            strongest_by_key.values(),
            key=lambda network: _network_strength(network),
            reverse=True,
        )


class TermuxScannerBackend(BaseScannerBackend):
    name = "termux"

    @classmethod
    def is_supported(cls) -> bool:
        return command_exists("termux-wifi-scaninfo") or "TERMUX_VERSION" in os.environ

    def scan(self) -> list[WiFiNetwork]:
        output = run_command(["termux-wifi-scaninfo"])
        records = json.loads(output)
        networks: list[WiFiNetwork] = []

        for record in records:
            signal_dbm = _safe_int(record.get("level"))
            raw_security = str(record.get("capabilities") or "")
            networks.append(
                WiFiNetwork(
                    ssid=str(record.get("ssid") or ""),
                    bssid=str(record.get("bssid") or ""),
                    signal_percent=dbm_to_percent(signal_dbm),
                    signal_dbm=signal_dbm,
                    channel=frequency_to_channel(_safe_int(record.get("frequency"))),
                    encryption=_classify_encryption(raw_security),
                    hidden=not str(record.get("ssid") or "").strip(),
                    wps_enabled="WPS" in raw_security.upper(),
                    raw_security=raw_security,
                    backend=self.name,
                )
            )

        return self.deduplicate(networks)


class NmcliScannerBackend(BaseScannerBackend):
    name = "nmcli"

    @classmethod
    def is_supported(cls) -> bool:
        return command_exists("nmcli")

    def scan(self) -> list[WiFiNetwork]:
        output = run_command(
            [
                "nmcli",
                "--colors",
                "no",
                "--mode",
                "multiline",
                "--terse",
                "--fields",
                "SSID,BSSID,CHAN,SIGNAL,SECURITY,IN-USE",
                "device",
                "wifi",
                "list",
                "--rescan",
                "yes",
            ]
        )

        records: list[dict[str, str]] = []
        current: dict[str, str] = {}
        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                if current:
                    records.append(current)
                    current = {}
                continue
            if ":" not in stripped:
                continue
            key, value = stripped.split(":", 1)
            current[key.strip().upper()] = value.strip()
        if current:
            records.append(current)

        networks = [
            WiFiNetwork(
                ssid=record.get("SSID", ""),
                bssid=record.get("BSSID", ""),
                signal_percent=_safe_int(record.get("SIGNAL")),
                signal_dbm=None,
                channel=_safe_int(record.get("CHAN")),
                encryption=_classify_encryption(record.get("SECURITY", "")),
                hidden=not record.get("SSID", "").strip(),
                wps_enabled=None,
                raw_security=record.get("SECURITY", ""),
                backend=self.name,
            )
            for record in records
        ]
        return self.deduplicate(networks)


class IwlistScannerBackend(BaseScannerBackend):
    name = "iwlist"

    @classmethod
    def is_supported(cls) -> bool:
        return command_exists("iwlist")

    def scan(self) -> list[WiFiNetwork]:
        interface = discover_wireless_interface(self.context.interface)
        if not interface:
            raise ScannerError("Unable to determine a wireless interface for the iwlist backend.")

        output = run_command(["iwlist", interface, "scanning"], timeout=30)
        pattern = re.compile(
            r"Cell \d+ - Address: (?P<bssid>[0-9A-Fa-f:]{17})(?P<body>.*?)(?=Cell \d+ - Address: |\Z)",
            flags=re.DOTALL,
        )

        networks: list[WiFiNetwork] = []
        for match in pattern.finditer(output):
            body = match.group("body")
            signal_dbm = extract_int(r"Signal level=(-?\d+)\s*dBm", body)
            quality_current = extract_int(r"Quality=(\d+)", body)
            quality_total = extract_int(r"Quality=\d+/(\d+)", body)
            signal_percent = None
            if quality_current is not None and quality_total:
                signal_percent = round((quality_current / quality_total) * 100)
            elif signal_dbm is not None:
                signal_percent = dbm_to_percent(signal_dbm)

            security_lines = [
                line.strip()
                for line in body.splitlines()
                if "IE:" in line or "Encryption key:" in line
            ]
            raw_security = " | ".join(security_lines)
            ssid_match = re.search(r'ESSID:"(.*?)"', body)
            channel = extract_int(r"Channel:(\d+)", body)
            if channel is None:
                channel = extract_int(r"\(Channel\s+(\d+)\)", body)

            networks.append(
                WiFiNetwork(
                    ssid=ssid_match.group(1) if ssid_match else "",
                    bssid=match.group("bssid"),
                    signal_percent=signal_percent,
                    signal_dbm=signal_dbm,
                    channel=channel,
                    encryption=_classify_encryption(raw_security),
                    hidden=not (ssid_match.group(1) if ssid_match else "").strip(),
                    wps_enabled=_detect_wps(body),
                    raw_security=raw_security,
                    backend=self.name,
                )
            )

        return self.deduplicate(networks)


class WiFiScanner:
    def __init__(self, backend_name: str = "auto", interface: str | None = None) -> None:
        self.context = ScannerContext(backend_name=backend_name, interface=interface)

    def scan(self) -> tuple[str, list[WiFiNetwork]]:
        backend = self._resolve_backend()
        try:
            networks = backend.scan()
        except CommandExecutionError as exc:
            raise ScannerError(str(exc)) from exc

        if not networks:
            raise ScannerError("No Wi-Fi networks were discovered by the selected backend.")
        return backend.name, networks

    def _resolve_backend(self) -> BaseScannerBackend:
        backends = {
            "termux": TermuxScannerBackend,
            "nmcli": NmcliScannerBackend,
            "iwlist": IwlistScannerBackend,
        }
        preferred = self.context.backend_name

        if preferred != "auto":
            backend_cls = backends.get(preferred)
            if backend_cls is None:
                raise ScannerError(f"Unsupported backend requested: {preferred}")
            if not backend_cls.is_supported():
                raise ScannerError(f"Requested backend is not available: {preferred}")
            return backend_cls(self.context)

        for backend_cls in (TermuxScannerBackend, NmcliScannerBackend, IwlistScannerBackend):
            if backend_cls.is_supported():
                return backend_cls(self.context)

        raise ScannerError(
            "No supported Wi-Fi scanning backend was found. Install termux-api, nmcli, or wireless-tools."
        )


def _classify_encryption(raw_security: str) -> str:
    normalized = raw_security.upper().strip()
    if not normalized or normalized in {"--", "[ESS]"}:
        return "Open"
    if "WEP" in normalized:
        return "WEP"
    if "WPA3" in normalized or "SAE" in normalized:
        return "WPA3"
    if "WPA2" in normalized and ("WPA1" in normalized or "WPA " in normalized or "WPA|" in normalized):
        return "WPA/WPA2"
    if "WPA2" in normalized or "RSN" in normalized:
        return "WPA2"
    if "WPA" in normalized:
        return "WPA"
    return "Unknown"


def _detect_wps(raw_block: str) -> bool | None:
    upper = raw_block.upper()
    if "WPS" in upper or "WI-FI PROTECTED SETUP" in upper:
        return True
    return None


def _network_strength(network: WiFiNetwork) -> int:
    if network.signal_percent is not None:
        return network.signal_percent
    if network.signal_dbm is not None:
        return dbm_to_percent(network.signal_dbm) or 0
    return 0


def _safe_int(value: object) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(str(value))
    except ValueError:
        return None

