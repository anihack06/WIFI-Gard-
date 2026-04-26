from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class WiFiNetwork:
    ssid: str
    bssid: str
    signal_percent: int | None = None
    signal_dbm: int | None = None
    channel: int | None = None
    encryption: str = "Unknown"
    hidden: bool = False
    wps_enabled: bool | None = None
    raw_security: str = ""
    backend: str = ""
    issues: list[str] = field(default_factory=list)

    @property
    def display_ssid(self) -> str:
        return self.ssid if self.ssid.strip() else "<hidden>"

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["display_ssid"] = self.display_ssid
        return payload


@dataclass(slots=True)
class PassphraseAuditResult:
    password_length: int
    wordlist_path: str | None
    wordlist_checked: bool
    found_in_wordlist: bool
    matched_line: int | None
    scanned_entries: int
    estimated_entropy_bits: float
    strength: str
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ReportDocument:
    tool_name: str
    generated_at: str
    platform: str
    backend: str
    scanned_networks: list[WiFiNetwork]
    selected_network: WiFiNetwork | None = None
    passphrase_audit: PassphraseAuditResult | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "generated_at": self.generated_at,
            "platform": self.platform,
            "backend": self.backend,
            "scanned_networks": [network.to_dict() for network in self.scanned_networks],
            "selected_network": (
                self.selected_network.to_dict() if self.selected_network else None
            ),
            "passphrase_audit": (
                self.passphrase_audit.to_dict() if self.passphrase_audit else None
            ),
        }

