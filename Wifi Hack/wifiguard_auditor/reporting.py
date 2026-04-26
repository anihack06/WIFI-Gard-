from __future__ import annotations

import json
import platform
from datetime import datetime, timezone
from pathlib import Path

from .models import PassphraseAuditResult, ReportDocument, WiFiNetwork


def build_report(
    backend: str,
    networks: list[WiFiNetwork],
    selected_network: WiFiNetwork | None = None,
    passphrase_audit: PassphraseAuditResult | None = None,
) -> ReportDocument:
    return ReportDocument(
        tool_name="WiFiGuard Auditor",
        generated_at=datetime.now(timezone.utc).isoformat(),
        platform=platform.platform(),
        backend=backend,
        scanned_networks=networks,
        selected_network=selected_network,
        passphrase_audit=passphrase_audit,
    )


def write_report(
    report: ReportDocument,
    output_path: str | Path,
    report_format: str = "auto",
) -> tuple[Path, str]:
    path = Path(output_path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    fmt = _resolve_format(path, report_format)

    if fmt == "json":
        path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
    elif fmt == "txt":
        path.write_text(_render_text_report(report), encoding="utf-8")
    else:
        raise ValueError(f"Unsupported report format: {fmt}")

    return path, fmt


def _resolve_format(path: Path, requested: str) -> str:
    if requested != "auto":
        return requested
    suffix = path.suffix.lower().lstrip(".")
    if suffix in {"json", "txt"}:
        return suffix
    return "txt"


def _render_text_report(report: ReportDocument) -> str:
    lines = [
        "WiFiGuard Auditor Report",
        "=" * 24,
        f"Generated At (UTC): {report.generated_at}",
        f"Platform: {report.platform}",
        f"Backend: {report.backend}",
        f"Networks Discovered: {len(report.scanned_networks)}",
        "",
    ]

    if report.selected_network:
        network = report.selected_network
        lines.extend(
            [
                "Selected Network",
                "-" * 16,
                f"SSID: {network.display_ssid}",
                f"BSSID: {network.bssid or 'Unknown'}",
                f"Signal: {_format_signal(network)}",
                f"Channel: {network.channel or 'Unknown'}",
                f"Encryption: {network.encryption}",
                f"Hidden SSID: {'Yes' if network.hidden else 'No'}",
                f"WPS Enabled: {_format_wps(network.wps_enabled)}",
                "Findings:",
            ]
        )
        if network.issues:
            lines.extend([f"- {issue}" for issue in network.issues])
        else:
            lines.append("- No common misconfigurations detected.")
        lines.append("")

    if report.passphrase_audit:
        audit = report.passphrase_audit
        lines.extend(
            [
                "Passphrase Audit",
                "-" * 16,
                f"Length: {audit.password_length}",
                f"Strength: {audit.strength}",
                f"Estimated Entropy (bits): {audit.estimated_entropy_bits}",
                f"Wordlist Checked: {'Yes' if audit.wordlist_checked else 'No'}",
            ]
        )
        if audit.wordlist_path:
            lines.append(f"Wordlist Path: {audit.wordlist_path}")
        lines.extend(
            [
                f"Found In Wordlist: {'Yes' if audit.found_in_wordlist else 'No'}",
                f"Scanned Entries: {audit.scanned_entries}",
                "Recommendations:",
            ]
        )
        lines.extend([f"- {item}" for item in audit.recommendations])
        lines.append("")

    lines.extend(["Observed Networks", "-" * 17])
    for index, network in enumerate(report.scanned_networks, start=1):
        issues = ", ".join(network.issues) if network.issues else "None"
        lines.extend(
            [
                f"{index}. {network.display_ssid}",
                f"   BSSID: {network.bssid or 'Unknown'}",
                f"   Signal: {_format_signal(network)}",
                f"   Channel: {network.channel or 'Unknown'}",
                f"   Encryption: {network.encryption}",
                f"   Hidden: {'Yes' if network.hidden else 'No'}",
                f"   WPS: {_format_wps(network.wps_enabled)}",
                f"   Findings: {issues}",
            ]
        )
    lines.append("")
    return "\n".join(lines)


def _format_signal(network: WiFiNetwork) -> str:
    if network.signal_dbm is not None and network.signal_percent is not None:
        return f"{network.signal_dbm} dBm ({network.signal_percent}%)"
    if network.signal_dbm is not None:
        return f"{network.signal_dbm} dBm"
    if network.signal_percent is not None:
        return f"{network.signal_percent}%"
    return "Unknown"


def _format_wps(value: bool | None) -> str:
    if value is True:
        return "Yes"
    if value is False:
        return "No"
    return "Unknown"
