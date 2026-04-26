from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.prompt import IntPrompt
from rich.table import Table

from .models import PassphraseAuditResult, WiFiNetwork


def build_console() -> Console:
    return Console()


def render_network_table(console: Console, networks: list[WiFiNetwork]) -> None:
    table = Table(title="WiFiGuard Auditor", header_style="bold cyan")
    table.add_column("#", style="bold white", justify="right")
    table.add_column("SSID", style="bold green")
    table.add_column("BSSID", style="cyan")
    table.add_column("Signal", justify="right")
    table.add_column("Channel", justify="right")
    table.add_column("Encryption", style="magenta")
    table.add_column("Hidden", justify="center")
    table.add_column("WPS", justify="center")
    table.add_column("Findings", justify="right")

    for index, network in enumerate(networks, start=1):
        table.add_row(
            str(index),
            network.display_ssid,
            network.bssid or "Unknown",
            format_signal(network),
            str(network.channel or "-"),
            network.encryption,
            "Yes" if network.hidden else "No",
            format_wps(network.wps_enabled),
            str(len(network.issues)),
        )

    console.print(table)


def render_network_details(console: Console, network: WiFiNetwork) -> None:
    details = Table.grid(padding=(0, 2))
    details.add_row("SSID", network.display_ssid)
    details.add_row("BSSID", network.bssid or "Unknown")
    details.add_row("Signal", format_signal(network))
    details.add_row("Channel", str(network.channel or "Unknown"))
    details.add_row("Encryption", network.encryption)
    details.add_row("Hidden SSID", "Yes" if network.hidden else "No")
    details.add_row("WPS Enabled", format_wps(network.wps_enabled))
    details.add_row("Backend", network.backend)
    console.print(Panel(details, title="Selected Network", border_style="bright_blue"))


def render_findings(console: Console, network: WiFiNetwork) -> None:
    if not network.issues:
        console.print("[bold green]No common misconfigurations detected.[/bold green]")
        return
    console.print("[bold yellow]Findings[/bold yellow]")
    for issue in network.issues:
        console.print(f" - {issue}")


def render_passphrase_audit(console: Console, result: PassphraseAuditResult) -> None:
    details = Table.grid(padding=(0, 2))
    details.add_row("Length", str(result.password_length))
    details.add_row("Strength", result.strength)
    details.add_row("Entropy", f"{result.estimated_entropy_bits} bits")
    details.add_row("Wordlist Checked", "Yes" if result.wordlist_checked else "No")
    if result.wordlist_path:
        details.add_row("Wordlist Path", result.wordlist_path)
    details.add_row("Found In Wordlist", "Yes" if result.found_in_wordlist else "No")
    details.add_row("Scanned Entries", str(result.scanned_entries))
    if result.matched_line is not None:
        details.add_row("Matched Line", str(result.matched_line))

    console.print(Panel(details, title="Passphrase Audit", border_style="bright_magenta"))
    console.print("[bold yellow]Recommendations[/bold yellow]")
    for item in result.recommendations:
        console.print(f" - {item}")


def prompt_for_selection(console: Console, networks: list[WiFiNetwork]) -> WiFiNetwork:
    choices = [str(index) for index in range(1, len(networks) + 1)]
    selection = IntPrompt.ask(
        "[bold cyan]Select a network by number[/bold cyan]",
        choices=choices,
        console=console,
        default=1,
    )
    return networks[selection - 1]


def format_signal(network: WiFiNetwork) -> str:
    if network.signal_dbm is not None and network.signal_percent is not None:
        return f"{network.signal_dbm} dBm / {network.signal_percent}%"
    if network.signal_dbm is not None:
        return f"{network.signal_dbm} dBm"
    if network.signal_percent is not None:
        return f"{network.signal_percent}%"
    return "Unknown"


def format_wps(value: bool | None) -> str:
    if value is True:
        return "Yes"
    if value is False:
        return "No"
    return "Unknown"
