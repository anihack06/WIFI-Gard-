from __future__ import annotations

import argparse
import sys
from getpass import getpass
from pathlib import Path

from rich.progress import BarColumn, Progress, TaskProgressColumn, TextColumn, TimeElapsedColumn

from . import __version__
from .analysis import analyze_network
from .audit import audit_known_passphrase
from .reporting import build_report, write_report
from .scanner import ScannerError, WiFiScanner
from .ui import (
    build_console,
    prompt_for_selection,
    render_findings,
    render_network_details,
    render_network_table,
    render_passphrase_audit,
)

DEFAULT_WORDLIST_NAME = "password-wordlist.txt"
PROJECT_ROOT = Path(__file__).resolve().parent.parent


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wifiguard",
        description="Passive Wi-Fi security auditing for Termux and Linux systems.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Scan nearby Wi-Fi networks.")
    _add_scan_arguments(scan_parser)
    scan_parser.set_defaults(func=run_scan)

    audit_parser = subparsers.add_parser(
        "audit-passphrase",
        help="Audit an owner-known passphrase against a local wordlist.",
    )
    _add_passphrase_arguments(audit_parser)
    audit_parser.add_argument("--report", help="Optional report output path.")
    audit_parser.add_argument(
        "--report-format",
        choices=["auto", "txt", "json"],
        default="auto",
        help="Report format. Defaults to filename extension or TXT.",
    )
    audit_parser.set_defaults(func=run_passphrase_only)

    return parser


def _add_scan_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--backend",
        choices=["auto", "termux", "nmcli", "iwlist"],
        default="auto",
        help="Force a specific Wi-Fi scanner backend.",
    )
    parser.add_argument(
        "--interface",
        help="Wireless interface for backends that require it, such as iwlist.",
    )
    parser.add_argument(
        "--select",
        type=int,
        help="Select a network by number without an interactive prompt.",
    )
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="Skip the selection prompt when --select is not provided.",
    )
    parser.add_argument("--report", help="Write a report to a TXT or JSON file.")
    parser.add_argument(
        "--report-format",
        choices=["auto", "txt", "json"],
        default="auto",
        help="Report format. Defaults to filename extension or TXT.",
    )
    _add_passphrase_arguments(parser)


def _add_passphrase_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--wordlist",
        help="Path to a local wordlist used only to check an owner-known passphrase. Overrides repo-default detection.",
    )
    password_group = parser.add_mutually_exclusive_group()
    password_group.add_argument(
        "--known-password",
        help="Owner-known Wi-Fi passphrase to audit locally.",
    )
    password_group.add_argument(
        "--prompt-password",
        action="store_true",
        help="Prompt for the owner-known Wi-Fi passphrase without echoing it.",
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args_list = list(sys.argv[1:] if argv is None else argv)
    if not args_list:
        args_list = ["scan"]
    elif args_list[0].startswith("-") and args_list[0] not in {"-h", "--help", "--version"}:
        args_list = ["scan", *args_list]

    args = parser.parse_args(args_list)
    handler = getattr(args, "func", run_scan)

    try:
        return handler(args)
    except ScannerError as exc:
        console = build_console()
        console.print(f"[bold red]Scanner error:[/bold red] {exc}")
        return 1
    except (FileNotFoundError, ValueError) as exc:
        console = build_console()
        console.print(f"[bold red]Error:[/bold red] {exc}")
        return 1


def run_scan(args: argparse.Namespace) -> int:
    console = build_console()
    scanner = WiFiScanner(backend_name=args.backend, interface=args.interface)
    backend_name, networks = scanner.scan()

    for network in networks:
        network.issues = analyze_network(network)

    render_network_table(console, networks)
    selected_network = _resolve_selection(args, console, networks)

    if selected_network is not None:
        render_network_details(console, selected_network)
        render_findings(console, selected_network)

    passphrase_audit = None
    if args.wordlist and not (args.known_password or args.prompt_password):
        raise ValueError("Passphrase auditing requires --known-password or --prompt-password.")

    if args.known_password or args.prompt_password:
        passphrase = _resolve_passphrase(args)
        wordlist_path = _resolve_wordlist_path(args.wordlist)
        if args.wordlist is None and wordlist_path is not None:
            console.print(f"[bold cyan]Using default wordlist:[/bold cyan] {wordlist_path}")
        passphrase_audit = _run_audit_with_progress(console, passphrase, wordlist_path)
        render_passphrase_audit(console, passphrase_audit)

    if args.report:
        report = build_report(
            backend=backend_name,
            networks=networks,
            selected_network=selected_network,
            passphrase_audit=passphrase_audit,
        )
        path, fmt = write_report(report, args.report, args.report_format)
        console.print(f"[bold green]Saved {fmt.upper()} report to[/bold green] {path}")

    return 0


def run_passphrase_only(args: argparse.Namespace) -> int:
    console = build_console()
    passphrase = _resolve_passphrase(args)
    wordlist_path = _resolve_wordlist_path(args.wordlist)
    if args.wordlist is None and wordlist_path is not None:
        console.print(f"[bold cyan]Using default wordlist:[/bold cyan] {wordlist_path}")
    result = _run_audit_with_progress(console, passphrase, wordlist_path)
    render_passphrase_audit(console, result)

    if args.report:
        report = build_report(
            backend="passphrase-only",
            networks=[],
            passphrase_audit=result,
        )
        path, fmt = write_report(report, args.report, args.report_format)
        console.print(f"[bold green]Saved {fmt.upper()} report to[/bold green] {path}")

    return 0


def _resolve_selection(args: argparse.Namespace, console, networks):
    if not networks:
        return None
    if args.select is not None:
        if args.select < 1 or args.select > len(networks):
            raise ValueError(f"--select must be between 1 and {len(networks)}.")
        return networks[args.select - 1]
    if args.non_interactive:
        return None
    return prompt_for_selection(console, networks)


def _resolve_passphrase(args: argparse.Namespace) -> str:
    if args.known_password:
        return args.known_password
    if args.prompt_password:
        return getpass("Enter the owner-known Wi-Fi passphrase: ")
    raise ValueError("Passphrase auditing requires --known-password or --prompt-password.")


def _resolve_wordlist_path(
    explicit_wordlist: str | None,
    cwd: Path | None = None,
    project_root: Path | None = None,
) -> Path | None:
    if explicit_wordlist:
        return Path(explicit_wordlist).expanduser().resolve()

    current_directory = Path.cwd() if cwd is None else cwd
    cwd_candidate = current_directory / DEFAULT_WORDLIST_NAME
    if cwd_candidate.is_file():
        return cwd_candidate.resolve()

    root_directory = PROJECT_ROOT if project_root is None else project_root
    repo_candidate = root_directory / DEFAULT_WORDLIST_NAME
    if repo_candidate.is_file():
        return repo_candidate.resolve()

    return None


def _run_audit_with_progress(console, passphrase: str, wordlist: Path | None):
    total = 1
    if wordlist:
        total = max(wordlist.expanduser().stat().st_size, 1)

    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=None),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task_id = progress.add_task("Auditing passphrase", total=total)

        def update_progress(completed: int, maximum: int) -> None:
            progress.update(task_id, completed=completed, total=max(maximum, 1))

        result = audit_known_passphrase(
            passphrase=passphrase,
            wordlist_path=wordlist,
            progress_callback=update_progress if wordlist else None,
        )
        progress.update(task_id, completed=total)
    return result
