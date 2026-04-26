from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Sequence


class CommandExecutionError(RuntimeError):
    """Raised when a local backend command fails."""


def command_exists(command: str) -> bool:
    return shutil.which(command) is not None


def run_command(args: Sequence[str], timeout: int = 20) -> str:
    try:
        completed = subprocess.run(
            list(args),
            capture_output=True,
            check=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise CommandExecutionError(f"Command not found: {args[0]}") from exc
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.strip() or "No stderr output"
        raise CommandExecutionError(f"Command failed: {' '.join(args)}\n{stderr}") from exc
    except subprocess.TimeoutExpired as exc:
        raise CommandExecutionError(f"Command timed out: {' '.join(args)}") from exc
    return completed.stdout


def ensure_file(path: str | Path) -> Path:
    file_path = Path(path).expanduser()
    if not file_path.is_file():
        raise FileNotFoundError(f"File not found: {file_path}")
    return file_path


def clamp(value: int, lower: int, upper: int) -> int:
    return max(lower, min(upper, value))


def dbm_to_percent(signal_dbm: int | None) -> int | None:
    if signal_dbm is None:
        return None
    # Approximate mapping commonly used for Wi-Fi signal readouts.
    return clamp(2 * (signal_dbm + 100), 0, 100)


def frequency_to_channel(frequency: int | None) -> int | None:
    if frequency is None:
        return None
    if frequency == 2484:
        return 14
    if 2412 <= frequency <= 2472:
        return ((frequency - 2412) // 5) + 1
    if 5000 <= frequency <= 5895:
        return (frequency - 5000) // 5
    if 5955 <= frequency <= 7115:
        return ((frequency - 5955) // 5) + 1
    return None


def extract_int(pattern: str, text: str) -> int | None:
    match = re.search(pattern, text, flags=re.IGNORECASE)
    if not match:
        return None
    return int(match.group(1))


def discover_wireless_interface(preferred: str | None = None) -> str | None:
    if preferred:
        return preferred

    interface = _discover_with_iw()
    if interface:
        return interface

    interface = _discover_with_nmcli()
    if interface:
        return interface

    return _discover_with_iwconfig()


def _discover_with_iw() -> str | None:
    if not command_exists("iw"):
        return None
    try:
        output = run_command(["iw", "dev"])
    except CommandExecutionError:
        return None

    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("Interface "):
            return stripped.split(maxsplit=1)[1]
    return None


def _discover_with_nmcli() -> str | None:
    if not command_exists("nmcli"):
        return None
    try:
        output = run_command(["nmcli", "--terse", "--fields", "DEVICE,TYPE", "device", "status"])
    except CommandExecutionError:
        return None

    for line in output.splitlines():
        parts = line.split(":")
        if len(parts) >= 2 and parts[1].strip() == "wifi":
            return parts[0].strip() or None
    return None


def _discover_with_iwconfig() -> str | None:
    if not command_exists("iwconfig"):
        return None
    try:
        output = run_command(["iwconfig"])
    except CommandExecutionError:
        return None

    for line in output.splitlines():
        if not line or line.startswith(" "):
            continue
        if "no wireless extensions" in line.lower():
            continue
        return line.split()[0]
    return None

