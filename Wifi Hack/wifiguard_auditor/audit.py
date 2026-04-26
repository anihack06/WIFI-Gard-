from __future__ import annotations

import math
from pathlib import Path
from typing import Callable

from .models import PassphraseAuditResult
from .utils import ensure_file

ProgressCallback = Callable[[int, int], None]


def audit_known_passphrase(
    passphrase: str,
    wordlist_path: str | Path | None = None,
    progress_callback: ProgressCallback | None = None,
) -> PassphraseAuditResult:
    if not passphrase or passphrase.isspace():
        raise ValueError("A non-empty passphrase is required for auditing.")

    found_in_wordlist = False
    matched_line: int | None = None
    scanned_entries = 0
    resolved_wordlist: Path | None = None

    if wordlist_path is not None:
        resolved_wordlist = ensure_file(wordlist_path)
        total_bytes = max(resolved_wordlist.stat().st_size, 1)
        if progress_callback:
            progress_callback(0, total_bytes)

        with resolved_wordlist.open("r", encoding="utf-8", errors="ignore") as handle:
            for line_number, line in enumerate(handle, start=1):
                scanned_entries = line_number
                candidate = line.rstrip("\r\n")
                if candidate == passphrase:
                    found_in_wordlist = True
                    matched_line = line_number
                    if progress_callback:
                        progress_callback(total_bytes, total_bytes)
                    break

                if progress_callback and (line_number % 250 == 0):
                    progress_callback(min(handle.buffer.tell(), total_bytes), total_bytes)
            else:
                if progress_callback:
                    progress_callback(total_bytes, total_bytes)

    estimated_entropy_bits = estimate_entropy_bits(passphrase)
    strength = classify_strength(passphrase, estimated_entropy_bits, found_in_wordlist)
    recommendations = build_recommendations(passphrase, found_in_wordlist, matched_line)

    return PassphraseAuditResult(
        password_length=len(passphrase),
        wordlist_path=str(resolved_wordlist) if resolved_wordlist else None,
        wordlist_checked=resolved_wordlist is not None,
        found_in_wordlist=found_in_wordlist,
        matched_line=matched_line,
        scanned_entries=scanned_entries,
        estimated_entropy_bits=estimated_entropy_bits,
        strength=strength,
        recommendations=recommendations,
    )


def estimate_entropy_bits(passphrase: str) -> float:
    pool_size = 0
    if any(char.islower() for char in passphrase):
        pool_size += 26
    if any(char.isupper() for char in passphrase):
        pool_size += 26
    if any(char.isdigit() for char in passphrase):
        pool_size += 10
    if any(not char.isalnum() for char in passphrase):
        pool_size += 33

    pool_size = max(pool_size, len(set(passphrase)), 1)
    return round(len(passphrase) * math.log2(pool_size), 2)


def classify_strength(
    passphrase: str,
    estimated_entropy_bits: float,
    found_in_wordlist: bool,
) -> str:
    if found_in_wordlist or len(passphrase) < 8:
        return "Very Weak"
    if len(passphrase) < 10 or estimated_entropy_bits < 45:
        return "Weak"
    if len(passphrase) < 12 or estimated_entropy_bits < 60:
        return "Fair"
    if estimated_entropy_bits < 80:
        return "Strong"
    return "Excellent"


def build_recommendations(
    passphrase: str,
    found_in_wordlist: bool,
    matched_line: int | None,
) -> list[str]:
    recommendations: list[str] = []

    if found_in_wordlist:
        if matched_line is not None:
            recommendations.append(
                f"Password matched the supplied wordlist on line {matched_line}. Replace it."
            )
        else:
            recommendations.append("Password matched the supplied wordlist. Replace it.")

    if len(passphrase) < 12:
        recommendations.append("Use at least 12 to 16 characters for a modern Wi-Fi passphrase.")

    has_mixed_classes = sum(
        [
            any(char.islower() for char in passphrase),
            any(char.isupper() for char in passphrase),
            any(char.isdigit() for char in passphrase),
            any(not char.isalnum() for char in passphrase),
        ]
    )
    if has_mixed_classes < 3:
        recommendations.append("Mix upper, lower, numeric, and symbol characters to improve resilience.")

    if passphrase.lower() == passphrase or passphrase.upper() == passphrase:
        recommendations.append("Avoid passwords made from only one letter case.")

    if passphrase.isalnum():
        recommendations.append("Add a few symbols or separators to expand the effective character set.")

    if not recommendations:
        recommendations.append("Passphrase looks healthy by local policy checks. Rotate it on a schedule you trust.")

    return recommendations
