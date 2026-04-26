from pathlib import Path

from wifiguard_auditor.audit import audit_known_passphrase


def test_audit_known_passphrase_detects_wordlist_match(tmp_path: Path) -> None:
    wordlist = tmp_path / "wordlist.txt"
    wordlist.write_text("password123\nCorrectHorseBatteryStaple!\n", encoding="utf-8")

    result = audit_known_passphrase("CorrectHorseBatteryStaple!", wordlist)

    assert result.wordlist_checked is True
    assert result.found_in_wordlist is True
    assert result.matched_line == 2
    assert result.strength == "Very Weak"


def test_audit_known_passphrase_without_wordlist() -> None:
    result = audit_known_passphrase("Taller!River!Lantern!27")

    assert result.wordlist_checked is False
    assert result.found_in_wordlist is False
    assert result.password_length == 23
    assert result.estimated_entropy_bits > 80


def test_audit_known_passphrase_matches_repo_wordlist() -> None:
    repo_wordlist = Path(__file__).resolve().parents[1] / "password-wordlist.txt"

    result = audit_known_passphrase("password", repo_wordlist)

    assert result.wordlist_checked is True
    assert result.found_in_wordlist is True
    assert result.matched_line == 1
